"""AWS account scanner (boto3).

Enumerates, per region:

* Bedrock Agents (agents, action groups, knowledge bases, aliases), Bedrock Flows, Prompts,
  Bedrock AgentCore (runtimes, gateways, memories, browsers, code interpreters), guardrails,
  custom models and the model-invocation-logging configuration
* Lambda functions (env var names / plaintext credentials, layers, runtime), ECS task definitions
  (images, env), SageMaker endpoints (model images), Step Functions (Bedrock integrations)
* Amazon Q Business applications, Lex V2 bots
* IAM roles / users / policies granting Bedrock, SageMaker, Q, Lex actions (``iam-grant``)
* Secrets Manager / SSM parameter *names* hinting LLM credentials
* CloudTrail management-event callers for the last N days (``gateway-caller``).
  LookupEvents does not expose data events; import exported invocation records
  for model and agent data-plane activity.

Auth: boto3 credential chain (``profile``, ``role_arn`` optional). Instance and
container role credentials require ``options.allow_instance_credentials``.
Offline export: JSONL of the raw records this connector emits (``_kind`` per record) – produce one
with ``shadowscan run cloud.aws --dump-records aws.jsonl``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatchcase
from functools import partial
from itertools import islice
from typing import Any, ClassVar
from urllib.parse import unquote

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.cloud.common import (
    RECORD_ERRORS,
    RecordDispatch,
    aggregate_caller_event,
    cloud_finding,
    credential_name_matches,
    done,
    first_tag,
    name_hint,
    scan_blob,
    scan_env,
    scan_iam_actions,
    string_list,
)
from shadowscan.connectors.cloud.credentials import (
    allow_instance_credentials,
    configure_aws_session,
    reject_instance_profile_sources,
)
from shadowscan.connectors.common import apply_matches, model_matches
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.identity import has_aws_account_scope
from shadowscan.utils.safe_json import strict_json_loads
from shadowscan.utils.text import truncate

DEFAULT_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"]
KNOWN_SERVICES = frozenset(
    {
        "bedrock",
        "agentcore",
        "lambda",
        "ecs",
        "sagemaker",
        "stepfunctions",
        "qbusiness",
        "lex",
        "iam",
        "secrets",
        "cloudtrail",
    }
)
LLM_ACTION_PREFIXES = (
    "bedrock:",
    "bedrock-agentcore:",
    "sagemaker:invoke",
    "qbusiness:",
    "lex:",
    "q:",
    "kendra:",
)
CLOUDTRAIL_EVENTS = [
    "InvokeModel",
    "InvokeModelWithResponseStream",
    "Converse",
    "ConverseStream",
    "InvokeAgent",
    "InvokeFlow",
    "InvokeInlineAgent",
    "InvokeAgentRuntime",
    "RetrieveAndGenerate",
    "InvokeEndpoint",
    "ChatSync",
]
MAX_LIST_PAGES = 1000
# Representative AI operations, not a complete IAM action catalogue. These
# establish potential access from NotAction; they never establish effective
# authorization or exhaustively evaluate a policy.
_AI_ACTION_CANDIDATES = (
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
    "bedrock:InvokeAgent",
    "bedrock:InvokeFlow",
    "bedrock:InvokeInlineAgent",
    "bedrock:RetrieveAndGenerate",
    "bedrock-agentcore:InvokeAgentRuntime",
    "sagemaker:InvokeEndpoint",
    "sagemaker:InvokeEndpointAsync",
    "sagemaker:InvokeEndpointWithResponseStream",
    "qbusiness:ChatSync",
    "qbusiness:Chat",
    "lex:RecognizeText",
    "lex:RecognizeUtterance",
    "lex:StartConversation",
    "q:SendMessage",
    "kendra:Query",
    "kendra:Retrieve",
)
# AgentCore tool and identity inventories: (record _kind, list operation, items key).
_AGENTCORE_LISTS = (
    ("agentcore-browser", "list_browsers", "browserSummaries"),
    ("agentcore-code-interpreter", "list_code_interpreters", "codeInterpreterSummaries"),
    ("agentcore-workload-identity", "list_workload_identities", "workloadIdentities"),
)
# Lambda layer name fragments that suggest an AI framework or provider SDK.
_LAYER_HINTS = (
    ("langchain", "framework.langchain"),
    ("llamaindex", "framework.llamaindex"),
    ("llama-index", "framework.llamaindex"),
    ("openai", "provider.openai"),
    ("anthropic", "provider.anthropic"),
    ("bedrock", "provider.aws-bedrock"),
    ("crewai", "framework.crewai"),
    ("strands", "framework.aws-strands"),
    ("agentcore", "cloud.aws-bedrock-agents"),
    ("litellm", "platform.litellm"),
    ("mcp", "protocol.mcp"),
)
# SageMaker serving images and container settings used for LLM inference.
_LLM_IMAGE_HINTS = ("tgi", "djl", "vllm", "lmi", "huggingface", "llm", "triton")
_LLM_ENV_HINTS = ("HF_MODEL_ID", "SM_NUM_GPUS", "MAX_INPUT_LENGTH", "OPTION_MODEL_ID", "HF_TASK")
_LLM_SECRET_KEYWORDS = (
    "openai",
    "anthropic",
    "claude",
    "gemini",
    "llm",
    "bedrock",
    "huggingface",
    "mistral",
    "cohere",
    "groq",
    "langsmith",
    "langfuse",
    "pinecone",
    "tavily",
)
# Evidence heuristics over trust policy principals, not URL validation: the
# GitHub Actions OIDC issuer host and the Bedrock service principals.
_GITHUB_ACTIONS_OIDC = "token.actions.githubusercontent.com"
_BEDROCK_TRUST_SERVICES = frozenset({"bedrock.amazonaws.com", "bedrock-agentcore.amazonaws.com"})
# Operations through which a trust policy lets a principal assume the role
# (lowercase: IAM matches action names case-insensitively).
_ASSUME_ROLE_ACTIONS = ("sts:assumerole", "sts:assumerolewithwebidentity", "sts:assumerolewithsaml")
# Service principals in a role trust policy that run agents or AI workloads.
_WORKLOAD_TRUST_SERVICES = (
    "lambda.amazonaws.com",
    "bedrock.amazonaws.com",
    "bedrock-agentcore.amazonaws.com",
    "ecs-tasks.amazonaws.com",
    "sagemaker.amazonaws.com",
    "states.amazonaws.com",
    "ec2.amazonaws.com",
    "eks.amazonaws.com",
    "apprunner.amazonaws.com",
)
# Resources whose ARN this connector generates from the account envelope.
_ENVELOPE_ARN_TYPES = frozenset({"bedrock-logging", "qbusiness-application", "lex-bot", "ssm-parameter"})
_DENIED_CODES = frozenset({"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"})
_UNAVAILABLE_MARKERS = ("Could not connect to the endpoint", "UnknownServiceError", "EndpointConnectionError")
# A provider error code is a fixed identifier (``AccessDeniedException``,
# ``ThrottlingException``); anything else is not reported as one.
_ERROR_CODE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")


def _error_code(exc: BaseException) -> str | None:
    """The provider's error code of a botocore ``ClientError``-shaped exception, else None."""
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, dict) else None
    code = error.get("Code") if isinstance(error, dict) else None
    return code if isinstance(code, str) and _ERROR_CODE_RE.fullmatch(code) else None


# CloudTrail event fields that must be text (or absent) before aggregation.
_CLOUDTRAIL_TEXT_FIELDS = (
    "principal",
    "userAgent",
    "modelId",
    "eventName",
    "sourceIp",
    "eventTime",
    "_region",
)


def _action_has_ai_scope(action: str, resource_services: set[str] | None = None) -> bool:
    """Whether an action expression can refer to an AI service in this scope."""
    if "[" in action or "]" in action:
        return False  # IAM uses * and ?, not fnmatch character classes.
    scopes = {"*"} if resource_services is None else resource_services
    lowered = action.lower()
    service = lowered.split(":", 1)[0]
    if lowered.startswith(LLM_ACTION_PREFIXES) and any(fnmatchcase(service, scope) for scope in scopes):
        return True
    return any(
        fnmatchcase(candidate.lower(), lowered)
        and any(fnmatchcase(candidate.split(":", 1)[0], scope) for scope in scopes)
        for candidate in _AI_ACTION_CANDIDATES
    )


def _is_account_id(value: Any) -> bool:
    """A 12-digit AWS account identifier (ASCII digits only)."""
    return isinstance(value, str) and len(value) == 12 and value.isascii() and value.isdigit()


def _resource_id(value: Any) -> str:
    """Reject malformed provider identifiers instead of inventing an identity."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("invalid AWS resource identifier")
    return value


def _optional_str(value: Any) -> str | None:
    """Provider timestamps as text; absent or empty values stay unknown."""
    return str(value) if value else None


def _without_metadata(response: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in response.items() if k != "ResponseMetadata"}


class AwsConnector(BaseConnector):
    name: ClassVar[str] = "cloud.aws"
    _ENV_VALUES_ARE_CONFIGURATION: ClassVar[bool] = True
    surface: ClassVar[Surface] = Surface.CLOUD
    provider: ClassVar[str | None] = "aws"
    requires: ClassVar[list[str]] = ["boto3"]
    description: ClassVar[str] = (
        "Bedrock Agents / AgentCore, Lambda, ECS, SageMaker, Step Functions, Q Business, Lex, IAM grants, "
        "secret names and CloudTrail LLM callers."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "profile": "AWS profile (env AWS_PROFILE)",
        "role_arn": "role to assume before scanning",
        "account_id": (
            "expected AWS account id for live scans (verified through STS); account label for offline exports"
        ),
        "allow_instance_credentials": (
            "allow EC2/ECS credential discovery (default false; inherited from options)"
        ),
        "regions": f"regions to scan (default {DEFAULT_REGIONS}; 'all' = every enabled region)",
        "services": (
            "subset of: bedrock, agentcore, lambda, ecs, sagemaker, stepfunctions, qbusiness, lex, iam, "
            "secrets, cloudtrail (default all)"
        ),
        "cloudtrail_days": "look-back window for LLM invocation events (default 7, 0 disables)",
        "max_lambda": "cap on Lambda functions per region (default 2000)",
        "max_ecs_api_calls": (
            "cap on ECS list/detail API calls per region "
            "(default 2000; reaching it marks coverage incomplete)"
        ),
        "input": "offline: JSONL of dumped records",
    }
    offline_formats: ClassVar[str] = "JSONL dump of records"

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        try:
            regions = string_list(ctx.get("regions"), "regions", pattern=r"[a-z0-9-]+")
            self.regions = regions or DEFAULT_REGIONS
            self._default_regions = not regions
            services = string_list(ctx.get("services"), "services") or sorted(KNOWN_SERVICES)
        except ValueError as exc:
            raise ConnectorError(f"cloud.aws: {exc}") from None
        unknown = sorted(set(services) - KNOWN_SERVICES)
        if unknown:
            raise ConnectorError(
                f"cloud.aws: unknown services {', '.join(unknown)}; "
                f"choose from {', '.join(sorted(KNOWN_SERVICES))}"
            )
        if "all" in self.regions and self.regions != ["all"]:
            raise ConnectorError("cloud.aws: regions 'all' cannot be combined with explicit regions")
        self.services = set(services)
        self.cloudtrail_days = int(ctx.get("cloudtrail_days", 7))
        self.max_lambda = int(ctx.get("max_lambda", 2000))
        if self.max_lambda < 1:
            raise ConnectorError("cloud.aws: max_lambda must be positive")
        self.max_ecs_api_calls = int(ctx.get("max_ecs_api_calls", 2000))
        if self.max_ecs_api_calls < 1:
            raise ConnectorError("cloud.aws: max_ecs_api_calls must be positive")
        account = ctx.get("account_id")
        # YAML numeric account IDs are common; never pad an already-truncated
        # identifier or accept booleans/floats as a cloud account identity.
        if isinstance(account, int) and not isinstance(account, bool):
            account = str(account)
        if account is not None and (not isinstance(account, str) or not account.strip()):
            raise ConnectorError("cloud.aws: account_id must be a nonempty string")
        if not self.offline and account is not None and not _is_account_id(account):
            raise ConnectorError(
                "cloud.aws: account_id must be exactly 12 ASCII digits (quote identifiers with leading zeros)"
            )
        self.account: str | None = account
        self._configured_account = account
        self._session: Any = None

    # ------------------------------------------------------------- session
    @staticmethod
    def _sdk_config() -> Any:
        from botocore.config import Config

        # Apply finite transport/retry bounds to STS as well as inventory calls.
        return Config(
            connect_timeout=10,
            read_timeout=30,
            ignore_configured_endpoint_urls=True,
            retries={"mode": "standard", "total_max_attempts": 3},
        )

    def _session_(self) -> Any:
        if self._session is not None:
            return self._session
        import boto3
        from botocore.loaders import Loader
        from botocore.session import Session

        profile = self.ctx.get("profile", env="AWS_PROFILE")
        # Configure this session only: process-wide environment changes race with
        # concurrent scans and can unexpectedly enable metadata access elsewhere.
        sdk_session = Session(profile=profile)
        # Endpoint rules are executable destination configuration too. Ignore
        # AWS_DATA_PATH and ~/.aws/models; both can override signed service
        # destinations even when configured endpoint URLs are disabled.
        sdk_session.register_component(
            "data_loader",
            Loader(
                extra_search_paths=[Loader.BUILTIN_DATA_PATH],
                include_default_search_paths=False,
            ),
        )
        sdk_session.set_default_client_config(self._sdk_config())
        allow_instance = allow_instance_credentials(self.ctx.get("allow_instance_credentials", False))
        configure_aws_session(sdk_session, allow_instance=allow_instance)
        if not allow_instance:
            # AssumeRoleProvider has its own source chain; removing providers
            # from this session alone cannot override a named instance profile.
            reject_instance_profile_sources(sdk_session, profile)
        session = boto3.Session(botocore_session=sdk_session)
        role = self.ctx.get("role_arn")
        try:
            if role:
                sts = session.client("sts", config=self._sdk_config())
                creds = sts.assume_role(RoleArn=role, RoleSessionName="shadowscan")["Credentials"]
                session = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                    botocore_session=sdk_session,
                )
            account = session.client("sts", config=self._sdk_config()).get_caller_identity()["Account"]
            if not _is_account_id(account):
                raise ValueError("invalid STS account identifier")
        except Exception as exc:
            raise ConnectorError(f"cloud.aws: cannot authenticate ({type(exc).__name__})") from exc
        if self.account is not None and self.account != account:
            raise ConnectorError(
                "cloud.aws: configured account_id does not match the authenticated AWS account"
            )
        self.account = account
        self._session = session
        return session

    def _client(self, service: str, region: str | None = None) -> Any:
        return self._session_().client(service, region_name=region, config=self._sdk_config())

    def _regions(self) -> list[str]:
        if self.regions == "all" or self.regions == ["all"]:
            ec2 = self._client("ec2", "us-east-1")
            return [r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"]]
        return list(self.regions)

    def _pages(self, client: Any, op: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
        """Keep successful pages when a later provider request fails."""
        try:
            try:
                paginator = client.get_paginator(op)
            except Exception as exc:  # some operations are not pageable
                if type(exc).__name__ != "OperationNotPageableError":
                    raise
                # Only failure to create a paginator permits the manual path.
                paginator = None
            if paginator is None:
                yield from self._manual_pages(client, op, kwargs)
                return
            for number, page in enumerate(islice(paginator.paginate(**kwargs), MAX_LIST_PAGES), start=1):
                if not isinstance(page, dict):
                    raise ValueError("invalid AWS list page")
                yield page
                if number == MAX_LIST_PAGES:
                    # Inspect the last response without fetching another page.
                    tokens = ("nextToken", "NextToken", "NextMarker", "Marker")
                    if page.get("IsTruncated") or any(page.get(key) for key in tokens):
                        self.ctx.warn(f"cloud.aws: {op} pagination limit reached")
                    return
        except Exception as exc:  # noqa: BLE001 - preserve pages already yielded
            code = _error_code(exc)
            denied = code in _DENIED_CODES
            detail = f"access denied ({code})" if denied else type(exc).__name__
            self.ctx.warn(f"cloud.aws: {op} collection failed ({detail})")

    def _manual_pages(self, client: Any, op: str, kwargs: dict[str, Any]) -> Iterator[dict[str, Any]]:
        """Follow ``nextToken``/``NextToken`` by hand for operations without a paginator."""
        seen: set[str] = set()
        request = dict(kwargs)
        for _ in range(MAX_LIST_PAGES):
            page = getattr(client, op)(**request)
            if not isinstance(page, dict):
                raise ValueError("invalid AWS list page")
            yield page
            token_key = "nextToken" if "nextToken" in page else "NextToken"
            token = page.get(token_key)
            if token is None or token == "":
                return
            if not isinstance(token, str) or token in seen:
                raise ValueError("invalid or repeated AWS pagination token")
            seen.add(token)
            request[token_key] = token
        self.ctx.warn(f"cloud.aws: {op} pagination limit reached")

    def _paginate(self, client: Any, op: str, key: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
        for page in self._pages(client, op, **kwargs):
            if key not in page or "error" in page or "Error" in page:
                self.ctx.warn(f"cloud.aws: missing or failed {key} page for {op}")
                continue
            items = page[key]
            if not isinstance(items, list):
                self.ctx.warn(f"cloud.aws: invalid {key} page for {op}")
                continue
            for item in items:
                if not isinstance(item, dict):
                    self.ctx.warn(f"cloud.aws: invalid {key} record for {op}")
                    continue
                yield item

    def _list_items(self, client: Any, op: str, key: str, **kwargs: Any) -> list[dict[str, Any]]:
        """Every item of a paginated listing, read in full before any detail call.

        Provider failures keep the pages already read (see ``_pages``); any other
        failure yields no items and marks coverage incomplete (see ``_safe``).
        """
        return self._safe(list, self._paginate(client, op, key, **kwargs)) or []

    def _safe(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Call one SDK operation; a failure warns, marks coverage incomplete and returns None.

        The diagnostic names the operation and the provider's error code or
        the exception type, never the message: SDK errors echo request
        arguments, which are built from untrusted response fields, and
        denied-authorization messages can carry encoded policy context.
        """
        try:
            return fn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - every failure below is reported as incomplete coverage
            code = _error_code(exc)
            msg = str(exc)
            operation = getattr(fn, "__name__", None)
            where = f" {operation}" if isinstance(operation, str) and operation.isidentifier() else ""
            detail = code or type(exc).__name__
            if code in _DENIED_CODES or "UnauthorizedOperation" in msg or "not authorized" in msg:
                self.ctx.warn(f"cloud.aws:{where} access denied ({detail})", incomplete=True)
            elif any(marker in msg for marker in _UNAVAILABLE_MARKERS):
                self.ctx.warn(f"cloud.aws:{where} service coverage unavailable ({detail})", incomplete=True)
            else:
                self.ctx.warn(f"cloud.aws:{where} request failed ({detail})", incomplete=True)
            return None

    def _guarded(self, kind: str, build: Callable[[], dict[str, Any] | None]) -> dict[str, Any] | None:
        """Build one record from provider responses; a malformed response skips that record only.

        Response fields are untrusted: a missing or mistyped field raises
        inside the builder. The record is reported as a coverage gap and
        collection continues with the next resource, service and region
        instead of abandoning them all.
        """
        try:
            return build()
        except RECORD_ERRORS as exc:
            self.ctx.warn(
                f"cloud.aws: malformed {kind} record skipped ({type(exc).__name__}); coverage incomplete",
                incomplete=True,
            )
            return None

    # -------------------------------------------------------------- collect
    def collect(self) -> Iterable[dict[str, Any]]:
        # Explicit region lists do not create a client. Authenticate before
        # emitting account metadata rather than relying on region discovery.
        self._session_()
        regions = self._regions()
        acct = self.account
        if self._default_regions and self.services - {"iam"}:
            # Informational: the operator chose no scope, so name what was and was not covered.
            self.ctx.warn(
                "cloud.aws: no 'regions' option set; scanned only the default regions "
                f"({', '.join(regions)}). "
                "Resources in other regions were not scanned. Set 'regions' to a list, or "
                "'regions: all' for every enabled region, to change the scope",
                incomplete=False,
            )
        yield {"_kind": "account", "account": acct, "regions": regions}
        if "iam" in self.services:
            yield from self._collect_iam()
        for region in regions:
            if "bedrock" in self.services:
                yield from self._collect_bedrock(region)
            if "agentcore" in self.services:
                yield from self._collect_agentcore(region)
            if "lambda" in self.services:
                yield from self._collect_lambda(region)
            if "ecs" in self.services:
                yield from self._collect_ecs(region)
            if "sagemaker" in self.services:
                yield from self._collect_sagemaker(region)
            if "stepfunctions" in self.services:
                yield from self._collect_stepfunctions(region)
            if "qbusiness" in self.services:
                yield from self._collect_q(region)
            if "lex" in self.services:
                yield from self._collect_lex(region)
            if "secrets" in self.services:
                yield from self._collect_secret_names(region)
            if "cloudtrail" in self.services and self.cloudtrail_days > 0:
                yield from self._collect_cloudtrail(region)

    def _collect_bedrock(self, region: str) -> Iterator[dict[str, Any]]:
        ba = self._client("bedrock-agent", region)
        for summary in self._list_items(ba, "list_agents", "agentSummaries"):
            agent = self._guarded("Bedrock agent", partial(self._bedrock_agent, ba, summary, region))
            if agent is not None:
                yield agent
        for kb in self._list_items(ba, "list_knowledge_bases", "knowledgeBaseSummaries"):
            kb["_kind"] = "bedrock-knowledge-base"
            kb["_region"] = region
            yield kb
        for flow in self._list_items(ba, "list_flows", "flowSummaries"):
            flow["_kind"] = "bedrock-flow"
            flow["_region"] = region
            yield flow
        b = self._client("bedrock", region)
        cfg = self._safe(b.get_model_invocation_logging_configuration)
        if cfg is not None:
            yield {"_kind": "bedrock-logging", "_region": region, "loggingConfig": cfg.get("loggingConfig")}
        for g in self._list_items(b, "list_guardrails", "guardrails"):
            g["_kind"] = "bedrock-guardrail"
            g["_region"] = region
            yield g
        for m in self._list_items(b, "list_custom_models", "modelSummaries"):
            m["_kind"] = "bedrock-custom-model"
            m["_region"] = region
            yield m

    def _bedrock_agent(self, ba: Any, summary: dict[str, Any], region: str) -> dict[str, Any]:
        """One agent with its aliases and, for DRAFT and every aliased version, its tools and sources."""
        detail = self._safe(ba.get_agent, agentId=summary["agentId"])
        agent: dict[str, Any] = (detail or {}).get("agent", summary)
        agent["_kind"] = "bedrock-agent"
        agent["_region"] = region
        agent_id = summary["agentId"]
        aliases = self._list_items(ba, "list_agent_aliases", "agentAliasSummaries", agentId=agent_id)
        agent["_aliases"] = aliases
        # An alias can route to a published version with different actions
        # from DRAFT. List summaries do not contain executors or built-ins.
        versions = {"DRAFT"}
        for alias in aliases:
            routes = alias.get("routingConfiguration") or []
            for route in routes:
                # Provider JSON is untrusted: a version that is not a string
                # would break the version sort for the whole agent.
                version = route.get("agentVersion") if isinstance(route, dict) else None
                if isinstance(version, str) and version:
                    versions.add(version)
                elif version is not None:
                    self.ctx.warn(
                        f"cloud.aws: invalid alias version for agent {agent_id}; version coverage incomplete",
                        incomplete=True,
                    )
        groups: list[dict[str, Any]] = []
        knowledge_bases: list[dict[str, Any]] = []
        collaborators: list[dict[str, Any]] = []
        # Snapshot the public DRAFT fields: storing the record itself creates a
        # cycle that export sanitization collapses to a redaction marker.
        version_details: dict[str, dict[str, Any]] = {
            "DRAFT": {k: v for k, v in agent.items() if not k.startswith("_")},
        }
        for version in sorted(versions):
            if version != "DRAFT":
                version_result = self._safe(ba.get_agent_version, agentId=agent_id, agentVersion=version)
                if isinstance(version_result, dict) and isinstance(version_result.get("agentVersion"), dict):
                    version_details[version] = version_result["agentVersion"]
                elif version_result is not None:
                    self.ctx.warn(
                        f"cloud.aws: invalid agent version response for {agent_id} version {version}",
                        incomplete=True,
                    )
            scope = {"agentId": agent_id, "agentVersion": version}
            for action in self._list_items(ba, "list_agent_action_groups", "actionGroupSummaries", **scope):
                detail = self._safe(ba.get_agent_action_group, **scope, actionGroupId=action["actionGroupId"])
                group = (detail or {}).get("agentActionGroup") or {}
                groups.append({**action, **group, "agentVersion": version})
            kbs = self._list_items(ba, "list_agent_knowledge_bases", "agentKnowledgeBaseSummaries", **scope)
            knowledge_bases.extend({**kb, "_agentVersion": version} for kb in kbs)
            collabs = self._list_items(ba, "list_agent_collaborators", "agentCollaboratorSummaries", **scope)
            collaborators.extend({**collab, "_agentVersion": version} for collab in collabs)
        agent["_versions_scanned"] = sorted(versions)
        agent["_version_details"] = version_details
        agent["_action_groups"] = groups
        agent["_knowledge_bases"] = knowledge_bases
        agent["_collaborators"] = collaborators
        return agent

    def _collect_agentcore(self, region: str) -> Iterator[dict[str, Any]]:
        try:
            ac = self._client("bedrock-agentcore-control", region)
        except Exception:  # noqa: BLE001 - old boto3
            self.ctx.warn(
                "cloud.aws: AgentCore unavailable in installed SDK; collection incomplete",
                incomplete=True,
            )
            return
        for rt in self._list_items(ac, "list_agent_runtimes", "agentRuntimes"):
            detail = self._safe(ac.get_agent_runtime, agentRuntimeId=rt.get("agentRuntimeId")) or {}
            rec = {**rt, **_without_metadata(detail)}
            rec["_kind"] = "agentcore-runtime"
            rec["_region"] = region
            yield rec
        for gw in self._list_items(ac, "list_gateways", "items"):
            gateway = self._guarded("AgentCore gateway", partial(self._agentcore_gateway, ac, gw, region))
            if gateway is not None:
                yield gateway
        for mem in self._list_items(ac, "list_memories", "memories"):
            mem["_kind"] = "agentcore-memory"
            mem["_region"] = region
            yield mem
        for kind, op, key in _AGENTCORE_LISTS:
            for item in self._list_items(ac, op, key):
                item["_kind"] = kind
                item["_region"] = region
                yield item

    def _agentcore_gateway(self, ac: Any, gw: dict[str, Any], region: str) -> dict[str, Any]:
        gateway_id = gw.get("gatewayId")
        targets = self._list_items(ac, "list_gateway_targets", "items", gatewayIdentifier=gateway_id)
        gw["_targets"] = []
        for target in targets:
            detail = self._safe(
                ac.get_gateway_target,
                gatewayIdentifier=gateway_id,
                targetId=target["targetId"],
            )
            gw["_targets"].append({**target, **_without_metadata(detail or {})})
        gw["_kind"] = "agentcore-gateway"
        gw["_region"] = region
        return gw

    def _collect_lambda(self, region: str) -> Iterator[dict[str, Any]]:
        lam = self._client("lambda", region)
        for n, fn in enumerate(self._paginate(lam, "list_functions", "Functions"), start=1):
            if n > self.max_lambda:
                self.ctx.warn(f"cloud.aws: max_lambda reached in {region}", incomplete=True)
                break
            rec = self._guarded("Lambda function", partial(self._lambda_record, lam, fn, region))
            if rec is not None:
                yield rec

    def _lambda_record(self, lam: Any, fn: dict[str, Any], region: str) -> dict[str, Any]:
        environment = fn.get("Environment", {})
        environment_known = isinstance(environment, dict) and "Error" not in environment
        variables = environment.get("Variables", {}) if isinstance(environment, dict) else {}
        if not isinstance(variables, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in variables.items()
        ):
            environment_known = False
            variables = (
                {k: v for k, v in variables.items() if isinstance(k, str) and isinstance(v, str)}
                if isinstance(variables, dict)
                else {}
            )
        if not environment_known:
            # Do not echo the provider error: it can contain sensitive
            # configuration. Preserve known variables and other signals.
            self.ctx.warn(
                "cloud.aws: Lambda environment unavailable or malformed; configuration coverage unknown"
            )
        rec = {
            "_kind": "lambda",
            "_region": region,
            "FunctionName": fn.get("FunctionName"),
            "FunctionArn": fn.get("FunctionArn"),
            "Runtime": fn.get("Runtime"),
            "Role": fn.get("Role"),
            "Handler": fn.get("Handler"),
            "Environment": variables,
            "environment_coverage": "observed" if environment_known else "unknown",
            "Layers": [layer.get("Arn") for layer in fn.get("Layers") or []],
            "LastModified": fn.get("LastModified"),
            "PackageType": fn.get("PackageType"),
            "Description": fn.get("Description"),
            "ImageUri": None,
        }
        if fn.get("PackageType") == "Image":
            code = self._safe(lam.get_function, FunctionName=fn["FunctionName"]) or {}
            image = code.get("Code") or {}
            rec["ImageUri"] = image.get("ImageUri") or image.get("ResolvedImageUri")
        tags = self._safe(lam.list_tags, Resource=fn["FunctionArn"]) or {}
        rec["Tags"] = tags.get("Tags") or {}
        return rec

    def _collect_ecs(self, region: str) -> Iterator[dict[str, Any]]:
        yield from _EcsInventory(self, self._client("ecs", region), region).collect()

    def _collect_sagemaker(self, region: str) -> Iterator[dict[str, Any]]:
        sm = self._client("sagemaker", region)
        for ep in self._list_items(sm, "list_endpoints", "Endpoints"):
            rec = self._guarded("SageMaker endpoint", partial(self._sagemaker_record, sm, ep, region))
            if rec is not None:
                yield rec

    def _sagemaker_record(self, sm: Any, ep: dict[str, Any], region: str) -> dict[str, Any]:
        desc = self._safe(sm.describe_endpoint, EndpointName=ep["EndpointName"]) or {}
        config_name = desc.get("EndpointConfigName", "")
        cfg = self._safe(sm.describe_endpoint_config, EndpointConfigName=config_name) or {}
        models = []
        for v in cfg.get("ProductionVariants") or []:
            m = self._safe(sm.describe_model, ModelName=v.get("ModelName", "")) or {}
            primary = [m["PrimaryContainer"]] if m.get("PrimaryContainer") else []
            containers = m.get("Containers") or primary
            models.append(
                {
                    "name": v.get("ModelName"),
                    "instance": v.get("InstanceType"),
                    "images": [c.get("Image") for c in containers],
                    "env": {k: v2 for c in containers for k, v2 in (c.get("Environment") or {}).items()},
                    "model_data": [c.get("ModelDataUrl") for c in containers],
                }
            )
        return {
            "_kind": "sagemaker-endpoint",
            "_region": region,
            "EndpointName": ep["EndpointName"],
            "EndpointArn": ep.get("EndpointArn"),
            "EndpointStatus": ep.get("EndpointStatus"),
            "CreationTime": str(ep.get("CreationTime")),
            "LastModifiedTime": str(ep.get("LastModifiedTime")),
            "models": models,
        }

    def _collect_stepfunctions(self, region: str) -> Iterator[dict[str, Any]]:
        sfn = self._client("stepfunctions", region)
        for sm in self._list_items(sfn, "list_state_machines", "stateMachines"):
            rec = self._guarded(
                "Step Functions state machine", partial(self._state_machine_record, sfn, sm, region)
            )
            if rec is not None:
                yield rec

    def _state_machine_record(self, sfn: Any, sm: dict[str, Any], region: str) -> dict[str, Any] | None:
        d = self._safe(sfn.describe_state_machine, stateMachineArn=sm["stateMachineArn"]) or {}
        definition = d.get("definition") or ""
        if not any(service in definition.lower() for service in ("bedrock", "sagemaker", "lambda")):
            return None
        return {
            "_kind": "state-machine",
            "_region": region,
            "name": sm.get("name"),
            "stateMachineArn": sm["stateMachineArn"],
            "roleArn": d.get("roleArn"),
            "definition": definition[:200_000],
            "creationDate": str(sm.get("creationDate")),
        }

    def _collect_q(self, region: str) -> Iterator[dict[str, Any]]:
        q = self._client("qbusiness", region)
        for app in self._list_items(q, "list_applications", "applications"):
            app["_kind"] = "qbusiness-application"
            app["_region"] = region
            yield app

    def _collect_lex(self, region: str) -> Iterator[dict[str, Any]]:
        lex = self._client("lexv2-models", region)
        for bot in self._list_items(lex, "list_bots", "botSummaries"):
            bot["_kind"] = "lex-bot"
            bot["_region"] = region
            yield bot

    def _collect_secret_names(self, region: str) -> Iterator[dict[str, Any]]:
        sm = self._client("secretsmanager", region)
        for s in self._list_items(sm, "list_secrets", "SecretList"):
            yield {
                "_kind": "secret-name",
                "_region": region,
                "Name": s.get("Name"),
                "ARN": s.get("ARN"),
                "LastAccessedDate": str(s.get("LastAccessedDate")),
                "Description": s.get("Description"),
                "Tags": {t["Key"]: t.get("Value") for t in s.get("Tags") or []},
            }
        ssm = self._client("ssm", region)
        for p in self._list_items(ssm, "describe_parameters", "Parameters"):
            yield {
                "_kind": "ssm-parameter",
                "_region": region,
                "Name": p.get("Name"),
                "Type": p.get("Type"),
                "LastModifiedDate": str(p.get("LastModifiedDate")),
            }

    def _collect_iam(self) -> Iterator[dict[str, Any]]:
        iam = self._client("iam")
        details = self._safe(lambda: list(self._paginate_details(iam)))
        if not details:
            return
        policies: dict[str, dict[str, Any]] = {}
        for item in details:
            if item.get("_type") == "Policies":
                arn = item.get("Arn")
                if not isinstance(arn, str):
                    self.ctx.warn(
                        "cloud.aws: malformed IAM policy record skipped; coverage incomplete", incomplete=True
                    )
                    continue
                for ver in item.get("PolicyVersionList") or []:
                    if ver.get("IsDefaultVersion"):
                        policies[arn] = ver.get("Document") or {}
        for item in details:
            if item.get("_type") in {"RoleDetailList", "UserDetailList", "GroupDetailList"}:
                rec = self._guarded("IAM principal", partial(self._iam_principal_record, item, policies))
                if rec is not None:
                    yield rec

    def _iam_principal_record(
        self, item: dict[str, Any], policies: dict[str, dict[str, Any]]
    ) -> dict[str, Any] | None:
        inline = item.get("RolePolicyList") or item.get("UserPolicyList") or item.get("GroupPolicyList") or []
        docs = [p.get("PolicyDocument") for p in inline]
        attached = item.get("AttachedManagedPolicies") or []
        unresolved = [p.get("PolicyArn") for p in attached if p.get("PolicyArn") not in policies]
        if unresolved:
            self.ctx.warn(
                f"cloud.aws: unresolved attached policies for {item.get('Arn')}: "
                f"{', '.join(str(p) for p in unresolved)}",
                incomplete=True,
            )
        docs += [policies.get(p.get("PolicyArn"), {}) for p in attached]
        actions, ai_patterns, potential_actions, limitations = _iam_policy_signals(docs)
        if item.get("PermissionsBoundary"):
            limitations.add("permissions-boundary-not-evaluated")
        if limitations:
            # Documented as incomplete: conditions, denies and boundaries can remove
            # access that the evidence shows, so effective authorization is unknown.
            self.ctx.warn(
                f"cloud.aws: IAM policy analysis is partial for {item.get('Arn')} ("
                + ", ".join(sorted(limitations))
                + "); these limits are not evaluated, so effective authorization is unknown "
                "and the scan is marked incomplete"
            )
        if not (potential_actions or ai_patterns):
            return None
        last_used = item.get("RoleLastUsed")
        return {
            "_kind": "iam-principal",
            "type": item["_type"].replace("DetailList", ""),
            "name": item.get("RoleName") or item.get("UserName") or item.get("GroupName"),
            "arn": item.get("Arn"),
            "created": str(item.get("CreateDate")),
            "last_used": str((last_used or {}).get("LastUsedDate")) if last_used else None,
            "assume_role_policy": item.get("AssumeRolePolicyDocument"),
            "actions": sorted(actions),
            "ai_action_patterns": sorted(ai_patterns),
            "potential_actions": sorted(potential_actions),
            "policy_limitations": sorted(limitations),
            "attached_policies": [p.get("PolicyName") for p in attached],
            "tags": {t["Key"]: t.get("Value") for t in item.get("Tags") or []},
        }

    def _paginate_details(self, iam: Any) -> Iterator[dict[str, Any]]:
        principal_filter = ["Role", "User", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]
        for page in self._pages(iam, "get_account_authorization_details", Filter=principal_filter):
            for key in ("RoleDetailList", "UserDetailList", "GroupDetailList", "Policies"):
                items = page.get(key, [])
                if not isinstance(items, list):
                    self.ctx.warn(f"cloud.aws: invalid IAM {key} page")
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        self.ctx.warn(f"cloud.aws: invalid IAM {key} record")
                        continue
                    yield {**item, "_type": key}

    def _collect_cloudtrail(self, region: str) -> Iterator[dict[str, Any]]:
        self.ctx.warn(
            f"cloud.aws: CloudTrail LookupEvents in {region} covers management events only; "
            "model/agent invocation data events require a CloudTrail Lake or trail export. "
            "No returned callers does not establish absence of runtime activity.",
            incomplete=False,
        )
        ct = self._client("cloudtrail", region)
        start = datetime.now(UTC) - timedelta(days=min(self.cloudtrail_days, 90))
        for event_name in CLOUDTRAIL_EVENTS:
            lookup = [{"AttributeKey": "EventName", "AttributeValue": event_name}]
            for ev in self._list_items(
                ct,
                "lookup_events",
                "Events",
                LookupAttributes=lookup,
                StartTime=start,
            ):
                record = _cloudtrail_record(ev, region)
                if record is None:
                    self.ctx.warn("cloud.aws: invalid CloudTrail event JSON; event coverage incomplete")
                    continue
                yield record

    # -------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        # Resolve the complete export envelope before publishing identities.
        # Retain derived findings, not raw provider payloads: account records can
        # follow resources or contradict a previous envelope in concatenated dumps.
        pending: list[Finding] = []
        if self.offline:
            self.account = self._configured_account
        accounts: set[str] = set()
        invalid_account = False
        failure: Exception | None = None
        callers: dict[str, dict[str, Any]] = {}
        dispatch = RecordDispatch(self, "account", "cloudtrail-event")
        try:
            for rec in records:
                kind = dispatch.kind(rec)
                if kind is None:
                    continue
                try:
                    if kind == "account":
                        account = rec.get("account")
                        if (
                            self._is_error_record(rec)
                            or not isinstance(account, str)
                            or not has_aws_account_scope("aws", account, None)
                        ):
                            invalid_account = True
                            raise ValueError("account")
                        accounts.add(account)
                    elif kind == "cloudtrail-event":
                        for field in _CLOUDTRAIL_TEXT_FIELDS:
                            if rec.get(field) is not None and not isinstance(rec[field], str):
                                raise ValueError("event field")
                        self._acc_caller(callers, rec)
                    else:
                        f = dispatch.handlers[kind](rec)
                        if f:
                            pending.append(f)
                except RECORD_ERRORS:
                    dispatch.invalid()
        except Exception as exc:  # noqa: BLE001 - preserve observations before a collection failure
            failure = exc
        expected_account = self.account  # configured offline, or verified by live STS
        if expected_account is not None:
            accounts.add(expected_account)
        ambiguous = invalid_account or len(accounts) > 1
        self.account = None if ambiguous else next(iter(accounts), None)
        if ambiguous:
            self.ctx.warn(
                "cloud.aws: conflicting or invalid account envelopes; short resource identities unresolved"
            )
        for key, agg in callers.items():
            self.ctx.check_deadline()
            try:
                pending.append(self._caller_finding(key, agg))
            except RECORD_ERRORS:
                self.ctx.warn("cloud.aws: invalid aggregated caller fields")
        for f in pending:
            self.ctx.check_deadline()
            self._resolve_finding_account(f, expected_account)
            yield f
        if failure is not None:
            raise failure

    def _resolve_finding_account(self, finding: Finding, expected_account: str | None) -> None:
        # These resources have connector-generated ARNs, so their account is an
        # envelope claim, not independent evidence from a provider resource ARN.
        if finding.resource_type in _ENVELOPE_ARN_TYPES:
            before = finding.resource
            parts = before.split(":", 5)
            parts[4] = self.account or ""
            finding.resource = ":".join(parts)
            for evidence in finding.evidence:
                if evidence.location == before:
                    evidence.location = finding.resource
            finding.account = self.account
        else:
            arn = finding.resource.removeprefix("cloudtrail:")
            explicit_account = arn.split(":", 5)[4] if has_aws_account_scope("aws", None, arn) else None
            finding.account = explicit_account or self.account
            scope = expected_account or self.account
            # A CloudTrail caller can legitimately belong to another account;
            # inventory resources returned by account-scoped list APIs cannot.
            if (
                explicit_account
                and not finding.resource_type.startswith("caller/")
                and has_aws_account_scope("aws", scope, None)
                and scope != explicit_account
            ):
                self.ctx.warn(
                    "cloud.aws: resource account differs from configured, authenticated or exported account; "
                    "identity unresolved"
                )
                finding.metadata["identity_unresolved"] = True
        if not has_aws_account_scope(finding.provider, finding.account, finding.resource):
            self.ctx.warn(
                "cloud.aws: resource lacks account scope; "
                "supply a consistent account_id or account export record"
            )
            finding.metadata["identity_unresolved"] = True
        finding.id = finding.compute_id()

    def _arn_account(self, arn: str | None) -> str | None:
        if has_aws_account_scope("aws", None, arn):
            assert arn is not None
            return arn.removeprefix("cloudtrail:").split(":", 5)[4]
        return self.account

    def _h_bedrock_agent(self, rec: dict[str, Any]) -> Finding:
        arn = rec.get("agentArn") or rec.get("agentId")
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.AGENT,
            title=f"Bedrock Agent: {rec.get('agentName')}",
            resource=_resource_id(arn),
            resource_type="bedrock-agent",
            account=self._arn_account(arn),
            region=rec.get("_region"),
            first_seen=_optional_str(rec.get("createdAt")),
            last_seen=_optional_str(rec.get("updatedAt")),
        )
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_model_provider("provider.aws-bedrock")
        f.add_capability("tool-use")
        details = self._agent_version_details(rec)
        models = [rec.get("foundationModel"), *(v.get("foundationModel") for v in details.values())]
        if any(model is not None and not isinstance(model, str) for model in models):
            self.ctx.warn("cloud.aws: Bedrock agent has an invalid foundation model identifier")
        f.models = sorted({model for model in models if isinstance(model, str) and model})
        apply_matches(f, model_matches(self.index, *f.models), weight_scale=0.5)
        ags = rec.get("_action_groups") or []
        kbs = rec.get("_knowledge_bases") or []
        f.add_evidence(
            Evidence(
                signal="aws:bedrock-agent",
                description=(
                    f"Agent '{rec.get('agentName')}' ({rec.get('agentStatus')}) on "
                    f"{rec.get('foundationModel')} "
                    f"with {len(ags)} action group version(s), {len(kbs)} knowledge base association(s), "
                    f"{len(rec.get('_aliases') or [])} alias(es); role {rec.get('agentResourceRoleArn')}"
                ),
                location=arn,
                weight=0.97,
                signature="cloud.aws-bedrock-agents",
            )
        )
        for ag in ags:
            if ag.get("actionGroupState") == "DISABLED":
                continue
            ex = ag.get("actionGroupExecutor") or {}
            if ex.get("lambda"):
                f.add_capability("code-exec")
                f.add_evidence(
                    Evidence(
                        signal="aws:action-group",
                        description=(
                            f"Action group '{ag.get('actionGroupName')}' executes Lambda {ex.get('lambda')}"
                        ),
                        weight=0.4,
                    )
                )
            if ag.get("parentActionSignature") == "AMAZON.CodeInterpreter":
                f.add_capability("code-exec")
                f.add_evidence(
                    Evidence(
                        signal="aws:code-interpreter",
                        description="Built-in code interpreter enabled",
                        weight=0.4,
                    )
                )
            if ag.get("parentActionSignature") == "AMAZON.UserInput":
                f.add_tag("asks-user")
        if any(k.get("knowledgeBaseState") != "DISABLED" for k in kbs):
            f.add_capability("rag")
        if rec.get("_collaborators"):
            f.add_capability("multi-agent")
        deployed_versions = [v for v in rec.get("_versions_scanned") or [] if v != "DRAFT"]
        observed_versions = (
            [details[v] for v in deployed_versions if v in details] if deployed_versions else [rec]
        )
        if observed_versions and any(not v.get("guardrailConfiguration") for v in observed_versions):
            f.add_tag("no-guardrail")
        if rec.get("memoryConfiguration") or any(v.get("memoryConfiguration") for v in details.values()):
            f.add_capability("memory")
        f.owner = first_tag(rec.get("tags"), "owner", "Owner")
        name_hint(self.index, f, rec.get("agentName"), rec.get("description"))
        f.metadata.update(_bedrock_agent_metadata(rec, details, ags, kbs))
        return done(f, self.index, Kind.AGENT)

    def _agent_version_details(self, rec: dict[str, Any]) -> dict[str, dict[str, Any]]:
        raw_details = rec.get("_version_details") or {}
        if not isinstance(raw_details, dict):
            self.ctx.warn("cloud.aws: Bedrock agent has invalid version details")
            raw_details = {}
        details: dict[str, dict[str, Any]] = {}
        for version, version_detail in raw_details.items():
            if not isinstance(version_detail, dict):
                if str(version) == "DRAFT":
                    # Older exports collapsed the self-referential DRAFT entry; the
                    # DRAFT details are the agent record itself by construction.
                    version_detail = rec
                else:
                    self.ctx.warn("cloud.aws: Bedrock agent has invalid version details")
                    continue
            details[str(version)] = version_detail
        return details

    def _h_bedrock_knowledge_base(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.CLOUD_RESOURCE,
            title=f"Bedrock Knowledge Base: {rec.get('name')}",
            resource=_resource_id(rec.get("knowledgeBaseId") or rec.get("name")),
            resource_type="bedrock-knowledge-base",
            account=self.account,
            region=rec.get("_region"),
            last_seen=_optional_str(rec.get("updatedAt")),
        )
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_capability("rag")
        f.add_evidence(
            Evidence(
                signal="aws:knowledge-base",
                description=(
                    f"Knowledge base '{rec.get('name')}' ({rec.get('status')}): "
                    f"{truncate(rec.get('description'), 120)}"
                ),
                weight=0.6,
                signature="cloud.aws-bedrock-agents",
            )
        )
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_bedrock_flow(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.WORKFLOW,
            title=f"Bedrock Flow: {rec.get('name')}",
            resource=_resource_id(rec.get("arn") or rec.get("id")),
            resource_type="bedrock-flow",
            account=self.account,
            region=rec.get("_region"),
            last_seen=_optional_str(rec.get("updatedAt")),
        )
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_model_provider("provider.aws-bedrock")
        f.add_evidence(
            Evidence(
                signal="aws:bedrock-flow",
                description=f"Flow '{rec.get('name')}' ({rec.get('status')}) v{rec.get('version')}",
                weight=0.9,
                signature="cloud.aws-bedrock-agents",
            )
        )
        return done(f, self.index, Kind.WORKFLOW)

    def _h_bedrock_logging(self, rec: dict[str, Any]) -> Finding | None:
        if "loggingConfig" not in rec or self._is_error_record(rec):
            # Live collection always includes the key (null when disabled); an
            # export lacking it or carrying an error body cannot establish absence.
            self.ctx.warn(
                f"cloud.aws: Bedrock logging configuration unavailable for {rec.get('_region')}; "
                "coverage unknown",
                incomplete=True,
            )
            return None
        cfg = rec.get("loggingConfig")
        state = "enabled" if cfg else "DISABLED"
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.CLOUD_RESOURCE,
            title=f"Bedrock model invocation logging {state} in {rec.get('_region')}",
            resource=f"arn:aws:bedrock:{rec.get('_region')}:{self.account}:logging",
            resource_type="bedrock-logging",
            account=self.account,
            region=rec.get("_region"),
        )
        f.add_model_provider("provider.aws-bedrock")
        destinations = (
            json.dumps({k: bool(v) for k, v in (cfg or {}).items() if k.endswith("Config")})
            if cfg
            else "not configured — LLM usage in this region is not auditable"
        )
        f.add_evidence(
            Evidence(
                signal="aws:bedrock-logging",
                description="Model invocation logging configuration: " + destinations,
                weight=0.2,
            )
        )
        if not cfg:
            f.add_tag("no-invocation-logging")
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_bedrock_guardrail(self, rec: dict[str, Any]) -> Finding | None:
        return None  # informational; agents reference guardrails directly

    def _h_bedrock_custom_model(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.CLOUD_RESOURCE,
            title=f"Bedrock custom model: {rec.get('modelName')}",
            resource=_resource_id(rec.get("modelArn") or rec.get("modelName")),
            resource_type="bedrock-custom-model",
            account=self.account,
            region=rec.get("_region"),
            first_seen=_optional_str(rec.get("creationTime")),
        )
        f.add_model_provider("provider.aws-bedrock")
        f.add_evidence(
            Evidence(
                signal="aws:custom-model",
                description=f"Custom model '{rec.get('modelName')}' based on {rec.get('baseModelName')}",
                weight=0.5,
            )
        )
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_agentcore_runtime(self, rec: dict[str, Any]) -> Finding:
        arn = rec.get("agentRuntimeArn") or rec.get("agentRuntimeId")
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.AGENT,
            title=f"Bedrock AgentCore runtime: {rec.get('agentRuntimeName')}",
            resource=_resource_id(arn),
            resource_type="agentcore-runtime",
            account=self._arn_account(arn),
            region=rec.get("_region"),
            first_seen=_optional_str(rec.get("createdAt")),
            last_seen=_optional_str(rec.get("lastUpdatedAt")),
        )
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_capability("tool-use")
        artifact = rec.get("agentRuntimeArtifact") or {}
        image = (artifact.get("containerConfiguration") or {}).get("containerUri")
        network = (rec.get("networkConfiguration") or {}).get("networkMode")
        protocol = (rec.get("protocolConfiguration") or {}).get("serverProtocol")
        f.add_evidence(
            Evidence(
                signal="aws:agentcore-runtime",
                description=(
                    f"AgentCore runtime '{rec.get('agentRuntimeName')}' ({rec.get('status')}) "
                    f"role {rec.get('roleArn')} image {image or 'n/a'}; network {network}; protocol "
                    f"{protocol}"
                ),
                location=arn,
                weight=0.97,
                signature="cloud.aws-bedrock-agents",
            )
        )
        if image:
            apply_matches(f, self.index.match_image(image), weight_scale=0.8)
        scan_env(self.index, f, rec.get("environmentVariables"), location=arn)
        auth = rec.get("authorizerConfiguration")
        if not auth:
            f.add_tag("iam-auth-only")
        f.metadata.update(
            {
                "status": rec.get("status"),
                "role": rec.get("roleArn"),
                "image": image,
                "protocol": protocol,
                "network": network,
                "authorizer": bool(auth),
                "description": truncate(rec.get("description")),
            }
        )
        return done(f, self.index, Kind.AGENT)

    def _h_agentcore_gateway(self, rec: dict[str, Any]) -> Finding:
        arn = rec.get("gatewayArn") or rec.get("gatewayId")
        targets = rec.get("_targets") or []
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.MCP_SERVER,
            title=f"AgentCore Gateway (MCP): {rec.get('name')}",
            resource=_resource_id(arn),
            resource_type="agentcore-gateway",
            account=self._arn_account(arn),
            region=rec.get("_region"),
            first_seen=_optional_str(rec.get("createdAt")),
        )
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_framework("protocol.mcp")
        f.add_capability("tool-use")
        f.add_capability("saas-actions")
        f.add_evidence(
            Evidence(
                signal="aws:agentcore-gateway",
                description=(
                    f"Gateway '{rec.get('name')}' ({rec.get('status')}) protocol {rec.get('protocolType')} "
                    f"authorizer {rec.get('authorizerType')} with {len(targets)} target(s): "
                    f"{', '.join(str(t.get('name')) for t in targets[:8])}"
                ),
                location=arn,
                weight=0.95,
                signature="cloud.aws-bedrock-agents",
            )
        )
        if any(
            t.get("targetType") == "LAMBDA"
            or (t.get("targetConfiguration") or {}).get("mcp", {}).get("lambda")
            for t in targets
        ):
            f.add_capability("code-exec")
        f.metadata.update(
            {
                "protocol": rec.get("protocolType"),
                "authorizer": rec.get("authorizerType"),
                "targets": [{"name": t.get("name"), "status": t.get("status")} for t in targets][:30],
                "url": rec.get("gatewayUrl"),
            }
        )
        return done(f, self.index, Kind.MCP_SERVER)

    def _h_agentcore_memory(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.CLOUD_RESOURCE,
            title=f"AgentCore Memory: {rec.get('name') or rec.get('id')}",
            resource=_resource_id(rec.get("arn") or rec.get("id")),
            resource_type="agentcore-memory",
            account=self.account,
            region=rec.get("_region"),
        )
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_capability("memory")
        f.add_evidence(
            Evidence(
                signal="aws:agentcore-memory",
                description=f"Memory store '{rec.get('name') or rec.get('id')}' ({rec.get('status')})",
                weight=0.7,
                signature="cloud.aws-bedrock-agents",
            )
        )
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_agentcore_browser(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.CLOUD_RESOURCE,
            title=f"AgentCore Browser: {rec.get('name') or rec.get('browserId')}",
            resource=_resource_id(rec.get("browserArn") or rec.get("browserId")),
            resource_type="agentcore-browser",
            account=self.account,
            region=rec.get("_region"),
        )
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_capability("browsing")
        f.add_evidence(
            Evidence(
                signal="aws:agentcore-browser",
                description=f"Managed browser '{rec.get('name')}' ({rec.get('status')})",
                weight=0.7,
                signature="cloud.aws-bedrock-agents",
            )
        )
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_agentcore_code_interpreter(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.CLOUD_RESOURCE,
            title=f"AgentCore Code Interpreter: {rec.get('name') or rec.get('codeInterpreterId')}",
            resource=_resource_id(rec.get("codeInterpreterArn") or rec.get("codeInterpreterId")),
            resource_type="agentcore-code-interpreter",
            account=self.account,
            region=rec.get("_region"),
        )
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_capability("code-exec")
        f.add_evidence(
            Evidence(
                signal="aws:agentcore-code-interpreter",
                description=f"Code interpreter '{rec.get('name')}' ({rec.get('status')})",
                weight=0.7,
                signature="cloud.aws-bedrock-agents",
            )
        )
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_agentcore_workload_identity(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.SERVICE_IDENTITY,
            title=f"AgentCore workload identity: {rec.get('name')}",
            resource=_resource_id(rec.get("workloadIdentityArn") or rec.get("name")),
            resource_type="agentcore-workload-identity",
            account=self.account,
            region=rec.get("_region"),
            surface=Surface.IDENTITY,
        )
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_capability("delegated-identity")
        return_urls = ", ".join(rec.get("allowedResourceOauth2ReturnUrls") or [])[:200] or "none"
        f.add_evidence(
            Evidence(
                signal="aws:agentcore-identity",
                description=f"Agent workload identity '{rec.get('name')}' (OAuth return URLs: {return_urls})",
                weight=0.8,
                signature="cloud.aws-bedrock-agents",
            )
        )
        return done(f, self.index, Kind.SERVICE_IDENTITY)

    def _h_lambda(self, rec: dict[str, Any]) -> Finding | None:
        arn = rec.get("FunctionArn")
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.CLOUD_RESOURCE,
            title=f"Lambda function: {rec.get('FunctionName')}",
            resource=_resource_id(arn or rec.get("FunctionName")),
            resource_type="lambda-function",
            account=self._arn_account(arn),
            region=rec.get("_region"),
            last_seen=rec.get("LastModified"),
        )
        if rec.get("environment_coverage") == "unknown":
            # Preserve coverage when sanitized collection records are rescanned.
            self.ctx.warn("cloud.aws: Lambda environment coverage is unknown")
        scan_env(self.index, f, rec.get("Environment"), location=arn)
        for layer in rec.get("Layers") or []:
            # arn:aws:lambda:REGION:ACCOUNT:layer:NAME:VERSION -> NAME
            layer_name = layer.split(":")[6] if layer.count(":") >= 7 else layer
            hints = self.index.match_domains_in_text(layer)
            for m in hints + self.index.match_code(layer_name.replace("-", " ")):
                apply_matches(f, [m], location=arn, weight_scale=0.5)
            low = layer.lower()
            for key, sig in _LAYER_HINTS:
                if key in low:
                    sig_obj = self.index.get(sig)
                    if sig_obj:
                        if sig_obj.category == "provider":
                            f.add_model_provider(sig)
                        else:
                            f.add_framework(sig)
                        f.add_evidence(
                            Evidence(
                                signal="aws:lambda-layer",
                                description=f"Layer {layer} suggests {sig_obj.name}",
                                location=arn,
                                weight=0.5,
                                signature=sig,
                            )
                        )
        if rec.get("ImageUri"):
            apply_matches(f, self.index.match_image(rec["ImageUri"]), location=arn)
        name_hint(self.index, f, rec.get("FunctionName"), rec.get("Description"))
        scan_blob(self.index, f, rec.get("Tags") or {}, location=arn, weight_scale=0.4)
        if not f.frameworks and not f.model_providers:
            return None
        f.add_evidence(
            Evidence(
                signal="aws:lambda",
                description=(
                    f"Function '{rec.get('FunctionName')}' ({rec.get('Runtime') or rec.get('PackageType')}), "
                    f"role {rec.get('Role')}"
                ),
                location=arn,
                weight=0.2,
            )
        )
        f.owner = first_tag(rec.get("Tags"), "owner", "Owner", "team")
        f.metadata.update(
            {
                "runtime": rec.get("Runtime"),
                "role": rec.get("Role"),
                "handler": rec.get("Handler"),
                "layers": rec.get("Layers"),
                "image": rec.get("ImageUri"),
                "env_names": sorted((rec.get("Environment") or {}).keys())[:40],
                "environment_coverage": rec.get("environment_coverage", "unspecified"),
                "tags": rec.get("Tags"),
            }
        )
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_ecs_task_definition(self, rec: dict[str, Any]) -> Finding | None:
        arn = rec.get("taskDefinitionArn")
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.CLOUD_RESOURCE,
            title=f"ECS task definition: {rec.get('family')}",
            resource=_resource_id(arn or rec.get("family")),
            resource_type="ecs-task-definition",
            account=self._arn_account(arn),
            region=rec.get("_region"),
        )
        for c in rec.get("containers") or []:
            if c.get("image"):
                apply_matches(f, self.index.match_image(c["image"]), location=arn)
            scan_env(self.index, f, c.get("environment"), location=arn)
            for s in c.get("secrets") or []:
                apply_matches(f, self.index.match_env(str(s)), location=arn, weight_scale=0.6)
        if not f.frameworks and not f.model_providers:
            return None
        images = ", ".join(str(c.get("image")) for c in rec.get("containers") or [])[:300]
        f.add_evidence(
            Evidence(
                signal="aws:ecs",
                description=(
                    f"Task definition '{rec.get('family')}' containers: {images}; "
                    f"task role {rec.get('taskRoleArn')}"
                ),
                location=arn,
                weight=0.2,
            )
        )
        f.metadata.update(
            {
                "task_role": rec.get("taskRoleArn"),
                "containers": [
                    {"name": c.get("name"), "image": c.get("image")} for c in rec.get("containers") or []
                ],
                "task_definition_status": rec.get("status"),
                "revision": rec.get("revision"),
                "deployment_state": rec.get("deployment_state", "unknown"),
                "discovery_sources": rec.get("discovery_sources", []),
                "workload_references": rec.get("workload_references", []),
                "workload_reference_count": rec.get(
                    "workload_reference_count", len(rec.get("workload_references", []))
                ),
                "workload_references_truncated": rec.get("workload_references_truncated", False),
            }
        )
        if rec.get("workload_references"):
            f.add_evidence(
                Evidence(
                    signal="aws:ecs-workload-reference",
                    description=(
                        "Exact task definition referenced by ECS tasks or services; "
                        "this shows workload configuration, not observed model invocation."
                    ),
                    location=arn,
                    weight=0.2,
                )
            )
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_sagemaker_endpoint(self, rec: dict[str, Any]) -> Finding | None:
        arn = rec.get("EndpointArn")
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.CLOUD_RESOURCE,
            title=f"SageMaker endpoint: {rec.get('EndpointName')}",
            resource=_resource_id(arn or rec.get("EndpointName")),
            resource_type="sagemaker-endpoint",
            account=self._arn_account(arn),
            region=rec.get("_region"),
            first_seen=rec.get("CreationTime"),
            last_seen=rec.get("LastModifiedTime"),
        )
        llm = False
        for m in rec.get("models") or []:
            for img in m.get("images") or []:
                if img:
                    ms = self.index.match_image(img)
                    apply_matches(f, ms, location=arn)
                    if ms or any(k in img.lower() for k in _LLM_IMAGE_HINTS):
                        llm = True
            scan_env(self.index, f, m.get("env"), location=arn)
            if any(k in json.dumps(m.get("env") or {}) for k in _LLM_ENV_HINTS):
                llm = True
        if not llm and not f.frameworks and not f.model_providers:
            return None
        if llm and not f.model_providers:
            f.add_model_provider("provider.huggingface")
        models = rec.get("models") or []
        f.add_evidence(
            Evidence(
                signal="aws:sagemaker",
                description=(
                    f"Endpoint '{rec.get('EndpointName')}' ({rec.get('EndpointStatus')}) serving "
                    f"{', '.join(str(m.get('name')) for m in models)} "
                    f"on {', '.join(str(m.get('instance')) for m in models)}"
                ),
                location=arn,
                weight=0.6,
            )
        )
        # Environment values never enter finding metadata: they are analysed
        # above and a benign value could otherwise be redacted out of sibling
        # identity fields. Keep the variable names, as the Lambda handler does.
        f.metadata.update(
            {
                "status": rec.get("EndpointStatus"),
                "models": [
                    {
                        **{k: v for k, v in m.items() if k != "env"},
                        "env_names": sorted(str(k) for k in (m.get("env") or {}))[:40],
                    }
                    for m in rec.get("models") or []
                    if isinstance(m, dict)
                ],
            }
        )
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_state_machine(self, rec: dict[str, Any]) -> Finding | None:
        arn = rec.get("stateMachineArn")
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.WORKFLOW,
            title=f"Step Functions workflow with LLM steps: {rec.get('name')}",
            resource=_resource_id(arn),
            resource_type="state-machine",
            account=self._arn_account(arn),
            region=rec.get("_region"),
            first_seen=rec.get("creationDate"),
        )
        definition = rec.get("definition") or ""
        if "bedrock" not in definition.lower() and "sagemaker" not in definition.lower():
            return None
        scan_blob(self.index, f, definition, location=arn)
        if "arn:aws:states:::bedrock" in definition or "bedrock:invokeModel" in definition:
            f.add_model_provider("provider.aws-bedrock")
            f.add_evidence(
                Evidence(
                    signal="aws:sfn-bedrock",
                    description="State machine invokes Bedrock (optimized integration)",
                    location=arn,
                    weight=0.8,
                    signature="provider.aws-bedrock",
                )
            )
        f.add_capability("autonomous")
        f.metadata.update({"role": rec.get("roleArn")})
        return done(f, self.index, Kind.WORKFLOW)

    def _h_qbusiness_application(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.AGENT,
            title=f"Amazon Q Business application: {rec.get('displayName')}",
            resource=(
                f"arn:aws:qbusiness:{rec.get('_region')}:{self.account}:"
                f"application/{rec.get('applicationId')}"
            ),
            resource_type="qbusiness-application",
            account=self.account,
            region=rec.get("_region"),
            first_seen=_optional_str(rec.get("createdAt")),
            last_seen=_optional_str(rec.get("updatedAt")),
        )
        f.add_framework("cloud.aws-other-ai")
        f.add_capability("rag")
        f.add_evidence(
            Evidence(
                signal="aws:qbusiness",
                description=(
                    f"Q Business app '{rec.get('displayName')}' ({rec.get('status')}), "
                    f"identity type {rec.get('identityType')}"
                ),
                weight=0.9,
                signature="cloud.aws-other-ai",
            )
        )
        return done(f, self.index, Kind.AGENT)

    def _h_lex_bot(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.AGENT,
            title=f"Lex bot: {rec.get('botName')}",
            resource=f"arn:aws:lex:{rec.get('_region')}:{self.account}:bot/{rec.get('botId')}",
            resource_type="lex-bot",
            account=self.account,
            region=rec.get("_region"),
            last_seen=_optional_str(rec.get("lastUpdatedDateTime")),
        )
        f.add_framework("cloud.aws-other-ai")
        f.add_evidence(
            Evidence(
                signal="aws:lex",
                description=(
                    f"Lex V2 bot '{rec.get('botName')}' ({rec.get('botStatus')}, type {rec.get('botType')})"
                ),
                weight=0.8,
                signature="cloud.aws-other-ai",
            )
        )
        return done(f, self.index, Kind.AGENT)

    def _h_secret_name(self, rec: dict[str, Any]) -> Finding | None:
        return self._name_only_secret(rec, "secretsmanager-secret", rec.get("ARN"))

    def _h_ssm_parameter(self, rec: dict[str, Any]) -> Finding | None:
        name = str(rec.get("Name") or "").lstrip("/")
        arn = f"arn:aws:ssm:{rec.get('_region')}:{self.account}:parameter/{name}"
        return self._name_only_secret(rec, "ssm-parameter", arn)

    def _name_only_secret(self, rec: dict[str, Any], rtype: str, arn: str | None) -> Finding | None:
        name = str(rec.get("Name") or "")
        matches = credential_name_matches(self.index, name, _LLM_SECRET_KEYWORDS)
        if matches is None:
            return None
        text_hits = [
            m
            for m in self.index.match_name(name.replace("/", " ").replace("-", " "))
            if m.signature.category != "identity-app"
        ]
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.SECRET,
            title=f"Stored LLM credential ({rtype}): {name}",
            resource=arn or name,
            resource_type=rtype,
            account=self.account,
            region=rec.get("_region"),
            last_seen=rec.get("LastAccessedDate") or rec.get("LastModifiedDate"),
        )
        apply_matches(f, matches + text_hits, location=arn, weight_scale=0.7)
        f.add_evidence(
            Evidence(
                signal=f"aws:{rtype}",
                description=(
                    f"{rtype} named '{name}' looks like an LLM provider credential (name only; value not "
                    "read)"
                ),
                location=arn,
                weight=0.4,
            )
        )
        f.add_tag("managed-secret")
        f.metadata.update({"name": name, "description": rec.get("Description"), "tags": rec.get("Tags")})
        return done(f, self.index, Kind.SECRET)

    def _h_iam_principal(self, rec: dict[str, Any]) -> Finding | None:
        actions = rec.get("actions") or []
        if not isinstance(actions, list) or any(not isinstance(action, str) for action in actions):
            raise ValueError("invalid IAM actions")
        default_patterns = [action for action in actions if _action_has_ai_scope(action)]
        ai_patterns = rec.get("ai_action_patterns", default_patterns)
        if not isinstance(ai_patterns, list) or any(
            not isinstance(action, str) or action not in actions or not _action_has_ai_scope(action)
            for action in ai_patterns
        ):
            raise ValueError("invalid AI action patterns")
        potential = rec.get("potential_actions") or []
        limitations = rec.get("policy_limitations") or []
        if not isinstance(potential, list) or any(not isinstance(action, str) for action in potential):
            raise ValueError("invalid potential IAM actions")
        if not isinstance(limitations, list) or any(not isinstance(limit, str) for limit in limitations):
            raise ValueError("invalid IAM policy limitations")
        if limitations:
            self.ctx.warn(
                "cloud.aws: IAM policy evidence has unevaluated semantics; effective authorization is unknown"
            )
        if not ai_patterns and not potential:
            return None
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.IAM_GRANT,
            title=f"IAM {rec.get('type')} with potential LLM/agent access: {rec.get('name')}",
            resource=_resource_id(rec.get("arn") or rec.get("name")),
            resource_type=f"iam-{str(rec.get('type', 'principal')).lower()}",
            account=self._arn_account(rec.get("arn")),
            first_seen=rec.get("created"),
            last_seen=rec.get("last_used"),
            surface=Surface.IDENTITY,
        )
        classified = scan_iam_actions(self.index, f, actions, location=rec.get("arn"))
        llm = [action for action in classified if action in ai_patterns]
        for action in potential:
            apply_matches(f, self.index.match_scope(action), location=rec.get("arn"), weight_scale=0.3)
        # Ancillary privileges remain evidence only after an AI grant exists.
        wildcard = [a for a in actions if "*" in a or "?" in a]
        principals = _trust_principals(rec.get("assume_role_policy"))
        if principals is None:
            # Unknown trust is not "no service trust": keep the grant evidence
            # but never let the scan read as complete.
            self.ctx.warn("cloud.aws: malformed IAM trust policy; trusted principals unknown")
            limitations = [*limitations, "malformed-trust-policy"]
            trust_note = "trust policy malformed, trusted principals unknown"
        else:
            trust_note = f"trusted by {', '.join(principals) or 'users/accounts'}"
        wildcard_note = " + wildcards " + ", ".join(wildcard[:3]) if wildcard else ""
        potential_note = "; potential NotAction grants " + ", ".join(potential[:8]) if potential else ""
        f.add_evidence(
            Evidence(
                signal="aws:iam",
                description=(
                    f"Policy evidence for {rec.get('type')} '{rec.get('name')}': explicit actions "
                    f"{', '.join(llm[:8]) or 'none'}{wildcard_note}{potential_note}; "
                    f"{trust_note}. Effective authorization is not evaluated."
                ),
                location=rec.get("arn"),
                weight=0.45 if llm else 0.25,
            )
        )
        if principals and _BEDROCK_TRUST_SERVICES.intersection(principals):
            f.add_framework("cloud.aws-bedrock-agents")
            f.add_tag("agent-execution-role")
        if wildcard:
            f.add_tag("wildcard-permissions")
        name_hint(self.index, f, rec.get("name"))
        f.owner = first_tag(rec.get("tags"), "owner", "Owner")
        f.metadata.update(
            {
                "principal_type": rec.get("type"),
                "llm_actions": llm[:40],
                "ai_action_patterns": ai_patterns,
                "potential_actions": potential,
                "policy_limitations": limitations,
                "effective_permissions": "not-evaluated",
                "wildcards": wildcard[:10],
                "attached_policies": rec.get("attached_policies"),
                "trusted_services": principals or [],
                "action_count": len(actions),
            }
        )
        return done(f, self.index, Kind.IAM_GRANT)

    # ------------------------------------------------------------ cloudtrail
    @staticmethod
    def _acc_caller(callers: dict[str, dict[str, Any]], rec: dict[str, Any]) -> None:
        agg = aggregate_caller_event(
            callers,
            rec.get("principal") or "unknown",
            time=rec.get("eventTime"),
            tally_present={
                "agents": rec.get("userAgent"),
                "models": rec.get("modelId"),
                "ops": rec.get("eventName"),
                "ips": rec.get("sourceIp"),
            },
            seed={"identity_type": rec.get("identityType"), "regions": set(), "errors": 0},
        )
        agg["regions"].add(rec.get("_region"))
        if rec.get("errorCode"):
            agg["errors"] += 1

    def _caller_finding(self, principal: str, agg: dict[str, Any]) -> Finding:
        f = cloud_finding(
            self.name,
            "aws",
            kind=Kind.GATEWAY_CALLER,
            title=f"LLM caller (CloudTrail): {principal.rsplit('/', 1)[-1]} — {agg['events']} invocation(s)",
            resource=f"cloudtrail:{principal}",
            resource_type=f"caller/{agg.get('identity_type') or 'principal'}",
            account=self._arn_account(principal if principal.startswith("arn:") else None),
            first_seen=agg["first"],
            last_seen=agg["last"],
            surface=Surface.GATEWAY,
        )
        f.add_model_provider("provider.aws-bedrock")
        for model in list(agg["models"])[:10]:
            apply_matches(f, model_matches(self.index, model), weight_scale=0.4)
        for ua in list(agg["agents"])[:10]:
            apply_matches(f, self.index.match_user_agent(ua))
        f.models = sorted(agg["models"], key=lambda m: -agg["models"][m])[:10]
        weight = 0.5 if agg.get("identity_type") in {"AssumedRole", "AWSService", "WebIdentityUser"} else 0.3
        operations = ", ".join(f"{k}×{v}" for k, v in list(agg["ops"].items())[:5])
        f.add_evidence(
            Evidence(
                signal="aws:cloudtrail",
                description=(
                    f"{agg['events']} LLM API call(s) ({operations}) by {agg.get('identity_type')} "
                    f"{principal}"
                ),
                weight=weight,
            )
        )
        if any(op.startswith("InvokeAgent") or op == "InvokeFlow" for op in agg["ops"]):
            f.add_framework("cloud.aws-bedrock-agents")
            f.add_capability("tool-use")
        if agg.get("identity_type") == "IAMUser":
            f.add_tag("long-lived-credentials")
        name_hint(self.index, f, principal)
        f.metadata.update(
            {
                "principal": principal,
                "identity_type": agg.get("identity_type"),
                "events": agg["events"],
                "models": agg["models"],
                "operations": agg["ops"],
                "user_agents": dict(sorted(agg["agents"].items(), key=lambda kv: -kv[1])[:5]),
                "source_ips": dict(sorted(agg["ips"].items(), key=lambda kv: -kv[1])[:5]),
                "regions": sorted(r for r in agg["regions"] if r),
                "errors": agg["errors"],
            }
        )
        return done(f, self.index, Kind.GATEWAY_CALLER)


class _EcsInventory:
    """Task definitions used by one region's ECS workloads, within an API call budget.

    Families resolve to the latest ACTIVE revision, which is not necessarily
    deployed. Exact references from running tasks and service deployments are
    discovered first, including INACTIVE definitions still in use, and then the
    latest registered revision of every active family.
    """

    def __init__(self, connector: AwsConnector, client: Any, region: str) -> None:
        self.connector = connector
        self.ctx = connector.ctx
        self.client = client
        self.region = region
        self.remaining = connector.max_ecs_api_calls
        self.limit_reported = False
        self.definitions: dict[str, dict[str, Any]] = {}
        self.attempted: set[str] = set()
        self.reference_keys: dict[str, set[str]] = {}

    def collect(self) -> Iterator[dict[str, Any]]:
        for cluster in self.identifiers("list_clusters", "clusterArns"):
            self.add_task_references(cluster)
            self.add_service_references(cluster)
        for family in self.identifiers("list_task_definition_families", "families", status="ACTIVE"):
            self.add_definition(family, "registered-family")
        yield from self.definitions.values()

    def call(self, op: str, **kwargs: Any) -> dict[str, Any] | None:
        """One budgeted request; exhaustion, failures and malformed responses mark coverage incomplete."""
        if self.remaining == 0:
            if not self.limit_reported:
                self.ctx.warn(f"cloud.aws: max_ecs_api_calls reached in {self.region}", incomplete=True)
                self.limit_reported = True
            return None
        self.remaining -= 1
        response = self.connector._safe(lambda: getattr(self.client, op)(**kwargs))
        if response is None:
            return None
        if not isinstance(response, dict):
            self.ctx.warn(f"cloud.aws: invalid ECS {op} response in {self.region}", incomplete=True)
            return None
        if response.get("failures"):
            self.ctx.warn(f"cloud.aws: partial ECS {op} failure in {self.region}", incomplete=True)
        return response

    def identifiers(self, op: str, key: str, **kwargs: Any) -> Iterator[str]:
        token = None
        seen: set[str] = set()
        while True:
            response = self.call(op, maxResults=100, **kwargs, **({"nextToken": token} if token else {}))
            if response is None:
                return
            values = response.get(key)
            if not isinstance(values, list) or any(
                not isinstance(value, str) or not value for value in values
            ):
                self.ctx.warn(f"cloud.aws: invalid ECS {key} page in {self.region}", incomplete=True)
                return
            yield from values
            token = response.get("nextToken")
            if token is None or token == "":
                return
            if not isinstance(token, str) or token in seen:
                self.ctx.warn(
                    f"cloud.aws: invalid or repeated ECS pagination token in {self.region}",
                    incomplete=True,
                )
                return
            seen.add(token)

    def describe(
        self,
        op: str,
        key: str,
        arn_key: str,
        batch: list[str],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Describe one batch; a response that omits a requested ARN marks coverage incomplete."""
        response = self.call(op, **kwargs)
        if response is None:
            return []
        returned = response.get(key, [])
        if not isinstance(returned, list) or any(not isinstance(item, dict) for item in returned):
            self.ctx.warn(f"cloud.aws: invalid ECS {key} in {self.region}", incomplete=True)
            return []
        if set(batch) != {item.get(arn_key) for item in returned}:
            noun = key.removesuffix("s")
            self.ctx.warn(f"cloud.aws: incomplete ECS {noun} descriptions in {self.region}", incomplete=True)
        return returned

    def add_task_references(self, cluster: str) -> None:
        # Desired RUNNING also covers tasks whose lastStatus is PENDING.
        tasks = self.identifiers("list_tasks", "taskArns", cluster=cluster, desiredStatus="RUNNING")
        for batch in _batches(tasks, 100):
            returned = self.describe(
                "describe_tasks", "tasks", "taskArn", batch, cluster=cluster, tasks=batch
            )
            for task in returned:
                self.add_definition(
                    task.get("taskDefinitionArn"),
                    "task",
                    {
                        "cluster": cluster,
                        "task": task.get("taskArn"),
                        "last_status": task.get("lastStatus"),
                        "desired_status": task.get("desiredStatus"),
                    },
                )

    def add_service_references(self, cluster: str) -> None:
        services = self.identifiers("list_services", "serviceArns", cluster=cluster)
        for batch in _batches(services, 10):
            returned = self.describe(
                "describe_services", "services", "serviceArn", batch, cluster=cluster, services=batch
            )
            for service in returned:
                if service.get("status") == "INACTIVE":
                    continue
                rollouts = [*(service.get("deployments") or []), *(service.get("taskSets") or [])]
                for deployment in [service, *rollouts]:
                    if deployment.get("taskDefinition"):
                        self.add_definition(
                            deployment["taskDefinition"],
                            "service",
                            {
                                "cluster": cluster,
                                "service": service.get("serviceArn"),
                                "deployment": deployment.get("id"),
                                "status": deployment.get("status"),
                                "running_count": deployment.get("runningCount"),
                                "desired_count": deployment.get("desiredCount"),
                            },
                        )

    def add_definition(self, identifier: Any, source: str, reference: dict[str, Any] | None = None) -> None:
        if not isinstance(identifier, str) or not identifier:
            self.ctx.warn(
                f"cloud.aws: missing ECS task definition identifier in {self.region}",
                incomplete=True,
            )
            return
        record = self.definitions.get(identifier)
        if record is None:
            if identifier in self.attempted:
                return
            self.attempted.add(identifier)
            record = self.describe_definition(identifier)
            if record is None:
                return
        if source not in record["discovery_sources"]:
            record["discovery_sources"].append(source)
        if reference:
            self.add_reference(record, reference)

    def describe_definition(self, identifier: str) -> dict[str, Any] | None:
        response = self.call("describe_task_definition", taskDefinition=identifier)
        if response is None:
            return None
        definition = response.get("taskDefinition")
        if (
            not isinstance(definition, dict)
            or not isinstance(definition.get("taskDefinitionArn"), str)
            or not definition["taskDefinitionArn"]
        ):
            self.ctx.warn(f"cloud.aws: invalid ECS task definition in {self.region}", incomplete=True)
            return None
        arn = definition["taskDefinitionArn"]
        if identifier.startswith("arn:") and arn != identifier:
            self.ctx.warn(f"cloud.aws: mismatched ECS task definition in {self.region}", incomplete=True)
            return None
        return self.definitions.setdefault(arn, _ecs_definition_record(definition, arn, self.region))

    def add_reference(self, record: dict[str, Any], reference: dict[str, Any]) -> None:
        keys = self.reference_keys.setdefault(record["taskDefinitionArn"], set())
        key = json.dumps(reference, sort_keys=True)
        if key not in keys:
            keys.add(key)
            record["workload_reference_count"] += 1
            # Inventory every referenced definition, but do not embed
            # an unbounded fleet of task IDs in a single finding.
            if len(record["workload_references"]) < 100:
                record["workload_references"].append(reference)
            else:
                record["workload_references_truncated"] = True
        if reference.get("task") and reference.get("last_status") == "RUNNING":
            record["deployment_state"] = "running-task-observed"
        elif record["deployment_state"] == "registered-only":
            record["deployment_state"] = "workload-referenced"


def _batches(values: Iterator[str], size: int) -> Iterator[list[str]]:
    while batch := list(islice(values, size)):
        yield batch


def _ecs_definition_record(definition: dict[str, Any], arn: str, region: str) -> dict[str, Any]:
    return {
        "_kind": "ecs-task-definition",
        "_region": region,
        "family": definition.get("family"),
        "taskDefinitionArn": arn,
        "taskRoleArn": definition.get("taskRoleArn"),
        "status": definition.get("status"),
        "revision": definition.get("revision"),
        "containers": [
            {
                "name": c.get("name"),
                "image": c.get("image"),
                "environment": {e["name"]: e.get("value") for e in c.get("environment") or []},
                "secrets": [s.get("name") for s in c.get("secrets") or []],
            }
            for c in definition.get("containerDefinitions") or []
        ],
        "discovery_sources": [],
        "workload_references": [],
        "workload_reference_count": 0,
        "workload_references_truncated": False,
        "deployment_state": "registered-only",
    }


def _cloudtrail_record(ev: dict[str, Any], region: str) -> dict[str, Any] | None:
    """Normalize one LookupEvents entry, or None when its embedded JSON is invalid.

    Ambiguous (duplicate-field) or malformed event JSON is not read as an empty
    event: the caller skips it and marks event coverage incomplete.
    """
    try:
        detail = strict_json_loads(ev.get("CloudTrailEvent") or "{}")
    except (ValueError, RecursionError):
        return None
    ident = detail.get("userIdentity") or {}
    return {
        "_kind": "cloudtrail-event",
        "_region": region,
        "eventName": ev.get("EventName"),
        "eventTime": str(ev.get("EventTime")),
        "eventSource": ev.get("EventSource"),
        "principal": ident.get("arn") or ident.get("principalId"),
        "identityType": ident.get("type"),
        "userAgent": detail.get("userAgent"),
        "sourceIp": detail.get("sourceIPAddress"),
        "modelId": (detail.get("requestParameters") or {}).get("modelId")
        or (detail.get("requestParameters") or {}).get("agentId"),
        "errorCode": detail.get("errorCode"),
    }


def _bedrock_agent_metadata(
    rec: dict[str, Any],
    details: dict[str, dict[str, Any]],
    ags: list[Any],
    kbs: list[Any],
) -> dict[str, Any]:
    return {
        "agent_id": rec.get("agentId"),
        "status": rec.get("agentStatus"),
        "foundation_model": rec.get("foundationModel"),
        "role": rec.get("agentResourceRoleArn"),
        "instruction": truncate(rec.get("instruction"), 300),
        "versions_scanned": rec.get("_versions_scanned") or [],
        "version_models": {v: d.get("foundationModel") for v, d in details.items()},
        "version_guardrails": {v: d.get("guardrailConfiguration") for v, d in details.items()},
        "action_groups": [
            {
                "name": a.get("actionGroupName"),
                "lambda": (a.get("actionGroupExecutor") or {}).get("lambda"),
                "state": a.get("actionGroupState"),
                "version": a.get("agentVersion"),
            }
            for a in ags
        ],
        "knowledge_bases": sorted({k.get("knowledgeBaseId") for k in kbs if k.get("knowledgeBaseId")}),
        "knowledge_base_versions": [
            {
                "id": k.get("knowledgeBaseId"),
                "version": k.get("_agentVersion"),
                "state": k.get("knowledgeBaseState"),
            }
            for k in kbs
        ],
        "collaborator_versions": [
            {
                "name": c.get("collaboratorName"),
                "id": c.get("collaboratorId"),
                "version": c.get("_agentVersion"),
            }
            for c in rec.get("_collaborators") or []
        ],
        "aliases": [a.get("agentAliasName") for a in rec.get("_aliases") or []],
        "guardrail": rec.get("guardrailConfiguration"),
        "collaboration": rec.get("agentCollaboration"),
    }


def _policy_strings(value: Any) -> list[str] | None:
    """A policy element as a nonempty list of nonblank strings, or None when malformed."""
    values = [value] if isinstance(value, str) else value
    if (
        not isinstance(values, list)
        or not values
        or any(not isinstance(v, str) or not v.strip() for v in values)
    ):
        return None
    return values


def _policy_document(value: Any) -> Any:
    """A policy document as given, or decoded from JSON text or URL-encoded JSON text.

    The IAM API returns documents URL-encoded; SDKs and most exports decode them.
    Raises ValueError (or RecursionError) for text that is neither.
    """
    if not isinstance(value, str):
        return value
    try:
        return strict_json_loads(value)
    except json.JSONDecodeError:
        # Only text that is not JSON at all is retried: an ambiguous (duplicate
        # field) document stays malformed rather than being reinterpreted.
        return strict_json_loads(unquote(value))


def _grants_assume_role(action: str) -> bool:
    """Whether an IAM action expression (``*`` and ``?`` wildcards, any case) includes role assumption."""
    if "[" in action or "]" in action:
        return False  # IAM uses * and ?, not fnmatch character classes.
    return any(fnmatchcase(candidate, action.lower()) for candidate in _ASSUME_ROLE_ACTIONS)


def _trust_principals(document: Any) -> list[str] | None:
    """Workload service principals and OIDC federation that a role trust policy allows.

    Only ``Allow`` statements whose ``Action`` includes role assumption count,
    with principals read from ``Principal.Service`` and ``Principal.Federated``.
    ``Deny``, ``NotAction`` and ``NotPrincipal`` statements never establish
    trust; conditions are not evaluated. An absent document trusts no service.
    Returns None for a malformed document: its trusted principals are unknown.
    """
    if document is None:
        return []
    try:
        policy = _policy_document(document)
    except (ValueError, RecursionError):
        return None
    statements = policy.get("Statement") if isinstance(policy, dict) else None
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        return None
    services: set[str] = set()
    federated = False
    for st in statements:
        if (
            not isinstance(st, dict)
            or not isinstance(st.get("Effect"), str)
            or st["Effect"] not in {"Allow", "Deny"}
            or ("Action" in st) == ("NotAction" in st)
            or ("Principal" in st) == ("NotPrincipal" in st)
        ):
            return None
        if st["Effect"] != "Allow" or "Action" not in st or "Principal" not in st:
            continue
        actions = _policy_strings(st["Action"])
        # "*" is everyone: it names no service or identity provider.
        principal = {} if st["Principal"] == "*" else st["Principal"]
        named = (
            {key: _policy_strings(value) for key, value in principal.items()}
            if isinstance(principal, dict)
            else None
        )
        if actions is None or named is None or any(names is None for names in named.values()):
            return None
        if not any(_grants_assume_role(action) for action in actions):
            continue
        services.update(named.get("Service") or [])
        federated = federated or any(
            "oidc-provider" in name or _GITHUB_ACTIONS_OIDC in name for name in named.get("Federated") or []
        )
    principals = [svc for svc in _WORKLOAD_TRUST_SERVICES if svc in services]
    if federated:
        principals.append("oidc-federated")
    return principals


def _resource_services(resources: list[str] | None, limitations: set[str]) -> set[str]:
    """Service scopes of a statement's resources (``*`` for any); others limit the analysis."""
    services: set[str] = set()
    for resource in resources or []:
        parts = resource.split(":", 5)
        if resource == "*":
            services.add("*")
        elif (
            len(parts) == 6 and parts[0] == "arn" and parts[2] and "[" not in parts[2] and "]" not in parts[2]
        ):
            services.add(parts[2].lower())
        else:
            limitations.add("resource-scope-not-evaluated")
    return services


def _iam_policy_signals(docs: list[Any]) -> tuple[set[str], set[str], set[str], set[str]]:
    """Collect policy evidence without claiming effective permissions.

    NotAction has an open-ended action universe. Check representative AI
    operations only, scoped to the resource's service, and disclose that the
    complement, resource/action compatibility and policy evaluation are partial.
    Conditions, denies and boundaries can restrict every observation here.
    """
    actions: set[str] = set()
    ai_patterns: set[str] = set()
    potential: set[str] = set()
    limitations: set[str] = set()
    for doc in docs:
        if isinstance(doc, str):
            try:
                doc = strict_json_loads(doc)
            except (ValueError, RecursionError):
                limitations.add("malformed-policy")
                continue
        if not isinstance(doc, dict):
            limitations.add("malformed-policy")
            continue
        stmts = doc.get("Statement")
        if isinstance(stmts, dict):
            stmts = [stmts]
        if not isinstance(stmts, list) or not stmts:
            limitations.add("missing-policy-statements")
            continue
        for st in stmts:
            if (
                not isinstance(st, dict)
                or not isinstance(st.get("Effect"), str)
                or st["Effect"] not in {"Allow", "Deny"}
            ):
                limitations.add("malformed-policy-statement")
                continue
            if st["Effect"] == "Deny":
                limitations.add("explicit-deny-not-evaluated")
                continue
            if "Condition" in st:
                limitations.add("conditions-not-evaluated")
            if "NotResource" in st:
                limitations.add("notresource-not-evaluated")
            if "Principal" in st or "NotPrincipal" in st:
                limitations.add("resource-policy-principals-not-evaluated")
            if ("Action" in st) == ("NotAction" in st):
                limitations.add("malformed-action-expression")
                continue
            resources = _policy_strings(st.get("Resource"))
            if resources is None and "NotResource" not in st:
                limitations.add("missing-or-malformed-resource")
            services = _resource_services(resources, limitations)
            if "Action" in st:
                explicit = _policy_strings(st["Action"])
                if explicit is None:
                    limitations.add("malformed-action-expression")
                else:
                    actions.update(explicit)
                    # Keep explicit policy evidence when resource scope is
                    # unknown, with the limitation above. Known non-AI resource
                    # scopes must not turn '*' into an AI grant.
                    scope = None if resources is None else services
                    ai_patterns.update(action for action in explicit if _action_has_ai_scope(action, scope))
                continue
            limitations.add("notaction-partially-evaluated")
            excluded = _policy_strings(st["NotAction"])
            if excluded is None or any("[" in action or "]" in action for action in excluded):
                limitations.add("malformed-action-expression")
                continue
            if resources is None or "NotResource" in st:
                continue
            for action in _AI_ACTION_CANDIDATES:
                service = action.split(":", 1)[0]
                if any(fnmatchcase(service, scope) for scope in services) and not any(
                    fnmatchcase(action.lower(), pattern.lower()) for pattern in excluded
                ):
                    potential.add(action)
    return actions, ai_patterns, potential, limitations
