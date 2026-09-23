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

Auth: standard boto3 credential chain (``profile``, ``role_arn`` optional).
Offline export: JSONL of the raw records this connector emits (``_kind`` per record) – produce one
with ``shadowscan run cloud.aws --dump-records aws.jsonl``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.cloud.common import (
    cloud_finding,
    done,
    name_hint,
    scan_blob,
    scan_env,
    scan_iam_actions,
)
from shadowscan.connectors.common import apply_matches, model_matches
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.text import truncate

DEFAULT_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"]
LLM_ACTION_PREFIXES = ("bedrock:", "bedrock-agentcore:", "sagemaker:invoke", "qbusiness:", "lex:", "q:", "kendra:")
CLOUDTRAIL_EVENTS = ["InvokeModel", "InvokeModelWithResponseStream", "Converse", "ConverseStream", "InvokeAgent", "InvokeFlow", "InvokeInlineAgent", "InvokeAgentRuntime", "RetrieveAndGenerate", "InvokeEndpoint", "ChatSync"]


class AwsConnector(BaseConnector):
    name: ClassVar[str] = "cloud.aws"
    surface: ClassVar[Surface] = Surface.CLOUD
    provider: ClassVar[str | None] = "aws"
    requires: ClassVar[list[str]] = ["boto3"]
    description: ClassVar[str] = "Bedrock Agents / AgentCore, Lambda, ECS, SageMaker, Step Functions, Q Business, Lex, IAM grants, secret names and CloudTrail LLM callers."
    config_keys: ClassVar[dict[str, str]] = {
        "profile": "AWS profile (env AWS_PROFILE)",
        "role_arn": "role to assume before scanning",
        "regions": f"regions to scan (default {DEFAULT_REGIONS}; 'all' = every enabled region)",
        "services": "subset of: bedrock, agentcore, lambda, ecs, sagemaker, stepfunctions, qbusiness, lex, iam, secrets, cloudtrail (default all)",
        "cloudtrail_days": "look-back window for LLM invocation events (default 7, 0 disables)",
        "max_lambda": "cap on Lambda functions per region (default 2000)",
        "input": "offline: JSONL of dumped records",
    }
    offline_formats: ClassVar[str] = "JSONL dump of records"

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.regions = ctx.get("regions") or DEFAULT_REGIONS
        self.services = set(ctx.get("services") or ["bedrock", "agentcore", "lambda", "ecs", "sagemaker", "stepfunctions", "qbusiness", "lex", "iam", "secrets", "cloudtrail"])
        self.cloudtrail_days = int(ctx.get("cloudtrail_days", 7))
        self.max_lambda = int(ctx.get("max_lambda", 2000))
        self.account: str | None = ctx.get("account_id")
        self._session: Any = None

    # ------------------------------------------------------------- session
    def _session_(self) -> Any:
        if self._session is not None:
            return self._session
        import boto3

        kwargs: dict[str, Any] = {}
        profile = self.ctx.get("profile", env="AWS_PROFILE")
        if profile:
            kwargs["profile_name"] = profile
        session = boto3.Session(**kwargs)
        role = self.ctx.get("role_arn")
        if role:
            sts = session.client("sts")
            creds = sts.assume_role(RoleArn=role, RoleSessionName="shadowscan")["Credentials"]
            session = boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"])
        try:
            self.account = self.account or session.client("sts").get_caller_identity()["Account"]
        except Exception as exc:  # noqa: BLE001
            raise ConnectorError(f"cloud.aws: cannot authenticate: {exc}") from exc
        self._session = session
        return session

    def _client(self, service: str, region: str | None = None) -> Any:
        return self._session_().client(service, region_name=region)

    def _regions(self) -> list[str]:
        if self.regions == "all" or self.regions == ["all"]:
            ec2 = self._client("ec2", "us-east-1")
            return [r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"]]
        return list(self.regions)

    @staticmethod
    def _paginate(client: Any, op: str, key: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
        try:
            paginator = client.get_paginator(op)
            for page in paginator.paginate(**kwargs):
                yield from page.get(key, []) or []
        except Exception as exc:  # noqa: BLE001 - not every op has a paginator
            # Never restart a failed paginator as a one-page request: that can
            # turn a denied/truncated inventory into apparent success.
            if type(exc).__name__ != "OperationNotPageableError":
                raise
            resp = getattr(client, op)(**kwargs)
            yield from resp.get(key, []) or []
            token = resp.get("nextToken") or resp.get("NextToken")
            while token:
                kw = dict(kwargs)
                kw["nextToken" if "nextToken" in resp else "NextToken"] = token
                resp = getattr(client, op)(**kw)
                yield from resp.get(key, []) or []
                token = resp.get("nextToken") or resp.get("NextToken")

    def _safe(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            if "AccessDenied" in msg or "UnauthorizedOperation" in msg or "not authorized" in msg:
                self.ctx.warn(f"cloud.aws: access denied: {truncate(msg, 160)}", incomplete=True)
            elif "Could not connect to the endpoint" in msg or "UnknownServiceError" in msg or "EndpointConnectionError" in msg:
                self.ctx.warn(f"cloud.aws: service coverage unavailable: {truncate(msg, 160)}", incomplete=True)
            else:
                self.ctx.warn(f"cloud.aws: {truncate(msg, 200)}", incomplete=True)
            return None

    # -------------------------------------------------------------- collect
    def collect(self) -> Iterable[dict[str, Any]]:
        regions = self._regions()
        acct = self.account
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
        for summary in self._safe(lambda: list(self._paginate(ba, "list_agents", "agentSummaries"))) or []:
            detail = self._safe(ba.get_agent, agentId=summary["agentId"])
            agent = (detail or {}).get("agent", summary)
            agent["_kind"] = "bedrock-agent"
            agent["_region"] = region
            agent["_action_groups"] = self._safe(lambda: list(self._paginate(ba, "list_agent_action_groups", "actionGroupSummaries", agentId=summary["agentId"], agentVersion="DRAFT"))) or []
            agent["_knowledge_bases"] = self._safe(lambda: list(self._paginate(ba, "list_agent_knowledge_bases", "agentKnowledgeBaseSummaries", agentId=summary["agentId"], agentVersion="DRAFT"))) or []
            agent["_aliases"] = self._safe(lambda: list(self._paginate(ba, "list_agent_aliases", "agentAliasSummaries", agentId=summary["agentId"]))) or []
            agent["_collaborators"] = self._safe(lambda: list(self._paginate(ba, "list_agent_collaborators", "agentCollaboratorSummaries", agentId=summary["agentId"], agentVersion="DRAFT"))) or []
            yield agent
        for kb in self._safe(lambda: list(self._paginate(ba, "list_knowledge_bases", "knowledgeBaseSummaries"))) or []:
            kb["_kind"] = "bedrock-knowledge-base"
            kb["_region"] = region
            yield kb
        for flow in self._safe(lambda: list(self._paginate(ba, "list_flows", "flowSummaries"))) or []:
            flow["_kind"] = "bedrock-flow"
            flow["_region"] = region
            yield flow
        b = self._client("bedrock", region)
        cfg = self._safe(b.get_model_invocation_logging_configuration)
        if cfg is not None:
            yield {"_kind": "bedrock-logging", "_region": region, "loggingConfig": cfg.get("loggingConfig")}
        for g in self._safe(lambda: list(self._paginate(b, "list_guardrails", "guardrails"))) or []:
            g["_kind"] = "bedrock-guardrail"
            g["_region"] = region
            yield g
        for m in self._safe(lambda: list(self._paginate(b, "list_custom_models", "modelSummaries"))) or []:
            m["_kind"] = "bedrock-custom-model"
            m["_region"] = region
            yield m

    def _collect_agentcore(self, region: str) -> Iterator[dict[str, Any]]:
        try:
            ac = self._client("bedrock-agentcore-control", region)
        except Exception:  # noqa: BLE001 - old boto3
            self.ctx.warn("cloud.aws: AgentCore unavailable in installed SDK; collection incomplete", incomplete=True)
            return
        for rt in self._safe(lambda: list(self._paginate(ac, "list_agent_runtimes", "agentRuntimes"))) or []:
            detail = self._safe(ac.get_agent_runtime, agentRuntimeId=rt.get("agentRuntimeId")) or {}
            rec = {**rt, **{k: v for k, v in detail.items() if k != "ResponseMetadata"}}
            rec["_kind"] = "agentcore-runtime"
            rec["_region"] = region
            yield rec
        for gw in self._safe(lambda: list(self._paginate(ac, "list_gateways", "items"))) or []:
            targets = self._safe(lambda: list(self._paginate(ac, "list_gateway_targets", "items", gatewayIdentifier=gw.get("gatewayId")))) or []
            gw["_targets"] = targets
            gw["_kind"] = "agentcore-gateway"
            gw["_region"] = region
            yield gw
        for mem in self._safe(lambda: list(self._paginate(ac, "list_memories", "memories"))) or []:
            mem["_kind"] = "agentcore-memory"
            mem["_region"] = region
            yield mem
        for kind, op, key in (("agentcore-browser", "list_browsers", "browserSummaries"), ("agentcore-code-interpreter", "list_code_interpreters", "codeInterpreterSummaries"), ("agentcore-workload-identity", "list_workload_identities", "workloadIdentities")):
            for item in self._safe(lambda: list(self._paginate(ac, op, key))) or []:
                item["_kind"] = kind
                item["_region"] = region
                yield item

    def _collect_lambda(self, region: str) -> Iterator[dict[str, Any]]:
        lam = self._client("lambda", region)
        n = 0
        for fn in self._safe(lambda: list(self._paginate(lam, "list_functions", "Functions"))) or []:
            n += 1
            if n > self.max_lambda:
                self.ctx.warn(f"cloud.aws: max_lambda reached in {region}", incomplete=True)
                break
            rec = {
                "_kind": "lambda",
                "_region": region,
                "FunctionName": fn.get("FunctionName"),
                "FunctionArn": fn.get("FunctionArn"),
                "Runtime": fn.get("Runtime"),
                "Role": fn.get("Role"),
                "Handler": fn.get("Handler"),
                "Environment": (fn.get("Environment") or {}).get("Variables") or {},
                "Layers": [layer.get("Arn") for layer in fn.get("Layers") or []],
                "LastModified": fn.get("LastModified"),
                "PackageType": fn.get("PackageType"),
                "Description": fn.get("Description"),
                "ImageUri": None,
            }
            if fn.get("PackageType") == "Image":
                code = self._safe(lam.get_function, FunctionName=fn["FunctionName"]) or {}
                rec["ImageUri"] = ((code.get("Code") or {}).get("ImageUri")) or ((code.get("Code") or {}).get("ResolvedImageUri"))
            tags = self._safe(lam.list_tags, Resource=fn["FunctionArn"]) or {}
            rec["Tags"] = tags.get("Tags") or {}
            yield rec

    def _collect_ecs(self, region: str) -> Iterator[dict[str, Any]]:
        ecs = self._client("ecs", region)
        families = self._safe(lambda: list(self._paginate(ecs, "list_task_definition_families", "families", status="ACTIVE"))) or []
        if len(families) > 1000:
            self.ctx.warn(f"cloud.aws: ECS family limit reached in {region}", incomplete=True)
        for fam in families[:1000]:
            td = self._safe(ecs.describe_task_definition, taskDefinition=fam)
            if not td:
                continue
            d = td.get("taskDefinition") or {}
            yield {
                "_kind": "ecs-task-definition",
                "_region": region,
                "family": fam,
                "taskDefinitionArn": d.get("taskDefinitionArn"),
                "taskRoleArn": d.get("taskRoleArn"),
                "containers": [{"name": c.get("name"), "image": c.get("image"), "environment": {e["name"]: e.get("value") for e in c.get("environment") or []}, "secrets": [s.get("name") for s in c.get("secrets") or []]} for c in d.get("containerDefinitions") or []],
            }

    def _collect_sagemaker(self, region: str) -> Iterator[dict[str, Any]]:
        sm = self._client("sagemaker", region)
        for ep in self._safe(lambda: list(self._paginate(sm, "list_endpoints", "Endpoints"))) or []:
            desc = self._safe(sm.describe_endpoint, EndpointName=ep["EndpointName"]) or {}
            cfg = self._safe(sm.describe_endpoint_config, EndpointConfigName=desc.get("EndpointConfigName", "")) or {}
            models = []
            for v in cfg.get("ProductionVariants") or []:
                m = self._safe(sm.describe_model, ModelName=v.get("ModelName", "")) or {}
                containers = m.get("Containers") or ([m["PrimaryContainer"]] if m.get("PrimaryContainer") else [])
                models.append({"name": v.get("ModelName"), "instance": v.get("InstanceType"), "images": [c.get("Image") for c in containers], "env": {k: v2 for c in containers for k, v2 in (c.get("Environment") or {}).items()}, "model_data": [c.get("ModelDataUrl") for c in containers]})
            yield {"_kind": "sagemaker-endpoint", "_region": region, "EndpointName": ep["EndpointName"], "EndpointArn": ep.get("EndpointArn"), "EndpointStatus": ep.get("EndpointStatus"), "CreationTime": str(ep.get("CreationTime")), "LastModifiedTime": str(ep.get("LastModifiedTime")), "models": models}

    def _collect_stepfunctions(self, region: str) -> Iterator[dict[str, Any]]:
        sfn = self._client("stepfunctions", region)
        for sm in self._safe(lambda: list(self._paginate(sfn, "list_state_machines", "stateMachines"))) or []:
            d = self._safe(sfn.describe_state_machine, stateMachineArn=sm["stateMachineArn"]) or {}
            definition = d.get("definition") or ""
            if "bedrock" in definition.lower() or "sagemaker" in definition.lower() or "lambda" in definition.lower():
                yield {"_kind": "state-machine", "_region": region, "name": sm.get("name"), "stateMachineArn": sm["stateMachineArn"], "roleArn": d.get("roleArn"), "definition": definition[:200_000], "creationDate": str(sm.get("creationDate"))}

    def _collect_q(self, region: str) -> Iterator[dict[str, Any]]:
        q = self._client("qbusiness", region)
        for app in self._safe(lambda: list(self._paginate(q, "list_applications", "applications"))) or []:
            app["_kind"] = "qbusiness-application"
            app["_region"] = region
            yield app

    def _collect_lex(self, region: str) -> Iterator[dict[str, Any]]:
        lex = self._client("lexv2-models", region)
        for bot in self._safe(lambda: list(self._paginate(lex, "list_bots", "botSummaries"))) or []:
            bot["_kind"] = "lex-bot"
            bot["_region"] = region
            yield bot

    def _collect_secret_names(self, region: str) -> Iterator[dict[str, Any]]:
        sm = self._client("secretsmanager", region)
        for s in self._safe(lambda: list(self._paginate(sm, "list_secrets", "SecretList"))) or []:
            yield {"_kind": "secret-name", "_region": region, "Name": s.get("Name"), "ARN": s.get("ARN"), "LastAccessedDate": str(s.get("LastAccessedDate")), "Description": s.get("Description"), "Tags": {t["Key"]: t.get("Value") for t in s.get("Tags") or []}}
        ssm = self._client("ssm", region)
        for p in self._safe(lambda: list(self._paginate(ssm, "describe_parameters", "Parameters"))) or []:
            yield {"_kind": "ssm-parameter", "_region": region, "Name": p.get("Name"), "Type": p.get("Type"), "LastModifiedDate": str(p.get("LastModifiedDate"))}

    def _collect_iam(self) -> Iterator[dict[str, Any]]:
        iam = self._client("iam")
        details = self._safe(lambda: list(self._paginate_details(iam)))
        if not details:
            return
        policies: dict[str, dict[str, Any]] = {}
        for item in details:
            if item.get("_type") == "Policies":
                for ver in item.get("PolicyVersionList") or []:
                    if ver.get("IsDefaultVersion"):
                        policies[item["Arn"]] = ver.get("Document") or {}
        for item in details:
            if item.get("_type") in {"RoleDetailList", "UserDetailList", "GroupDetailList"}:
                docs = [p.get("PolicyDocument") for p in item.get("RolePolicyList") or item.get("UserPolicyList") or item.get("GroupPolicyList") or []]
                unresolved = [p.get("PolicyArn") for p in item.get("AttachedManagedPolicies") or [] if p.get("PolicyArn") not in policies]
                if unresolved:
                    self.ctx.warn(f"cloud.aws: unresolved attached policies for {item.get('Arn')}: {', '.join(str(p) for p in unresolved)}", incomplete=True)
                docs += [policies.get(p.get("PolicyArn"), {}) for p in item.get("AttachedManagedPolicies") or []]
                actions = _actions_from_docs(docs)
                if any(a.lower().startswith(LLM_ACTION_PREFIXES) or a == "*" for a in actions):
                    yield {
                        "_kind": "iam-principal",
                        "type": item["_type"].replace("DetailList", ""),
                        "name": item.get("RoleName") or item.get("UserName") or item.get("GroupName"),
                        "arn": item.get("Arn"),
                        "created": str(item.get("CreateDate")),
                        "last_used": str((item.get("RoleLastUsed") or {}).get("LastUsedDate")) if item.get("RoleLastUsed") else None,
                        "assume_role_policy": item.get("AssumeRolePolicyDocument"),
                        "actions": sorted(actions),
                        "attached_policies": [p.get("PolicyName") for p in item.get("AttachedManagedPolicies") or []],
                        "tags": {t["Key"]: t.get("Value") for t in item.get("Tags") or []},
                    }

    def _paginate_details(self, iam: Any) -> Iterator[dict[str, Any]]:
        paginator = iam.get_paginator("get_account_authorization_details")
        for page in paginator.paginate(Filter=["Role", "User", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]):
            for key in ("RoleDetailList", "UserDetailList", "GroupDetailList", "Policies"):
                for item in page.get(key, []) or []:
                    item["_type"] = key
                    yield item

    def _collect_cloudtrail(self, region: str) -> Iterator[dict[str, Any]]:
        self.ctx.warn(
            f"cloud.aws: CloudTrail LookupEvents in {region} covers management events only; "
            "model/agent invocation data events require a CloudTrail Lake or trail export. "
            "No returned callers does not establish absence of runtime activity.", incomplete=True,
        )
        ct = self._client("cloudtrail", region)
        start = datetime.now(UTC) - timedelta(days=min(self.cloudtrail_days, 90))
        for event_name in CLOUDTRAIL_EVENTS:
            events = self._safe(lambda: list(self._paginate(ct, "lookup_events", "Events", LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}], StartTime=start)))
            for ev in events or []:
                try:
                    detail = json.loads(ev.get("CloudTrailEvent") or "{}")
                except json.JSONDecodeError:
                    detail = {}
                ident = detail.get("userIdentity") or {}
                yield {
                    "_kind": "cloudtrail-event",
                    "_region": region,
                    "eventName": ev.get("EventName"),
                    "eventTime": str(ev.get("EventTime")),
                    "eventSource": ev.get("EventSource"),
                    "principal": ident.get("arn") or ident.get("principalId"),
                    "identityType": ident.get("type"),
                    "userAgent": detail.get("userAgent"),
                    "sourceIp": detail.get("sourceIPAddress"),
                    "modelId": (detail.get("requestParameters") or {}).get("modelId") or ((detail.get("requestParameters") or {}).get("agentId")),
                    "errorCode": detail.get("errorCode"),
                }

    # -------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        callers: dict[str, dict[str, Any]] = {}
        handlers = {name[3:].replace("_", "-"): getattr(self, name) for name in dir(type(self)) if name.startswith("_h_")}
        for rec in records:
            self.ctx.examined()
            kind = rec.get("_kind") if isinstance(rec, dict) else None
            if not isinstance(kind, str) or kind not in handlers.keys() | {"account", "cloudtrail-event"}:
                self.ctx.warn("cloud.aws: record has missing, invalid, or unsupported _kind")
                continue
            try:
                if kind == "account":
                    if not isinstance(rec.get("account"), str) or not rec["account"]:
                        raise ValueError("account")
                    self.account = self.account or rec["account"]
                elif kind == "cloudtrail-event":
                    for field in ("principal", "userAgent", "modelId", "eventName", "sourceIp", "eventTime", "_region"):
                        if rec.get(field) is not None and not isinstance(rec[field], str):
                            raise ValueError("event field")
                    self._acc_caller(callers, rec)
                else:
                    f = handlers[kind](rec)
                    if f:
                        yield f
            except (ValueError, TypeError, KeyError, AttributeError):
                self.ctx.warn("cloud.aws: record has invalid fields for its _kind")
        for key, agg in callers.items():
            try:
                yield self._caller_finding(key, agg)
            except (ValueError, TypeError, KeyError, AttributeError):
                self.ctx.warn("cloud.aws: invalid aggregated caller fields")

    def _arn_account(self, arn: str | None) -> str | None:
        try:
            return arn.split(":")[4] if arn else self.account
        except (IndexError, AttributeError):
            return self.account

    def _h_bedrock_agent(self, rec: dict[str, Any]) -> Finding:
        arn = rec.get("agentArn") or rec.get("agentId")
        f = cloud_finding(self.name, "aws", kind=Kind.AGENT, title=f"Bedrock Agent: {rec.get('agentName')}", resource=arn, resource_type="bedrock-agent", account=self._arn_account(arn), region=rec.get("_region"), first_seen=str(rec.get("createdAt")) if rec.get("createdAt") else None, last_seen=str(rec.get("updatedAt")) if rec.get("updatedAt") else None)
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_model_provider("provider.aws-bedrock")
        f.add_capability("tool-use")
        model = rec.get("foundationModel")
        if model is not None and not isinstance(model, str):
            self.ctx.warn("cloud.aws: Bedrock agent has an invalid foundation model identifier")
        f.models = [model] if isinstance(model, str) and model else []
        apply_matches(f, model_matches(self.index, *f.models), weight_scale=0.5)
        ags = rec.get("_action_groups") or []
        kbs = rec.get("_knowledge_bases") or []
        f.add_evidence(Evidence(signal="aws:bedrock-agent", description=f"Agent '{rec.get('agentName')}' ({rec.get('agentStatus')}) on {rec.get('foundationModel')} with {len(ags)} action group(s), {len(kbs)} knowledge base(s), {len(rec.get('_aliases') or [])} alias(es); role {rec.get('agentResourceRoleArn')}", location=arn, weight=0.97, signature="cloud.aws-bedrock-agents"))
        for ag in ags:
            ex = ag.get("actionGroupExecutor") or {}
            if ex.get("lambda"):
                f.add_capability("code-exec")
                f.add_evidence(Evidence(signal="aws:action-group", description=f"Action group '{ag.get('actionGroupName')}' executes Lambda {ex.get('lambda')}", weight=0.4))
            if ag.get("parentActionGroupSignature") == "AMAZON.CodeInterpreter":
                f.add_capability("code-exec")
                f.add_evidence(Evidence(signal="aws:code-interpreter", description="Built-in code interpreter enabled", weight=0.4))
            if ag.get("parentActionGroupSignature") == "AMAZON.UserInput":
                f.add_tag("asks-user")
        if kbs:
            f.add_capability("rag")
        if rec.get("_collaborators"):
            f.add_capability("multi-agent")
        if not rec.get("guardrailConfiguration"):
            f.add_tag("no-guardrail")
        if rec.get("memoryConfiguration"):
            f.add_capability("memory")
        f.owner = (rec.get("tags") or {}).get("owner") or (rec.get("tags") or {}).get("Owner")
        name_hint(self.index, f, rec.get("agentName"), rec.get("description"))
        f.metadata.update({"agent_id": rec.get("agentId"), "status": rec.get("agentStatus"), "foundation_model": rec.get("foundationModel"), "role": rec.get("agentResourceRoleArn"), "instruction": truncate(rec.get("instruction"), 300), "action_groups": [{"name": a.get("actionGroupName"), "lambda": (a.get("actionGroupExecutor") or {}).get("lambda"), "state": a.get("actionGroupState")} for a in ags], "knowledge_bases": [k.get("knowledgeBaseId") for k in kbs], "aliases": [a.get("agentAliasName") for a in rec.get("_aliases") or []], "guardrail": rec.get("guardrailConfiguration"), "collaboration": rec.get("agentCollaboration")})
        return done(f, self.index, Kind.AGENT)

    def _h_bedrock_knowledge_base(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "aws", kind=Kind.CLOUD_RESOURCE, title=f"Bedrock Knowledge Base: {rec.get('name')}", resource=rec.get("knowledgeBaseId") or rec.get("name"), resource_type="bedrock-knowledge-base", account=self.account, region=rec.get("_region"), last_seen=str(rec.get("updatedAt")) if rec.get("updatedAt") else None)
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_capability("rag")
        f.add_evidence(Evidence(signal="aws:knowledge-base", description=f"Knowledge base '{rec.get('name')}' ({rec.get('status')}): {truncate(rec.get('description'), 120)}", weight=0.6, signature="cloud.aws-bedrock-agents"))
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_bedrock_flow(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "aws", kind=Kind.WORKFLOW, title=f"Bedrock Flow: {rec.get('name')}", resource=rec.get("arn") or rec.get("id"), resource_type="bedrock-flow", account=self.account, region=rec.get("_region"), last_seen=str(rec.get("updatedAt")) if rec.get("updatedAt") else None)
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_model_provider("provider.aws-bedrock")
        f.add_evidence(Evidence(signal="aws:bedrock-flow", description=f"Flow '{rec.get('name')}' ({rec.get('status')}) v{rec.get('version')}", weight=0.9, signature="cloud.aws-bedrock-agents"))
        return done(f, self.index, Kind.WORKFLOW)

    def _h_bedrock_logging(self, rec: dict[str, Any]) -> Finding | None:
        cfg = rec.get("loggingConfig")
        f = cloud_finding(self.name, "aws", kind=Kind.CLOUD_RESOURCE, title=f"Bedrock model invocation logging {'enabled' if cfg else 'DISABLED'} in {rec.get('_region')}", resource=f"arn:aws:bedrock:{rec.get('_region')}:{self.account}:logging", resource_type="bedrock-logging", account=self.account, region=rec.get("_region"))
        f.add_model_provider("provider.aws-bedrock")
        f.add_evidence(Evidence(signal="aws:bedrock-logging", description="Model invocation logging configuration: " + (json.dumps({k: bool(v) for k, v in (cfg or {}).items() if k.endswith("Config")}) if cfg else "not configured — LLM usage in this region is not auditable"), weight=0.2))
        if not cfg:
            f.add_tag("no-invocation-logging")
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_bedrock_guardrail(self, rec: dict[str, Any]) -> Finding | None:
        return None  # informational; agents reference guardrails directly

    def _h_bedrock_custom_model(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "aws", kind=Kind.CLOUD_RESOURCE, title=f"Bedrock custom model: {rec.get('modelName')}", resource=rec.get("modelArn") or rec.get("modelName"), resource_type="bedrock-custom-model", account=self.account, region=rec.get("_region"), first_seen=str(rec.get("creationTime")) if rec.get("creationTime") else None)
        f.add_model_provider("provider.aws-bedrock")
        f.add_evidence(Evidence(signal="aws:custom-model", description=f"Custom model '{rec.get('modelName')}' based on {rec.get('baseModelName')}", weight=0.5))
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_agentcore_runtime(self, rec: dict[str, Any]) -> Finding:
        arn = rec.get("agentRuntimeArn") or rec.get("agentRuntimeId")
        f = cloud_finding(self.name, "aws", kind=Kind.AGENT, title=f"Bedrock AgentCore runtime: {rec.get('agentRuntimeName')}", resource=arn, resource_type="agentcore-runtime", account=self._arn_account(arn), region=rec.get("_region"), first_seen=str(rec.get("createdAt")) if rec.get("createdAt") else None, last_seen=str(rec.get("lastUpdatedAt")) if rec.get("lastUpdatedAt") else None)
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_capability("tool-use")
        artifact = rec.get("agentRuntimeArtifact") or {}
        image = ((artifact.get("containerConfiguration") or {}).get("containerUri"))
        f.add_evidence(Evidence(signal="aws:agentcore-runtime", description=f"AgentCore runtime '{rec.get('agentRuntimeName')}' ({rec.get('status')}) role {rec.get('roleArn')} image {image or 'n/a'}; network {((rec.get('networkConfiguration') or {}).get('networkMode'))}; protocol {((rec.get('protocolConfiguration') or {}).get('serverProtocol'))}", location=arn, weight=0.97, signature="cloud.aws-bedrock-agents"))
        if image:
            apply_matches(f, self.index.match_image(image), weight_scale=0.8)
        scan_env(self.index, f, rec.get("environmentVariables"), location=arn)
        auth = rec.get("authorizerConfiguration")
        if not auth:
            f.add_tag("iam-auth-only")
        f.metadata.update({"status": rec.get("status"), "role": rec.get("roleArn"), "image": image, "protocol": (rec.get("protocolConfiguration") or {}).get("serverProtocol"), "network": (rec.get("networkConfiguration") or {}).get("networkMode"), "authorizer": bool(auth), "description": truncate(rec.get("description"))})
        return done(f, self.index, Kind.AGENT)

    def _h_agentcore_gateway(self, rec: dict[str, Any]) -> Finding:
        arn = rec.get("gatewayArn") or rec.get("gatewayId")
        targets = rec.get("_targets") or []
        f = cloud_finding(self.name, "aws", kind=Kind.MCP_SERVER, title=f"AgentCore Gateway (MCP): {rec.get('name')}", resource=arn, resource_type="agentcore-gateway", account=self._arn_account(arn), region=rec.get("_region"), first_seen=str(rec.get("createdAt")) if rec.get("createdAt") else None)
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_framework("protocol.mcp")
        f.add_capability("tool-use")
        f.add_capability("saas-actions")
        f.add_evidence(Evidence(signal="aws:agentcore-gateway", description=f"Gateway '{rec.get('name')}' ({rec.get('status')}) protocol {rec.get('protocolType')} authorizer {rec.get('authorizerType')} with {len(targets)} target(s): {', '.join(str(t.get('name')) for t in targets[:8])}", location=arn, weight=0.95, signature="cloud.aws-bedrock-agents"))
        if any((t.get("targetConfiguration") or {}).get("mcp", {}).get("lambda") for t in targets):
            f.add_capability("code-exec")
        f.metadata.update({"protocol": rec.get("protocolType"), "authorizer": rec.get("authorizerType"), "targets": [{"name": t.get("name"), "status": t.get("status")} for t in targets][:30], "url": rec.get("gatewayUrl")})
        return done(f, self.index, Kind.MCP_SERVER)

    def _h_agentcore_memory(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "aws", kind=Kind.CLOUD_RESOURCE, title=f"AgentCore Memory: {rec.get('name') or rec.get('id')}", resource=rec.get("arn") or rec.get("id"), resource_type="agentcore-memory", account=self.account, region=rec.get("_region"))
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_capability("memory")
        f.add_evidence(Evidence(signal="aws:agentcore-memory", description=f"Memory store '{rec.get('name') or rec.get('id')}' ({rec.get('status')})", weight=0.7, signature="cloud.aws-bedrock-agents"))
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_agentcore_browser(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "aws", kind=Kind.CLOUD_RESOURCE, title=f"AgentCore Browser: {rec.get('name') or rec.get('browserId')}", resource=rec.get("browserArn") or rec.get("browserId"), resource_type="agentcore-browser", account=self.account, region=rec.get("_region"))
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_capability("browsing")
        f.add_evidence(Evidence(signal="aws:agentcore-browser", description=f"Managed browser '{rec.get('name')}' ({rec.get('status')})", weight=0.7, signature="cloud.aws-bedrock-agents"))
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_agentcore_code_interpreter(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "aws", kind=Kind.CLOUD_RESOURCE, title=f"AgentCore Code Interpreter: {rec.get('name') or rec.get('codeInterpreterId')}", resource=rec.get("codeInterpreterArn") or rec.get("codeInterpreterId"), resource_type="agentcore-code-interpreter", account=self.account, region=rec.get("_region"))
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_capability("code-exec")
        f.add_evidence(Evidence(signal="aws:agentcore-code-interpreter", description=f"Code interpreter '{rec.get('name')}' ({rec.get('status')})", weight=0.7, signature="cloud.aws-bedrock-agents"))
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_agentcore_workload_identity(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "aws", kind=Kind.SERVICE_IDENTITY, title=f"AgentCore workload identity: {rec.get('name')}", resource=rec.get("workloadIdentityArn") or rec.get("name"), resource_type="agentcore-workload-identity", account=self.account, region=rec.get("_region"), surface=Surface.IDENTITY)
        f.add_framework("cloud.aws-bedrock-agents")
        f.add_capability("delegated-identity")
        f.add_evidence(Evidence(signal="aws:agentcore-identity", description=f"Agent workload identity '{rec.get('name')}' (OAuth return URLs: {', '.join(rec.get('allowedResourceOauth2ReturnUrls') or [])[:200] or 'none'})", weight=0.8, signature="cloud.aws-bedrock-agents"))
        return done(f, self.index, Kind.SERVICE_IDENTITY)

    def _h_lambda(self, rec: dict[str, Any]) -> Finding | None:
        arn = rec.get("FunctionArn")
        f = cloud_finding(self.name, "aws", kind=Kind.CLOUD_RESOURCE, title=f"Lambda function: {rec.get('FunctionName')}", resource=arn or rec.get("FunctionName"), resource_type="lambda-function", account=self._arn_account(arn), region=rec.get("_region"), last_seen=rec.get("LastModified"))
        scan_env(self.index, f, rec.get("Environment"), location=arn)
        for layer in rec.get("Layers") or []:
            for m in self.index.match_domains_in_text(layer) + self.index.match_code(layer.rsplit(":", 2)[0].rsplit(":", 1)[-1].replace("-", " ") if ":" in layer else layer):
                apply_matches(f, [m], location=arn, weight_scale=0.5)
            low = layer.lower()
            for key, sig in (("langchain", "framework.langchain"), ("llamaindex", "framework.llamaindex"), ("llama-index", "framework.llamaindex"), ("openai", "provider.openai"), ("anthropic", "provider.anthropic"), ("bedrock", "provider.aws-bedrock"), ("crewai", "framework.crewai"), ("strands", "framework.aws-strands"), ("agentcore", "cloud.aws-bedrock-agents"), ("litellm", "platform.litellm"), ("mcp", "protocol.mcp")):
                if key in low:
                    sig_obj = self.index.get(sig)
                    if sig_obj:
                        (f.add_model_provider if sig_obj.category == "provider" else f.add_framework)(sig)
                        f.add_evidence(Evidence(signal="aws:lambda-layer", description=f"Layer {layer} suggests {sig_obj.name}", location=arn, weight=0.5, signature=sig))
        if rec.get("ImageUri"):
            apply_matches(f, self.index.match_image(rec["ImageUri"]), location=arn)
        name_hint(self.index, f, rec.get("FunctionName"), rec.get("Description"))
        scan_blob(self.index, f, rec.get("Tags") or {}, location=arn, weight_scale=0.4)
        if not f.frameworks and not f.model_providers:
            return None
        f.add_evidence(Evidence(signal="aws:lambda", description=f"Function '{rec.get('FunctionName')}' ({rec.get('Runtime') or rec.get('PackageType')}), role {rec.get('Role')}", location=arn, weight=0.2))
        f.owner = (rec.get("Tags") or {}).get("owner") or (rec.get("Tags") or {}).get("Owner") or (rec.get("Tags") or {}).get("team")
        f.metadata.update({"runtime": rec.get("Runtime"), "role": rec.get("Role"), "handler": rec.get("Handler"), "layers": rec.get("Layers"), "image": rec.get("ImageUri"), "env_names": sorted((rec.get("Environment") or {}).keys())[:40], "tags": rec.get("Tags")})
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_ecs_task_definition(self, rec: dict[str, Any]) -> Finding | None:
        arn = rec.get("taskDefinitionArn")
        f = cloud_finding(self.name, "aws", kind=Kind.CLOUD_RESOURCE, title=f"ECS task definition: {rec.get('family')}", resource=arn or rec.get("family"), resource_type="ecs-task-definition", account=self._arn_account(arn), region=rec.get("_region"))
        for c in rec.get("containers") or []:
            if c.get("image"):
                apply_matches(f, self.index.match_image(c["image"]), location=arn)
            scan_env(self.index, f, c.get("environment"), location=arn)
            for s in c.get("secrets") or []:
                apply_matches(f, self.index.match_env(str(s)), location=arn, weight_scale=0.6)
        if not f.frameworks and not f.model_providers:
            return None
        f.add_evidence(Evidence(signal="aws:ecs", description=f"Task definition '{rec.get('family')}' containers: {', '.join(str(c.get('image')) for c in rec.get('containers') or [])[:300]}; task role {rec.get('taskRoleArn')}", location=arn, weight=0.2))
        f.metadata.update({"task_role": rec.get("taskRoleArn"), "containers": [{"name": c.get("name"), "image": c.get("image")} for c in rec.get("containers") or []]})
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_sagemaker_endpoint(self, rec: dict[str, Any]) -> Finding | None:
        arn = rec.get("EndpointArn")
        f = cloud_finding(self.name, "aws", kind=Kind.CLOUD_RESOURCE, title=f"SageMaker endpoint: {rec.get('EndpointName')}", resource=arn or rec.get("EndpointName"), resource_type="sagemaker-endpoint", account=self._arn_account(arn), region=rec.get("_region"), first_seen=rec.get("CreationTime"), last_seen=rec.get("LastModifiedTime"))
        llm = False
        for m in rec.get("models") or []:
            for img in m.get("images") or []:
                if img:
                    ms = self.index.match_image(img)
                    apply_matches(f, ms, location=arn)
                    if ms or any(k in img.lower() for k in ("tgi", "djl", "vllm", "lmi", "huggingface", "llm", "triton")):
                        llm = True
            scan_env(self.index, f, m.get("env"), location=arn)
            if any(k in json.dumps(m.get("env") or {}) for k in ("HF_MODEL_ID", "SM_NUM_GPUS", "MAX_INPUT_LENGTH", "OPTION_MODEL_ID", "HF_TASK")):
                llm = True
        if not llm and not f.frameworks and not f.model_providers:
            return None
        f.add_model_provider("provider.huggingface") if llm and not f.model_providers else None
        f.add_evidence(Evidence(signal="aws:sagemaker", description=f"Endpoint '{rec.get('EndpointName')}' ({rec.get('EndpointStatus')}) serving {', '.join(str(m.get('name')) for m in rec.get('models') or [])} on {', '.join(str(m.get('instance')) for m in rec.get('models') or [])}", location=arn, weight=0.6))
        f.metadata.update({"status": rec.get("EndpointStatus"), "models": rec.get("models")})
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_state_machine(self, rec: dict[str, Any]) -> Finding | None:
        arn = rec.get("stateMachineArn")
        f = cloud_finding(self.name, "aws", kind=Kind.WORKFLOW, title=f"Step Functions workflow with LLM steps: {rec.get('name')}", resource=arn, resource_type="state-machine", account=self._arn_account(arn), region=rec.get("_region"), first_seen=rec.get("creationDate"))
        definition = rec.get("definition") or ""
        if "bedrock" not in definition.lower() and "sagemaker" not in definition.lower():
            return None
        scan_blob(self.index, f, definition, location=arn)
        if "arn:aws:states:::bedrock" in definition or "bedrock:invokeModel" in definition:
            f.add_model_provider("provider.aws-bedrock")
            f.add_evidence(Evidence(signal="aws:sfn-bedrock", description="State machine invokes Bedrock (optimized integration)", location=arn, weight=0.8, signature="provider.aws-bedrock"))
        f.add_capability("autonomous")
        f.metadata.update({"role": rec.get("roleArn")})
        return done(f, self.index, Kind.WORKFLOW)

    def _h_qbusiness_application(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "aws", kind=Kind.AGENT, title=f"Amazon Q Business application: {rec.get('displayName')}", resource=f"arn:aws:qbusiness:{rec.get('_region')}:{self.account}:application/{rec.get('applicationId')}", resource_type="qbusiness-application", account=self.account, region=rec.get("_region"), first_seen=str(rec.get("createdAt")) if rec.get("createdAt") else None, last_seen=str(rec.get("updatedAt")) if rec.get("updatedAt") else None)
        f.add_framework("cloud.aws-other-ai")
        f.add_capability("rag")
        f.add_evidence(Evidence(signal="aws:qbusiness", description=f"Q Business app '{rec.get('displayName')}' ({rec.get('status')}), identity type {rec.get('identityType')}", weight=0.9, signature="cloud.aws-other-ai"))
        return done(f, self.index, Kind.AGENT)

    def _h_lex_bot(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "aws", kind=Kind.AGENT, title=f"Lex bot: {rec.get('botName')}", resource=f"arn:aws:lex:{rec.get('_region')}:{self.account}:bot/{rec.get('botId')}", resource_type="lex-bot", account=self.account, region=rec.get("_region"), last_seen=str(rec.get("lastUpdatedDateTime")) if rec.get("lastUpdatedDateTime") else None)
        f.add_framework("cloud.aws-other-ai")
        f.add_evidence(Evidence(signal="aws:lex", description=f"Lex V2 bot '{rec.get('botName')}' ({rec.get('botStatus')}, type {rec.get('botType')})", weight=0.8, signature="cloud.aws-other-ai"))
        return done(f, self.index, Kind.AGENT)

    def _h_secret_name(self, rec: dict[str, Any]) -> Finding | None:
        return self._name_only_secret(rec, "secretsmanager-secret", rec.get("ARN"))

    def _h_ssm_parameter(self, rec: dict[str, Any]) -> Finding | None:
        return self._name_only_secret(rec, "ssm-parameter", f"arn:aws:ssm:{rec.get('_region')}:{self.account}:parameter{rec.get('Name')}")

    def _name_only_secret(self, rec: dict[str, Any], rtype: str, arn: str | None) -> Finding | None:
        name = str(rec.get("Name") or "")
        norm = "".join(ch if ch.isalnum() else "_" for ch in name).upper().strip("_")
        matches = self.index.match_env(norm)
        text_hits = [m for m in self.index.match_name(name.replace("/", " ").replace("-", " ")) if m.signature.category != "identity-app"]
        if not matches and not any(k in name.lower() for k in ("openai", "anthropic", "claude", "gemini", "llm", "bedrock", "huggingface", "mistral", "cohere", "groq", "langsmith", "langfuse", "pinecone", "tavily")):
            return None
        f = cloud_finding(self.name, "aws", kind=Kind.SECRET, title=f"Stored LLM credential ({rtype}): {name}", resource=arn or name, resource_type=rtype, account=self.account, region=rec.get("_region"), last_seen=rec.get("LastAccessedDate") or rec.get("LastModifiedDate"))
        apply_matches(f, matches + text_hits, location=arn, weight_scale=0.7)
        f.add_evidence(Evidence(signal=f"aws:{rtype}", description=f"{rtype} named '{name}' looks like an LLM provider credential (name only; value not read)", location=arn, weight=0.4))
        f.add_tag("managed-secret")
        f.metadata.update({"name": name, "description": rec.get("Description"), "tags": rec.get("Tags")})
        return done(f, self.index, Kind.SECRET)

    def _h_iam_principal(self, rec: dict[str, Any]) -> Finding | None:
        actions = rec.get("actions") or []
        f = cloud_finding(self.name, "aws", kind=Kind.IAM_GRANT, title=f"IAM {rec.get('type')} with LLM/agent permissions: {rec.get('name')}", resource=rec.get("arn") or rec.get("name"), resource_type=f"iam-{str(rec.get('type', 'principal')).lower()}", account=self._arn_account(rec.get("arn")), first_seen=rec.get("created"), last_seen=rec.get("last_used"), surface=Surface.IDENTITY)
        llm = scan_iam_actions(self.index, f, actions, location=rec.get("arn"))
        wildcard = [a for a in actions if a == "*" or a.endswith(":*")]
        if not llm and not wildcard:
            return None
        trust = json.dumps(rec.get("assume_role_policy") or {})
        principals = []
        for svc in ("lambda.amazonaws.com", "bedrock.amazonaws.com", "bedrock-agentcore.amazonaws.com", "ecs-tasks.amazonaws.com", "sagemaker.amazonaws.com", "states.amazonaws.com", "ec2.amazonaws.com", "eks.amazonaws.com", "apprunner.amazonaws.com"):
            if svc in trust:
                principals.append(svc)
        if "oidc-provider" in trust or "token.actions.githubusercontent.com" in trust:
            principals.append("oidc-federated")
        f.add_evidence(Evidence(signal="aws:iam", description=f"{rec.get('type')} '{rec.get('name')}' allows {', '.join(llm[:8])}{' + wildcards ' + ', '.join(wildcard[:3]) if wildcard else ''}; trusted by {', '.join(principals) or 'users/accounts'}", location=rec.get("arn"), weight=0.45 if llm else 0.25))
        if "bedrock.amazonaws.com" in principals or "bedrock-agentcore.amazonaws.com" in principals:
            f.add_framework("cloud.aws-bedrock-agents")
            f.add_tag("agent-execution-role")
        if wildcard:
            f.add_tag("wildcard-permissions")
        name_hint(self.index, f, rec.get("name"))
        f.owner = (rec.get("tags") or {}).get("owner") or (rec.get("tags") or {}).get("Owner")
        f.metadata.update({"principal_type": rec.get("type"), "llm_actions": llm[:40], "wildcards": wildcard[:10], "attached_policies": rec.get("attached_policies"), "trusted_services": principals, "action_count": len(actions)})
        return done(f, self.index, Kind.IAM_GRANT)

    # ------------------------------------------------------------ cloudtrail
    @staticmethod
    def _acc_caller(callers: dict[str, dict[str, Any]], rec: dict[str, Any]) -> None:
        key = rec.get("principal") or "unknown"
        agg = callers.setdefault(key, {"events": 0, "models": {}, "ops": {}, "agents": {}, "first": None, "last": None, "regions": set(), "identity_type": rec.get("identityType"), "ips": {}, "errors": 0})
        agg["events"] += 1
        ua = rec.get("userAgent")
        if ua:
            agg["agents"][ua] = agg["agents"].get(ua, 0) + 1
        model = rec.get("modelId")
        if model:
            agg["models"][model] = agg["models"].get(model, 0) + 1
        op = rec.get("eventName")
        if op:
            agg["ops"][op] = agg["ops"].get(op, 0) + 1
        ip = rec.get("sourceIp")
        if ip:
            agg["ips"][ip] = agg["ips"].get(ip, 0) + 1
        t = rec.get("eventTime")
        if t:
            agg["first"] = t if not agg["first"] or t < agg["first"] else agg["first"]
            agg["last"] = t if not agg["last"] or t > agg["last"] else agg["last"]
        agg["regions"].add(rec.get("_region"))
        if rec.get("errorCode"):
            agg["errors"] += 1

    def _caller_finding(self, principal: str, agg: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "aws", kind=Kind.GATEWAY_CALLER, title=f"LLM caller (CloudTrail): {principal.rsplit('/', 1)[-1]} — {agg['events']} invocation(s)", resource=f"cloudtrail:{principal}", resource_type=f"caller/{agg.get('identity_type') or 'principal'}", account=self._arn_account(principal if principal.startswith("arn:") else None), first_seen=agg["first"], last_seen=agg["last"], surface=Surface.GATEWAY)
        f.add_model_provider("provider.aws-bedrock")
        for model in list(agg["models"])[:10]:
            apply_matches(f, model_matches(self.index, model), weight_scale=0.4)
        for ua in list(agg["agents"])[:10]:
            apply_matches(f, self.index.match_user_agent(ua))
        f.models = sorted(agg["models"], key=lambda m: -agg["models"][m])[:10]
        weight = 0.5 if agg.get("identity_type") in {"AssumedRole", "AWSService", "WebIdentityUser"} else 0.3
        f.add_evidence(Evidence(signal="aws:cloudtrail", description=f"{agg['events']} LLM API call(s) ({', '.join(f'{k}×{v}' for k, v in list(agg['ops'].items())[:5])}) by {agg.get('identity_type')} {principal}", weight=weight))
        if any(op.startswith("InvokeAgent") or op == "InvokeFlow" for op in agg["ops"]):
            f.add_framework("cloud.aws-bedrock-agents")
            f.add_capability("tool-use")
        if agg.get("identity_type") == "IAMUser":
            f.add_tag("long-lived-credentials")
        name_hint(self.index, f, principal)
        f.metadata.update({"principal": principal, "identity_type": agg.get("identity_type"), "events": agg["events"], "models": agg["models"], "operations": agg["ops"], "user_agents": dict(sorted(agg["agents"].items(), key=lambda kv: -kv[1])[:5]), "source_ips": dict(sorted(agg["ips"].items(), key=lambda kv: -kv[1])[:5]), "regions": sorted(r for r in agg["regions"] if r), "errors": agg["errors"]})
        return done(f, self.index, Kind.GATEWAY_CALLER)


def _actions_from_docs(docs: list[Any]) -> set[str]:
    actions: set[str] = set()
    for doc in docs:
        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
            except json.JSONDecodeError:
                continue
        if not isinstance(doc, dict):
            continue
        stmts = doc.get("Statement") or []
        if isinstance(stmts, dict):
            stmts = [stmts]
        for st in stmts:
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            acts = st.get("Action") or []
            if isinstance(acts, str):
                acts = [acts]
            actions.update(str(a) for a in acts)
    return actions
