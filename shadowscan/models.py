"""Core data model shared by every connector, the engine and the reporters.

Everything ShadowScan discovers is normalised into a :class:`Finding`. A finding
describes *one thing that behaves like, or enables, an AI agent* on one surface,
together with the evidence that led to it, the frameworks / model providers it
uses, a confidence score, a risk assessment and (once reconciled against the
sanctioned inventory) whether it is a *shadow* agent.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass, field, fields
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from shadowscan.utils.redaction import SanitizationLimitError, sanitize

FINDING_IDENTITY_SCHEMA = "shadowscan.finding-identity/v2"
LEGACY_FINDING_IDENTITY_SCHEMA = "shadowscan.finding-identity/v1"


def _validate_number(value: Any, name: str, *, minimum: float | None = None, maximum: float | None = None) -> None:
    """Validate imported numeric fields without reflecting untrusted values."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"finding {name} must be a finite number")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"finding {name} must be a finite number")
    if (minimum is not None and value < minimum) or (maximum is not None and value > maximum):
        raise ValueError(f"finding {name} is outside its allowed range")


class Surface(str, Enum):
    """Where an agent (or agent enabler) was discovered."""

    CODE = "code"
    IDENTITY = "identity"
    GATEWAY = "gateway"
    LOWCODE = "lowcode"
    SAAS = "saas"
    CLOUD = "cloud"


class Kind(str, Enum):
    """What kind of thing the finding describes."""

    AGENT = "agent"  # an actual agent (orchestrator use, cloud agent resource, bot...)
    FRAMEWORK_USAGE = "framework-usage"  # a project using an agent framework / LLM SDK
    MCP_SERVER = "mcp-server"  # Model Context Protocol server or client config
    AGENT_CONFIG = "agent-config"  # coding-agent / declarative agent configuration file
    OAUTH_GRANT = "oauth-grant"  # an OAuth grant / consented application
    SERVICE_IDENTITY = "service-identity"  # service principal, service account, M2M client
    TOKEN = "token"  # analysed JWT / API token
    GATEWAY_CALLER = "gateway-caller"  # principal calling an LLM API observed in logs
    WORKFLOW = "workflow"  # low-code flow / scenario / recipe with AI steps
    BOT_APP = "bot-app"  # SaaS bot / app installation
    CLOUD_RESOURCE = "cloud-resource"  # managed AI resource (endpoint, deployment, function...)
    IAM_GRANT = "iam-grant"  # IAM role / policy enabling LLM or agent access
    SECRET = "secret"  # credential for an LLM provider found in code / config
    INFRA = "infra"  # IaC or container definitions provisioning AI agents


class Likelihood(str, Enum):
    CONFIRMED = "confirmed"  # >= 0.85
    LIKELY = "likely"  # >= 0.6
    POSSIBLE = "possible"  # >= 0.3
    WEAK = "weak"  # < 0.3

    @classmethod
    def from_confidence(cls, confidence: float) -> Likelihood:
        if confidence >= 0.85:
            return cls.CONFIRMED
        if confidence >= 0.6:
            return cls.LIKELY
        if confidence >= 0.3:
            return cls.POSSIBLE
        return cls.WEAK


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_score(cls, score: float) -> RiskLevel:
        if score >= 75:
            return cls.CRITICAL
        if score >= 50:
            return cls.HIGH
        if score >= 25:
            return cls.MEDIUM
        if score > 0:
            return cls.LOW
        return cls.INFO


@dataclass(slots=True)
class Evidence:
    """A single observation supporting a finding."""

    signal: str  # machine readable id, e.g. "dependency:pypi:langchain"
    description: str  # human readable explanation
    location: str | None = None  # file:line, ARN, URL, object id...
    snippet: str | None = None  # short excerpt (secrets must be redacted before storing)
    weight: float = 0.5  # 0..1 contribution to confidence
    signature: str | None = None  # signature id that produced it, if any
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.sanitize()

    def sanitize(self) -> None:
        names = [attr.name for attr in fields(self)]
        # The schema keys are trusted code, while attributes can contain
        # attacker-controlled keys. Keep the former outside the sanitizer.
        # A field that resembles an argv flag must not reinterpret the next
        # dataclass field as its value. Real argv lists inside a field retain
        # their normal pair-aware redaction.
        values = sanitize([(getattr(self, name),) for name in names])
        for name, (value,) in zip(names, values, strict=True):
            setattr(self, name, value)


@dataclass(slots=True)
class RiskFactor:
    id: str
    description: str
    weight: int


@dataclass(slots=True)
class Risk:
    score: int = 0
    level: RiskLevel = RiskLevel.INFO
    factors: list[RiskFactor] = field(default_factory=list)


@dataclass(slots=True)
class Finding:
    surface: Surface
    connector: str
    kind: Kind
    title: str
    resource: str  # canonical, stable identifier of the discovered object
    resource_type: str  # e.g. "repository", "lambda-function", "oauth-app"
    provider: str | None = None  # platform / vendor hosting it (aws, okta, slack, github...)
    account: str | None = None  # tenant / org / account / project id
    region: str | None = None
    owner: str | None = None  # best-effort owner (user, team, email)
    frameworks: list[str] = field(default_factory=list)  # signature ids (framework.langchain...)
    model_providers: list[str] = field(default_factory=list)  # signature ids (provider.openai...)
    models: list[str] = field(default_factory=list)  # concrete model ids seen
    capabilities: list[str] = field(default_factory=list)  # tool-use, code-exec, memory, browsing...
    permissions: list[str] = field(default_factory=list)  # scopes / IAM actions / roles
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float = 0.0
    likelihood: Likelihood = Likelihood.WEAK
    risk: Risk = field(default_factory=Risk)
    shadow: bool | None = None  # None: no inventory supplied; True: unregistered
    registry_match: str | None = None  # agent_id from the sanctioned inventory
    tags: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = ""
    # Stable observation type, independent of inferred kind. Connectors emitting
    # several observations of one resource/type must supply distinct values.
    identity_discriminator: str = ""
    identity_schema: str = FINDING_IDENTITY_SCHEMA

    def __post_init__(self) -> None:
        if not self.identity_discriminator:
            # Suffixes describe mutable platform classifications (for example
            # service-principal/ManagedIdentity and auth0-client/non_interactive).
            self.identity_discriminator = self.resource_type.split("/", 1)[0]
        if not self.id:
            self.id = self.compute_id()
        self.likelihood = Likelihood.from_confidence(self.confidence)
        self.sanitize()

    # ------------------------------------------------------------------ helpers
    def compute_id(self) -> str:
        if self.identity_schema == LEGACY_FINDING_IDENTITY_SCHEMA:
            raw = f"{self.surface.value}|{self.connector}|{self.kind.value}|{self.provider}|{self.account}|{self.resource}"
        else:
            raw = json.dumps([
                self.identity_schema, self.surface.value, self.connector, self.provider,
                self.account, self.region, self.resource, self.identity_discriminator,
            ], separators=(",", ":"), ensure_ascii=True)
        return "ss-" + hashlib.sha256(raw.encode()).hexdigest()[:16]

    def sanitize(self) -> None:
        """Remove credentials from every persisted/reportable field in place."""
        identity_names = (
            "connector", "resource", "resource_type", "provider", "account", "region",
            "identity_discriminator", "identity_schema",
        )
        identity_before = tuple(getattr(self, name) for name in identity_names)
        # A generated digest is an opaque identifier, even if a one-character
        # credential happens to occur among its hexadecimal digits. Imported
        # arbitrary IDs must still pass through the sanitizer.
        generated_id = self.id == self.compute_id()
        trusted_schema = self.identity_schema in {FINDING_IDENTITY_SCHEMA, LEGACY_FINDING_IDENTITY_SCHEMA}
        names = [attr.name for attr in fields(self)
                 if attr.name not in {"surface", "kind", "likelihood", "risk", "evidence"}
                 and not (generated_id and attr.name == "id")
                 and not (trusted_schema and attr.name == "identity_schema")]
        evidence_names = [attr.name for attr in fields(Evidence)]
        values, evidence_values, risk_values = sanitize((
            [(getattr(self, name),) for name in names],
            [[(getattr(ev, name),) for name in evidence_names] for ev in self.evidence],
            [[(factor.id,), (factor.description,)] for factor in self.risk.factors],
        ))
        for name, (value,) in zip(names, values, strict=True):
            setattr(self, name, value)
        changed = {name for name, original in zip(identity_names, identity_before, strict=True)
                   if getattr(self, name) != original}
        # A verified raw-identity digest distinguishes redacted resources and
        # scopes; registry matching already rejects their placeholders. Never
        # allow a changed connector/type/discriminator or an arbitrary ID to
        # yield a misleading or colliding finding.
        if self.id == "[REDACTED]" or changed & {
            "connector", "resource_type", "identity_discriminator", "identity_schema",
        } or (changed and not generated_id):
            raise SanitizationLimitError("finding identity includes a credential; finding omitted")
        for ev, clean in zip(self.evidence, evidence_values, strict=True):
            for name, (value,) in zip(evidence_names, clean, strict=True):
                setattr(ev, name, value)
        for factor, ((identifier,), (description,)) in zip(self.risk.factors, risk_values, strict=True):
            factor.id = identifier
            factor.description = description

    def add_evidence(self, ev: Evidence) -> None:
        ev.sanitize()
        self.evidence.append(ev)

    def add_framework(self, sig_id: str) -> None:
        if sig_id and sig_id not in self.frameworks:
            self.frameworks.append(sig_id)

    def add_model_provider(self, sig_id: str) -> None:
        if sig_id and sig_id not in self.model_providers:
            self.model_providers.append(sig_id)

    def add_capability(self, cap: str) -> None:
        if cap and cap not in self.capabilities:
            self.capabilities.append(cap)

    def add_tag(self, tag: str) -> None:
        if tag and tag not in self.tags:
            self.tags.append(tag)

    def recompute_confidence(self) -> None:
        """Noisy-OR combination of evidence weights.

        Independent weak signals reinforce each other but never exceed 1.0.
        """
        p_none = 1.0
        groups: dict[str, float] = {}
        for number, ev in enumerate(self.evidence):
            w = max(0.0, min(1.0, ev.weight))
            group = ev.attributes.get("confidence_group")
            key = f"group:{group}" if isinstance(group, str) else f"evidence:{number}"
            groups[key] = max(groups.get(key, 0.0), w)
        for w in groups.values():
            p_none *= 1.0 - w
        self.confidence = round(1.0 - p_none, 3)
        self.likelihood = Likelihood.from_confidence(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        self.sanitize()
        d = asdict(self)
        d["surface"] = self.surface.value
        d["kind"] = self.kind.value
        d["likelihood"] = self.likelihood.value
        d["risk"]["level"] = self.risk.level.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        if not isinstance(d, dict):
            raise TypeError("finding must be an object")
        # Reports can carry newer display fields. Only accept known model
        # fields, while requiring the fields that define a usable identity.
        for name in ("surface", "connector", "kind", "title", "resource", "resource_type"):
            if not isinstance(d.get(name), str) or not d[name].strip():
                raise ValueError(f"finding {name} is required")
        d = {name: d[name] for name in (attr.name for attr in fields(cls)) if name in d}
        # Reading an old report preserves its identity rather than silently
        # relabeling old ids as v2. Upgrades require a freshly collected baseline.
        d.setdefault("identity_schema", LEGACY_FINDING_IDENTITY_SCHEMA)
        d["surface"] = Surface(d["surface"])
        d["kind"] = Kind(d["kind"])
        d["likelihood"] = Likelihood(d.get("likelihood", "weak"))
        _validate_number(d.get("confidence", 0.0), "confidence", minimum=0, maximum=1)
        risk = d.get("risk")
        if risk is None:
            risk = {}
        if not isinstance(risk, dict):
            raise ValueError("finding risk must be an object")
        _validate_number(risk.get("score", 0), "risk score", minimum=0, maximum=100)
        factors = risk.get("factors", [])
        if not isinstance(factors, list) or any(not isinstance(factor, dict) for factor in factors):
            raise ValueError("finding risk factors must be objects")
        for factor in factors:
            _validate_number(factor.get("weight"), "risk factor weight")
        d["risk"] = Risk(
            score=risk.get("score", 0),
            level=RiskLevel(risk.get("level", "info")),
            factors=[RiskFactor(**{name: value for name, value in factor.items()
                                   if name in {"id", "description", "weight"}}) for factor in factors],
        )
        evidence = d.get("evidence", [])
        if not isinstance(evidence, list) or any(not isinstance(item, dict) for item in evidence):
            raise ValueError("finding evidence must be objects")
        for item in evidence:
            _validate_number(item.get("weight", 0.5), "evidence weight", minimum=0, maximum=1)
        evidence_fields = {attr.name for attr in fields(Evidence)}
        d["evidence"] = [Evidence(**{name: value for name, value in item.items() if name in evidence_fields})
                         for item in evidence]
        return cls(**d)


@dataclass(slots=True)
class ScanStats:
    connector: str
    started_at: str
    finished_at: str | None = None
    findings: int = 0
    objects_examined: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str | None = None
    cached: bool = False
    incomplete: bool = False


@dataclass(slots=True)
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    stats: list[ScanStats] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: now_iso())
    finished_at: str | None = None
    version: str = ""
    inventory_size: int = 0
    collection_scope: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        for finding in self.findings:
            finding.sanitize()

    @property
    def complete(self) -> bool:
        """Only a scan whose requested connectors all completed is successful."""
        return bool(self.stats) and not any(s.errors or s.skipped or s.incomplete for s in self.stats)

    def summary(self) -> dict[str, Any]:
        by_surface: dict[str, int] = {}
        by_kind: dict[str, int] = {}
        by_level: dict[str, int] = {}
        frameworks: dict[str, int] = {}
        providers: dict[str, int] = {}
        shadow = 0
        for f in self.findings:
            f.sanitize()
            by_surface[f.surface.value] = by_surface.get(f.surface.value, 0) + 1
            by_kind[f.kind.value] = by_kind.get(f.kind.value, 0) + 1
            by_level[f.risk.level.value] = by_level.get(f.risk.level.value, 0) + 1
            for fw in f.frameworks:
                frameworks[fw] = frameworks.get(fw, 0) + 1
            for p in f.model_providers:
                providers[p] = providers.get(p, 0) + 1
            if f.shadow:
                shadow += 1
        return {
            "complete": self.complete,
            "status": "complete" if self.complete else "incomplete",
            "total": len(self.findings),
            "shadow": shadow,
            "by_surface": by_surface,
            "by_kind": by_kind,
            "by_risk_level": by_level,
            "frameworks": dict(sorted(frameworks.items(), key=lambda kv: -kv[1])),
            "model_providers": dict(sorted(providers.items(), key=lambda kv: -kv[1])),
            "errors": sum(len(s.errors) for s in self.stats),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "finding_identity_schema": FINDING_IDENTITY_SCHEMA,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "inventory_size": self.inventory_size,
            "collection_scope": sanitize(self.collection_scope),
            "summary": self.summary(),
            "stats": [sanitize(asdict(s)) for s in self.stats],
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()
