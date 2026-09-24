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

from shadowscan.utils.redaction import sanitize

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

    AGENT = "agent"
    FRAMEWORK_USAGE = "framework-usage"
    MCP_SERVER = "mcp-server"
    AGENT_CONFIG = "agent-config"
    OAUTH_GRANT = "oauth-grant"
    SERVICE_IDENTITY = "service-identity"
    TOKEN = "token"
    GATEWAY_CALLER = "gateway-caller"
    WORKFLOW = "workflow"
    BOT_APP = "bot-app"
    CLOUD_RESOURCE = "cloud-resource"
    IAM_GRANT = "iam-grant"
    SECRET = "secret"
    INFRA = "infra"


class Likelihood(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    WEAK = "weak"

    @classmethod
    def from_confidence(cls, confidence: float) -> Likelihood:
        if confidence >= 0.85:
            return cls.CONFIRMED
        if confidence >= 0.6:
            return cls.LIKELY
        if confidence >= 0.3:
            return cls.POSSIBLE
        return cls.WEAK


class EvidenceTier(str, Enum):
    """How much collected evidence can support. Never equals execution by itself."""

    STATIC_CANDIDATE = "static_candidate"
    CONFIGURED_RESOURCE = "configured_resource"
    RUNTIME_OBSERVED = "runtime_observed"
    CORROBORATED = "corroborated"

    @property
    def rank(self) -> int:
        return {
            EvidenceTier.STATIC_CANDIDATE: 0,
            EvidenceTier.CONFIGURED_RESOURCE: 1,
            EvidenceTier.RUNTIME_OBSERVED: 2,
            EvidenceTier.CORROBORATED: 3,
        }[self]


class ExecutionStatus(str, Enum):
    """Whether this scan established execution. Static hits stay not_established."""

    NOT_ESTABLISHED = "not_established"
    CONFIGURED = "configured"
    OBSERVED = "observed"
    CORROBORATED = "corroborated"
    UNKNOWN = "unknown"


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

    signal: str
    description: str
    location: str | None = None
    snippet: str | None = None
    weight: float = 0.5
    signature: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.sanitize()

    def sanitize(self) -> None:
        values = sanitize({attr.name: getattr(self, attr.name) for attr in fields(self)})
        for name, value in values.items():
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
    resource: str
    resource_type: str
    provider: str | None = None
    account: str | None = None
    region: str | None = None
    owner: str | None = None
    frameworks: list[str] = field(default_factory=list)
    model_providers: list[str] = field(default_factory=list)
    models: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float = 0.0
    likelihood: Likelihood = Likelihood.WEAK
    risk: Risk = field(default_factory=Risk)
    shadow: bool | None = None
    registry_match: str | None = None
    tags: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = ""
    identity_discriminator: str = ""
    identity_schema: str = FINDING_IDENTITY_SCHEMA
    evidence_tier: EvidenceTier = EvidenceTier.STATIC_CANDIDATE
    execution_status: ExecutionStatus = ExecutionStatus.NOT_ESTABLISHED
    gate_eligible: bool = False

    def __post_init__(self) -> None:
        if not self.identity_discriminator:
            self.identity_discriminator = self.resource_type.split("/", 1)[0]
        if not self.id:
            self.id = self.compute_id()
        self.likelihood = Likelihood.from_confidence(self.confidence)
        if not isinstance(self.evidence_tier, EvidenceTier):
            self.evidence_tier = EvidenceTier(self.evidence_tier)
        if not isinstance(self.execution_status, ExecutionStatus):
            self.execution_status = ExecutionStatus(self.execution_status)
        self.sanitize()

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
        values = {
            attr.name: getattr(self, attr.name) for attr in fields(self)
            if attr.name not in {"surface", "kind", "likelihood", "risk", "evidence", "evidence_tier", "execution_status"}
        }
        values["evidence"] = [{attr.name: getattr(ev, attr.name) for attr in fields(ev)} for ev in self.evidence]
        values["risk_factors"] = [asdict(factor) for factor in self.risk.factors]
        values = sanitize(values)
        for name, value in values.items():
            if name not in {"evidence", "risk_factors"}:
                setattr(self, name, value)
        for ev, clean in zip(self.evidence, values["evidence"], strict=True):
            for name, value in clean.items():
                setattr(ev, name, value)
        for factor, clean in zip(self.risk.factors, values["risk_factors"], strict=True):
            factor.id = clean["id"]
            factor.description = clean["description"]

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
        p_none = 1.0
        for ev in self.evidence:
            w = max(0.0, min(1.0, ev.weight))
            p_none *= 1.0 - w
        self.confidence = round(1.0 - p_none, 3)
        self.likelihood = Likelihood.from_confidence(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        self.sanitize()
        d = asdict(self)
        d["surface"] = self.surface.value
        d["kind"] = self.kind.value
        d["likelihood"] = self.likelihood.value
        d["evidence_tier"] = self.evidence_tier.value
        d["execution_status"] = self.execution_status.value
        d["risk"]["level"] = self.risk.level.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        if not isinstance(d, dict):
            raise TypeError("finding must be an object")
        for name in ("surface", "connector", "kind", "title", "resource", "resource_type"):
            if not isinstance(d.get(name), str) or not d[name].strip():
                raise ValueError(f"finding {name} is required")
        d = {name: d[name] for name in (attr.name for attr in fields(cls)) if name in d}
        d.setdefault("identity_schema", LEGACY_FINDING_IDENTITY_SCHEMA)
        d["surface"] = Surface(d["surface"])
        d["kind"] = Kind(d["kind"])
        d["likelihood"] = Likelihood(d.get("likelihood", "weak"))
        if "evidence_tier" in d:
            d["evidence_tier"] = EvidenceTier(d["evidence_tier"])
        if "execution_status" in d:
            d["execution_status"] = ExecutionStatus(d["execution_status"])
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
    cache_key: str | None = None
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
