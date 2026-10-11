"""The finding schema every AI Review Gate reviewer emits and the gate consumes.

A finding is a JSON object. The gate validates the shape below and drops
anything else; a reviewer that cannot produce the schema produces nothing,
and an empty findings directory is a blocked gate, not a passing one.

Required fields:
    schema_version: the string "1".
    agent: one of AGENTS (the reviewer that wrote the finding).
    severity: one of critical, high, medium, low.
    category: one of security, correctness, operability, testing,
        architecture, supply-chain.
    title: short one-line summary (1..200 characters, no newlines).
    body: the finding: what is wrong, the attack or failure scenario, the
        recommendation, and the reviewer's explicit assumptions about the
        surrounding system (middleware, validation, deployment).

Optional fields:
    path / line: location in the diff. path must be a normalized
        repository-relative file; line a positive integer. Both must be
        present or both absent. The gate verifies the file is in the diff.
    confidence: one of high, medium, low.
    cwe / owasp: reference identifiers (for example "CWE-89",
        "A03:2021-Injection").
    fingerprint: stable identity for deduplication. Reviewers that re-derive
        scanner evidence (CodeQL, secret scanning, Dependabot) set the
        scanner's fingerprint so the gate reports it once. When absent the
        gate derives one from agent, path, line and title.
    blocking: boolean, default true for critical/high severity. The gate
        recomputes blocking from severity and never trusts the field.

The gate only accepts severity from the agent. It never lowers one.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

SCHEMA_VERSION = "1"

AGENTS = (
    "orchestrator",
    "appsec",
    "correctness",
    "operability",
    "testing",
    "architecture",
    "supply-chain",
)
SEVERITIES = ("critical", "high", "medium", "low")
CATEGORIES = (
    "security",
    "correctness",
    "operability",
    "testing",
    "architecture",
    "supply-chain",
)
CONFIDENCES = ("high", "medium", "low")

BLOCKING_SEVERITIES = frozenset({"critical", "high"})

MAX_TITLE = 200
MAX_BODY = 8000
MAX_FINDINGS_PER_FILE = 50

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True)
class Finding:
    agent: str
    severity: str
    category: str
    title: str
    body: str
    path: str | None = None
    line: int | None = None
    confidence: str | None = None
    cwe: str | None = None
    owasp: str | None = None
    fingerprint: str | None = None
    blocking: bool = field(default=True)

    @property
    def identity(self) -> str:
        """Stable dedup identity: the supplied fingerprint or a derived one."""
        if self.fingerprint:
            return self.fingerprint
        base = f"{self.agent}|{self.path or ''}|{self.line or 0}|{self.title}"
        return "sha256:" + hashlib.sha256(base.encode("utf-8")).hexdigest()


def _clean(value: Any) -> str | None:
    """A value usable in a review: stripped of control characters, else None."""
    if not isinstance(value, str):
        return None
    text = _CONTROL.sub("", value).strip()
    return text or None


def _path(value: Any) -> str | None:
    """A normalized repository-relative path, or None for anything else."""
    text = _clean(value)
    if text is None:
        return None
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or path.as_posix() != text
        or any(part in {".", ".."} for part in path.parts)
        or "\\" in text
    ):
        return None
    return text


def parse_finding(data: Any) -> Finding | None:
    """One finding from decoded JSON, or None when the shape is not the schema.

    The gate treats reviewer output as untrusted: any missing, mistyped or
    out-of-range required field invalidates the whole finding. An invalid
    finding is dropped and counted; enough dropped findings block the gate
    (see synthesize), so a reviewer cannot pass by emitting noise.
    """
    if not isinstance(data, dict):
        return None
    if data.get("schema_version") != SCHEMA_VERSION:
        return None
    agent = _clean(data.get("agent"))
    severity = _clean(data.get("severity"))
    category = _clean(data.get("category"))
    title = _clean(data.get("title"))
    body = _clean(data.get("body"))
    if agent not in AGENTS:
        return None
    if severity not in SEVERITIES:
        return None
    if category not in CATEGORIES:
        return None
    if title is None or len(title) > MAX_TITLE or "\n" in title:
        return None
    if body is None or len(body) > MAX_BODY:
        return None

    path = _path(data.get("path"))
    line = data.get("line")
    if data.get("path") is not None and path is None:
        return None
    if (path is None) != (line is None):
        return None
    if line is not None and (type(line) is not int or line < 1):
        return None

    confidence = _clean(data.get("confidence"))
    if confidence not in CONFIDENCES:
        confidence = None
    cwe = _clean(data.get("cwe"))
    if cwe is not None and not re.fullmatch(r"CWE-\d{1,5}", cwe):
        cwe = None
    owasp = _clean(data.get("owasp"))
    if owasp is not None and len(owasp) > 80:
        owasp = None
    fingerprint = _clean(data.get("fingerprint"))
    if fingerprint is not None and (len(fingerprint) > 200 or "\n" in fingerprint):
        fingerprint = None

    return Finding(
        agent=agent,
        severity=severity,
        category=category,
        title=title,
        body=body,
        path=path,
        line=line,
        confidence=confidence,
        cwe=cwe,
        owasp=owasp,
        fingerprint=fingerprint,
        # The gate derives blocking from severity; the field is informational.
        blocking=severity in BLOCKING_SEVERITIES,
    )
