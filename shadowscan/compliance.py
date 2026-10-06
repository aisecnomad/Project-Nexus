"""Conservative control references derived from stable finding tags."""

from __future__ import annotations

from collections.abc import Iterable

_TAG_REFERENCES: dict[str, tuple[str, ...]] = {
    "tool-poisoning": ("OWASP-LLM-01", "OWASP-ASI-01", "MITRE-ATLAS-AML.T0051"),
    "unsafe-serialization": ("OWASP-LLM-03", "OWASP-ASI-04", "MITRE-ATLAS-AML.T0010"),
    "hardcoded-credential": ("OWASP-LLM-03", "OWASP-ASI-04"),
    "cluster-admin": ("OWASP-LLM-06", "OWASP-ASI-08"),
    "privileged-pod": ("OWASP-LLM-06", "OWASP-ASI-08"),
    "code-exec": ("OWASP-LLM-06", "OWASP-ASI-08"),
    "saas-actions": ("OWASP-LLM-06", "OWASP-ASI-08"),
    "exposed-llm-server": ("OWASP-LLM-07", "OWASP-ASI-05"),
    "unauthenticated-mcp": ("OWASP-LLM-07", "OWASP-ASI-05"),
}


def compliance_references(tags: Iterable[str]) -> list[str]:
    """Return stable, deduplicated compliance references for recognized tags."""
    return sorted({reference for tag in tags for reference in _TAG_REFERENCES.get(tag, ())})
