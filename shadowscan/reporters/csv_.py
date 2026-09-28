"""CSV output (one row per finding; evidence summarised)."""

from __future__ import annotations

import csv
import io
import re

from shadowscan.models import ScanResult

COLUMNS = [
    "id",
    "risk_level",
    "risk_score",
    "shadow",
    "registry_match",
    "surface",
    "kind",
    "title",
    "resource",
    "resource_type",
    "provider",
    "account",
    "region",
    "owner",
    "confidence",
    "likelihood",
    "frameworks",
    "model_providers",
    "models",
    "capabilities",
    "tags",
    "permissions",
    "first_seen",
    "last_seen",
    "risk_factors",
    "evidence_count",
    "top_evidence",
    "connector",
]

# A spreadsheet cell must not begin with a formula trigger (OWASP CSV injection).
# A value can start several cells: a report opened with another delimiter (for
# example a semicolon locale), or a joined list split on "|", starts a new cell
# after each delimiter or line break. Leading whitespace, including a no-break
# space, and quotes may be trimmed, so they do not hide a trigger. A value that
# starts with a tab or line break, or a later cell that does, is also neutralised.
_FORMULA_CELL = re.compile(
    r"^(?=[\t\r\n])"
    r"|(?:^|(?<=[,;\t|\r\n]))(?=[\t\r]|[ \t\r\n\v\f\ufeff\u00a0\"]*[=+\-@])"
)


def _safe_cell(value: object) -> object:
    """Force every formula-like cell in an untrusted string to spreadsheet text."""
    if isinstance(value, str):
        return _FORMULA_CELL.sub("'", value)
    return value


def render_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS, extrasaction="ignore")
    w.writeheader()
    for f in result.findings:
        f.sanitize()
        top_evidence = sorted(f.evidence, key=lambda e: -e.weight)[:3]
        row = {
            "id": f.id,
            "risk_level": f.risk.level.value,
            "risk_score": f.risk.score,
            "shadow": "" if f.shadow is None else ("yes" if f.shadow else "no"),
            "registry_match": f.registry_match or "",
            "surface": f.surface.value,
            "kind": f.kind.value,
            "title": f.title,
            "resource": f.resource,
            "resource_type": f.resource_type,
            "provider": f.provider or "",
            "account": f.account or "",
            "region": f.region or "",
            "owner": f.owner or "",
            "confidence": f.confidence,
            "likelihood": f.likelihood.value,
            "frameworks": "|".join(f.frameworks),
            "model_providers": "|".join(f.model_providers),
            "models": "|".join(f.models),
            "capabilities": "|".join(f.capabilities),
            "tags": "|".join(f.tags),
            "permissions": "|".join(f.permissions[:30]),
            "first_seen": f.first_seen or "",
            "last_seen": f.last_seen or "",
            "risk_factors": "; ".join(x.description for x in f.risk.factors if x.weight > 0),
            "evidence_count": len(f.evidence),
            "top_evidence": " | ".join(e.description for e in top_evidence),
            "connector": f.connector,
        }
        w.writerow({key: _safe_cell(value) for key, value in row.items()})
    return buf.getvalue()
