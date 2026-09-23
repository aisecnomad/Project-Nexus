"""JSON output (full fidelity: findings, evidence, risk factors, stats)."""

from __future__ import annotations

from shadowscan.models import ScanResult


def render_json(result: ScanResult) -> str:
    return result.to_json(indent=2)
