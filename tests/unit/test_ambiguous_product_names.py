"""Product names that are also first names or common words need context to match."""

from __future__ import annotations

import pytest

CODING = "identity-app.coding-assistants-saas"
MEETINGS = "identity-app.meeting-notetakers"
SALES = "identity-app.hr-sales-support-ai"


def matched(index, text: str) -> set[str]:
    return {m.signature_id for m in index.match_name(text)}


@pytest.mark.parametrize(("text", "signature"), [
    ("Cursor", CODING), ("Cursor AI", CODING), ("cursor.com", CODING), ("Warp", CODING), ("Zed Editor", CODING),
    ("Devin AI", CODING), ("devin-ai-integration[bot]", "coding-agent.pr-review-bots"), ("Augment Code", CODING),
    ("OpenHands by All Hands AI", CODING), ("Fathom AI Notetaker", MEETINGS), ("Fathom Video", MEETINGS), ("Gong", MEETINGS),
    ("Fellow.app", MEETINGS), ("Otter.ai", MEETINGS), ("Jamie AI", MEETINGS), ("Apollo.io", SALES), ("Drift", SALES),
    ("Clay", SALES), ("Olivia by Paradox", SALES), ("Qualified Piper", SALES), ("Outreach Kaia", SALES),
    ("Codex", "coding-agent.openai-codex"), ("OpenAI Codex connector", "coding-agent.openai-codex"),
    ("Sweep AI", "coding-agent.pr-review-bots"), ("Cursor", "coding-agent.cursor"),
])
def test_product_names_still_match(index, text, signature):
    assert signature in matched(index, text)


@pytest.mark.parametrize("text", [
    "Olivia Martinez", "Jamie Chen", "Piper Lee", "Devin Smith", "Kaia Johnson", "Ema Novak",
    "Apollo GraphQL Router", "Fathom Analytics export", "cursor-pagination-handler", "database cursor helper",
    "warp-speed-deploy", "zed-attack-proxy scans", "drift-detection-lambda", "qualified leads report",
    "clay-modelling-club", "Laravel artisan scheduler", "lavender-hr-theme", "grain-silo-monitor",
    "fellow employees directory", "All Hands meeting notes", "sweep old snapshots", "ellipsis in the title",
    "graphite metrics exporter", "codex of internal policies", "augment your workflow", "Otter valley office",
    "EMA smoothing job", "cognition research wiki", "a lovable mascot", "paradox of choice",
])
def test_first_names_and_common_words_do_not_name_ai_products(index, text):
    assert not {CODING, MEETINGS, SALES, "coding-agent.cursor", "coding-agent.openai-codex", "coding-agent.pr-review-bots"} & matched(index, text)
