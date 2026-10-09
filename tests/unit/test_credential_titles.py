"""A credential finding says what it knows: an LLM provider credential only when a provider is attributed."""

from __future__ import annotations

from shadowscan.models import Kind

# Built at run time so that no literal in the repository looks like a live key.
OPENAI_KEY = "sk-proj-" + "kLKFlNfzW2mTofMpnx1qOu7fTm9F8IRv6iKzoC2h"
MAIL_PASSWORD = "Tq7" + "Zr2Vx9Lm4Kp8Wd3Nc6"


def _secrets(findings):
    return [finding for finding in findings if finding.kind == Kind.SECRET]


def test_an_assigned_password_is_a_hard_coded_credential_not_an_llm_credential(tmp_path, run_connector):
    (tmp_path / "settings.py").write_text(f'MAIL_PASSWORD = "{MAIL_PASSWORD}"\n', encoding="utf-8")
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    [finding] = _secrets(findings)
    assert finding.title == "Hard-coded credential in settings.py"
    assert not finding.model_providers
    assert "hardcoded-credential" in finding.tags and "unattributed-credential" in finding.tags
    assert MAIL_PASSWORD not in repr(finding.to_dict())


def test_a_provider_key_is_still_an_llm_provider_credential(tmp_path, run_connector):
    (tmp_path / "config.py").write_text(f'OPENAI_API_KEY = "{OPENAI_KEY}"\n', encoding="utf-8")
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    [finding] = _secrets(findings)
    assert finding.title == "LLM provider credential in config.py"
    assert "provider.openai" in finding.model_providers
    assert "unattributed-credential" not in finding.tags
    assert OPENAI_KEY not in repr(finding.to_dict())


def test_the_title_is_not_part_of_the_finding_identity(tmp_path, run_connector):
    (tmp_path / "settings.py").write_text(f'MAIL_PASSWORD = "{MAIL_PASSWORD}"\n', encoding="utf-8")
    [finding] = _secrets(run_connector("code.filesystem", path=str(tmp_path), use_git=False)[0])
    before = finding.id
    finding.title = "LLM provider credential in settings.py"
    assert finding.compute_id() == before
