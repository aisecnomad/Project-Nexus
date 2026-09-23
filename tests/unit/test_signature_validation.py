from __future__ import annotations

import copy
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import yaml

from shadowscan.signatures import SignatureIndex, load_signatures
from shadowscan.signatures.loader import load_signature_file, signature_from_dict
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.signatures.validate import main


def _signature():
    return {
        "id": "framework.example",
        "name": "Example",
        "category": "framework",
        "signals": [{"type": "code", "patterns": [r"\bExampleAgent\b"], "weight": 0.8}],
    }


@pytest.mark.parametrize("weight", [True, "0.5", None, -0.1, 1.01, float("nan"), float("inf"), 10**500])
def test_rejects_invalid_weight_without_coercion(weight):
    sig = _signature()
    sig["signals"][0]["weight"] = weight
    with pytest.raises(ValueError, match="weight"):
        signature_from_dict(sig)


@pytest.mark.parametrize(
    ("field", "value"),
    [("category", "unknown"), ("tags", "tag"), ("agent_indicator", "false"), ("id", 123),
     ("signals", []), ("signals", {}), ("severity", "critical"), ("severity", "urgent"),
     ("weigth", 0.9)],
)
def test_rejects_invalid_signature_shapes_and_unsupported_severity(field, value):
    sig = _signature()
    sig[field] = value
    with pytest.raises(ValueError):
        signature_from_dict(sig)


@pytest.mark.parametrize(
    "signal",
    [None, [], {"type": "bogus"}, {"type": "code", "patterns": "bad"},
     {"type": "code", "patterns": [123]}, {"type": "code", "patterns": ["["]},
     {"type": "domain", "values": ["re:["]},
     {"type": "dependency", "names": ["example"], "patterns": ["unused"]},
     {"type": "code", "patterns": ["example"], "severity": "high"},
     {"type": "env", "names": [], "patterns": []}],
)
def test_rejects_invalid_signal_shapes_and_regexes(signal):
    sig = _signature()
    sig["signals"] = [signal]
    with pytest.raises(ValueError):
        signature_from_dict(sig)


@pytest.mark.parametrize("content", ["42", "null", "[]", "", "signatures: []", "signatures: {}",
                                      "signatures: null", "signatures: []\nversion: 1",
                                      "signatures: []\nsignatures: []"])
def test_invalid_yaml_pack_fails_closed(tmp_path, content):
    path = tmp_path / "bad.yaml"
    path.write_text(content)
    with pytest.raises(ValueError):
        load_signature_file(path)


def test_cli_validates_builtin_and_custom_packs(tmp_path, capsys):
    assert main([]) == 0
    path = tmp_path / "example.yaml"
    path.write_text(yaml.safe_dump({"signatures": [_signature()]}))
    assert main(["--no-builtin", str(tmp_path)]) == 0
    path.write_text("signatures: [{id: broken}]")
    assert main([str(tmp_path)]) == 1
    assert "Signature validation failed" in capsys.readouterr().err


def test_duplicate_ids_fail_within_pack_but_override_across_packs(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    data = yaml.safe_dump({"signatures": [_signature()]})
    (first / "a.yaml").write_text(data)
    (first / "b.yaml").write_text(data)
    with pytest.raises(ValueError, match="duplicate signature id"):
        load_signatures([first], include_builtin=False)
    (first / "b.yaml").unlink()
    changed = _signature()
    changed["name"] = "Override"
    (second / "a.yaml").write_text(yaml.safe_dump({"signatures": [changed]}))
    assert load_signatures([first, second], include_builtin=False)[0].name == "Override"


def test_fingerprint_covers_signature_semantics_and_ignores_source_paths():
    original = _signature()
    first = SignatureIndex([signature_from_dict(original, "one/path")])
    second = SignatureIndex([signature_from_dict(original, "two/path")])
    assert first.fingerprint() == second.fingerprint()
    changed = copy.deepcopy(original)
    changed["signals"][0]["weight"] = 0.9
    assert first.fingerprint() != SignatureIndex([signature_from_dict(changed)]).fingerprint()


def test_per_input_budget_is_enforced_and_reset(index, monkeypatch):
    with pytest.raises(MatchTimeoutError, match="budget"), index.scan_budget(seconds=0.01):
        deadline_elapsed = time.monotonic() + 1
        monkeypatch.setattr("shadowscan.signatures.matcher.time.monotonic", lambda: deadline_elapsed)
    monkeypatch.undo()
    assert index.match_imports("from crewai import Agent", "python")


def test_match_excerpt_redacts_before_truncating_and_preserves_secret_identity():
    signature = _signature()
    signature["signals"][0]["patterns"] = [r"token=.*"]
    matcher = SignatureIndex([signature_from_dict(signature)])
    secret = "opaque" * 80
    match = matcher.match_code("token=" + secret)[0]
    assert match.value == "token=[REDACTED]"
    signature["signals"] = [{"type": "secret", "patterns": [r"opaque[\w]+"]}]
    matcher = SignatureIndex([signature_from_dict(signature)])
    assert matcher.match_secrets(secret)[0].value == secret


def test_builtin_newline_and_hostname_regressions_finish_within_budget(index):
    start = time.monotonic()
    with index.scan_budget(seconds=2):
        assert index.match_imports("\n" * 1_000_000, "python") == []
        assert index.match_code("\n" * 1_000_000) == []
        assert index.match_domains_in_text("a." * 500_000) == []
    assert time.monotonic() - start < 2
    hits = index.match_domains_in_text("\nhttps://api.openai.com/v1\napi.openai.com\napi.anthropic.com")
    providers = [(m.signature_id, m.line) for m in hits if m.signature.category == "provider"]
    assert providers == [("provider.openai", 2), ("provider.anthropic", 4)]


def test_parallel_tokenization_does_not_exhaust_regex_deadlines(index):
    text = "https://api.openai.com/v1\napi.anthropic.com\n" * 2000
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(index.match_domains_in_text, [text] * 12))
    for matches in results:
        assert {"provider.openai", "provider.anthropic"} <= {m.signature_id for m in matches}


@pytest.mark.parametrize("signal_type", ["code", "domain", "env", "client_id"])
def test_untrusted_regex_execution_is_preempted(signal_type):
    # A subprocess timeout also bounds the regression test if runtime preemption
    # is accidentally removed. Thread timeouts cannot stop a running regex.
    code = r'''
import sys
from shadowscan.signatures.loader import signature_from_dict
from shadowscan.signatures.matcher import MatchTimeoutError, SignatureIndex
kind = sys.argv[1]
signal = {"type": kind, "values" if kind == "domain" else "patterns":
          ["re:(a+)+$" if kind == "domain" else "(a+)+$"]}
index = SignatureIndex([signature_from_dict({"id": "custom.expensive", "category": "framework", "signals": [signal]})])
try:
    getattr(index, "match_" + kind)("a" * 50000 + "!")
except MatchTimeoutError:
    print("incomplete")
else:
    raise AssertionError("expected matching to time out")
'''
    result = subprocess.run([sys.executable, "-c", code, signal_type], capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "incomplete"
