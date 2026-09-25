from __future__ import annotations

import copy
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import yaml

from shadowscan.risk import CAPABILITY_WEIGHTS
from shadowscan.signatures import SignatureIndex, load_signatures
from shadowscan.signatures.loader import VALID_CATEGORIES, load_signature_file, signature_from_dict
from shadowscan.signatures.matcher import _LANG_ALIASES, MatchTimeoutError
from shadowscan.signatures.schema import (
    CAPABILITIES,
    ECOSYSTEMS,
    LANGUAGES,
    NAMESPACE_CATEGORIES,
    check_glob,
    matches_empty_string,
)
from shadowscan.signatures.validate import cross_signature_duplicates, main, validate_signature_set


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


def test_parallel_match_processing_is_not_charged_to_regex_iterator(monkeypatch):
    import shadowscan.signatures.matcher as matcher_module

    matcher = SignatureIndex([signature_from_dict(_signature())])
    original = matcher_module.sanitize_text

    def expensive_callback(value):
        # regex's timeout includes CPU consumed outside the regex while its
        # iterator is suspended. Simulate bounded redaction/caller processing,
        # including competing connector workers, exceeding a pattern budget
        # while remaining well inside the unchanged two-second input budget.
        deadline = time.process_time() + 0.12
        while time.process_time() < deadline:
            pass
        return original(value)

    monkeypatch.setattr(matcher_module, "sanitize_text", expensive_callback)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(matcher.match_code, ["ExampleAgent ExampleAgent"] * 4))
    assert all([match.value for match in result] == ["ExampleAgent", "ExampleAgent"] for result in results)


def test_regex_iterator_consumes_only_the_remaining_match_quota():
    import regex

    from shadowscan.signatures.matcher import _finditer

    class GuardedPattern:
        def finditer(self, text, **kwargs):
            for number, match in enumerate(regex.compile("a").finditer(text, **kwargs)):
                if number >= 3:
                    pytest.fail("Matcher consumed beyond the caller's remaining quota")
                yield match

    assert len(_finditer(GuardedPattern(), "a" * 10_000, "bounded.quota", 3)) == 3


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


# ------------------------------------------------------------ vocabularies
def test_capability_vocabulary_matches_the_risk_engine():
    # risk.py scores capabilities by exact string; a signature capability the
    # engine does not know would silently never contribute to a score.
    assert set(CAPABILITY_WEIGHTS) == CAPABILITIES


def test_language_vocabulary_matches_the_matcher_aliases():
    assert set(_LANG_ALIASES.values()) == LANGUAGES


def test_namespace_table_covers_every_category_and_manifest_ecosystems_are_closed():
    assert set(NAMESPACE_CATEGORIES.values()) == VALID_CATEGORIES
    assert {"pypi", "npm", "nuget", "maven", "go", "cargo", "rubygems", "composer", "conda", "any"} == ECOSYSTEMS


@pytest.mark.parametrize(
    "signal",
    [
        {"type": "dependency", "ecosystem": "pip", "names": ["example"]},
        {"type": "dependency", "ecosystem": "PyPI", "names": ["example"]},
        {"type": "dependency", "ecosystem": 1, "names": ["example"]},
        {"type": "import", "languages": ["typescript"], "patterns": ["example"]},
        {"type": "code", "patterns": ["example"], "capabilities": ["code_exec"]},
        {"type": "code", "patterns": ["example"], "capabilities": ["tool-use", "tool-use"]},
        {"type": "code", "patterns": ["example", "example"]},
        {"type": "dependency", "ecosystem": "pypi", "names": ["a", "a"]},
        {"type": "scope", "values": ["api", "api"]},
        {"type": "code", "patterns": ["example"], "weight": 0},
        {"type": "code", "patterns": ["example"], "weight": 0.0},
        {"type": "code", "patterns": ["a*"]},
        {"type": "code", "patterns": ["^"]},
        {"type": "code", "patterns": ["(?i)foo|"]},
        {"type": "env", "names": ["A_B"], "patterns": [r"\s*"]},
        {"type": "domain", "values": ["re:.*"]},
        {"type": "file", "globs": ["**/[abc"]},
        {"type": "file", "globs": ["a]b"]},
        {"type": "file", "globs": ["**/{a,b}.json"]},
    ],
)
def test_rejects_vocabulary_typos_zero_weights_empty_matches_and_bad_globs(signal):
    sig = _signature()
    sig["signals"] = [signal]
    with pytest.raises(ValueError):
        signature_from_dict(sig)


@pytest.mark.parametrize(
    "signal",
    [
        {"type": "dependency", "names": ["example"]},
        {"type": "dependency", "ecosystem": "any", "names": ["example"]},
        {"type": "code", "patterns": [r"\bexample\b"], "weight": 0.01},
        {"type": "file", "globs": ["**/[!.]*.md", "[]]literal", "*.json"]},
        {"type": "domain", "values": ["re:.*:11434$", "*.example.com"]},
    ],
)
def test_accepts_well_formed_signals(signal):
    sig = _signature()
    sig["signals"] = [signal]
    assert signature_from_dict(sig).signals[0].type == signal["type"]


def test_empty_string_and_glob_helpers():
    assert matches_empty_string("a*") and matches_empty_string("^$") and matches_empty_string("")
    assert not matches_empty_string(r"\bagent\b") and not matches_empty_string("[")  # loader reports the compile error
    check_glob("**/[!.]*.md", "ok")
    with pytest.raises(ValueError, match="unbalanced"):
        check_glob("[abc", "bad")


@pytest.mark.parametrize(
    ("field", "value"),
    [("capabilities", ["tool_use"]), ("capabilities", ["tool-use", "tool-use"]), ("tags", ["coding", "coding"])],
)
def test_rejects_signature_level_vocabulary_and_duplicates(field, value):
    sig = _signature()
    sig[field] = value
    with pytest.raises(ValueError):
        signature_from_dict(sig)


@pytest.mark.parametrize(
    ("sig_id", "category", "ok"),
    [
        ("cloud.example", "platform", False),
        ("cloud.example", "cloud-service", True),
        ("tool.example", "sandbox", True),
        ("tool.example", "framework", False),
        ("framework.example", "provider", False),
        ("identity-app.example", "identity-app", True),
        ("custom.example", "framework", True),
        ("acme.example", "provider", True),
    ],
)
def test_id_namespace_must_match_its_category(sig_id, category, ok):
    sig = _signature()
    sig["id"], sig["category"] = sig_id, category
    if ok:
        assert signature_from_dict(sig).id == sig_id
    else:
        with pytest.raises(ValueError, match="namespace"):
            signature_from_dict(sig)


def test_uniqueness_is_per_signal_so_distinct_signals_may_layer_capabilities():
    # The matcher lets two signals of one signature attach different weights or
    # capabilities to the same text (see the filesystem connector); only a
    # value repeated inside one signal is a data error.
    sig = _signature()
    sig["signals"] = [
        {"type": "code", "patterns": ["--yolo"], "weight": 0.9},
        {"type": "code", "patterns": ["--yolo"], "weight": 0.5, "capabilities": ["autonomous"]},
        {"type": "env", "patterns": ["--yolo"]},
    ]
    assert len(signature_from_dict(sig).signals) == 3
    sig["signals"] = [{"type": "code", "patterns": ["--yolo", "--yolo"]}]
    with pytest.raises(ValueError, match="duplicate value"):
        signature_from_dict(sig)


def _named(sig_id: str, category: str, patterns: list[str], signal_type: str = "code"):
    field = "values" if signal_type == "domain" else "patterns"
    return signature_from_dict({"id": sig_id, "category": category, "signals": [{"type": signal_type, field: patterns}]})


def test_cross_signature_duplicate_regexes_are_errors_unless_one_side_is_heuristic():
    shared = r"\bAgent\s*\(\s*model\s*="
    a = _named("framework.a", "framework", [shared])
    b = _named("framework.b", "framework", [shared])
    heuristic = _named("heuristic.h", "heuristic", [shared])
    problems = cross_signature_duplicates([a, b, heuristic])
    assert len(problems) == 1 and "framework.a, framework.b" in problems[0] and repr(shared) in problems[0]
    assert cross_signature_duplicates([a, heuristic]) == []
    # Different signal types are different observations even with identical text.
    assert cross_signature_duplicates([a, _named("provider.c", "provider", [shared], "user_agent")]) == []
    # Domain regexes count; plain domain values (shared on purpose with policies) do not.
    d1 = _named("provider.d1", "provider", ["re:.*:11434$", "api.example.com"], "domain")
    d2 = _named("provider.d2", "provider", ["re:.*:11434$", "api.example.com"], "domain")
    assert len(cross_signature_duplicates([d1, d2])) == 1


def test_builtin_packs_pass_the_whole_set_checks():
    assert validate_signature_set(load_signatures()) == []


def test_cli_reports_competing_regexes_in_custom_packs(tmp_path, capsys):
    first, second = _signature(), _signature()
    second["id"] = "framework.other"
    (tmp_path / "pack.yaml").write_text(yaml.safe_dump({"signatures": [first, second]}))
    assert main(["--no-builtin", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "Signature validation failed" in err and "competing signatures framework.example, framework.other" in err
    second["signals"][0]["patterns"] = [r"\bOtherAgent\b"]
    (tmp_path / "pack.yaml").write_text(yaml.safe_dump({"signatures": [first, second]}))
    assert main(["--no-builtin", str(tmp_path)]) == 0
    assert capsys.readouterr().out.strip() == "Validated 2 signatures and 2 signals."
