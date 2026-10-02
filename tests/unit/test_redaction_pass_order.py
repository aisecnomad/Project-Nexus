"""Rules added to redaction never reveal what the established rules withheld.

Every pass reads the text the passes before it leave. An added rule that
withheld more inside the established passes changed what the later ones
read: a value withheld together with the name, tag or scheme glued after it
hid that context from the pass that withholds by it, and the credential
behind it reached reports. The established passes therefore run first,
exactly as before the rules were added, and the added passes read what they
leave; ``sanitize`` runs its structured rules in the same two steps, then
removes the leaves nested in a withheld credential container last.

The forms below are shrunk from a differential fuzz run. The established
rules (bd16bd6) withhold each secret; the first fix round (94a52e2) showed it.
"""

from __future__ import annotations

import json
import random
from typing import Any

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.reporters import RENDERERS
from shadowscan.utils import redaction
from shadowscan.utils.redaction import REDACTED, sanitize, sanitize_text

SECRET = "Zq8Rw2Lk5Tn7Vb3Xc9Mf"

# (form, what the added rule that hid the context read)
GLUED_FORMS = [
    # Element content withheld by the element's name, before an assignment
    # whose value runs past the closing tag.
    (f'<a key="passwd" value="">token=</a{SECRET}', "element content"),
    (f'<p value="" name="apiKey">token=</p/{SECRET}', "element content"),
    # A record value under a setting name glued to the next name or scheme.
    (f'name=Key value=tK3token ="{SECRET}"', "credential-word record name"),
    (f"name=I:Token value=Basic {SECRET}", "hierarchical record name"),
    (f"name=i.key value=b4cfe38a(docker login -p {SECRET}", "hierarchical record name"),
    (f'name=Key value=e2d19ca6("ApiKey",{SECRET}', "credential-word record name"),
    (f"name=Key value=OtPeQArJ`pwd: '{SECRET}'", "credential-word record name"),
    # A numbered name's or a YAML value's opaque literal glued to a fallback's name.
    (f'Key2=M8vrtKey ||"{SECRET}"', "numbered name"),
    (f'key: eb9gcQDv.pwd ||"{SECRET}"', "unquoted YAML value"),
    # A value 'dotnet user-secrets set' stores, glued to an assignment.
    (f'dotnet user-secrets set "Authorization" token"={SECRET}', "user-secrets value"),
    # Values withheld early changed what the mapping pass consumed after them.
    (f'Credential=""key="TOKEN"value="X}}"\n{SECRET}', "quoted record value"),
    (f'ApiKey=""<a key="Key""">XYXdqY0F]</a;{SECRET}', "credential-word key attribute"),
    (f'i_key=<p""name="z:Token">//1</p{{}}\n{SECRET}', "hierarchical name attribute"),
]


@pytest.mark.parametrize(("source", "rule"), GLUED_FORMS)
def test_an_added_rule_never_hides_the_context_an_established_rule_reads(source, rule):
    assert SECRET in source
    safe = sanitize_text(source)
    assert SECRET not in safe, rule
    assert SECRET not in redaction._sanitize_established(source), rule
    assert sanitize_text(safe) == safe


# Forms that main (b40ac3c) withholds, shrunk from a differential of these
# passes against it. Each hid a name from the rule that withholds by it.
MAIN_WITHHELD_FORMS = [
    # A record value in JSON-escaped YAML ran past the escaped line break and
    # took the next line's name with it.
    (
        '{"cmd": "- name: access_token\\n  value: sbKXLhjisp\\n\\n$env:auth_token = \\"' + SECRET + '\\""}',
        "record value across an escaped line break",
    ),
    # After a withheld query value, an ordinary parameter's value ran past the
    # marker and the '&' into the next parameter's name.
    (
        f"https://x.blob.core.windows.net/c?sv=2020&sig=esDrvsxl3d&Authorization: Bearer igM^{SECRET}",
        "query value past a marker",
    ),
    (
        f"https://x.blob.core.windows.net/c?sv=2020&sig=esDrvsxl3d&Authorization: Bearer KTLn {SECRET}",
        "query value past a marker",
    ),
    # A statement withheld to the end of its line took a record name that
    # followed it there; the value on the next line lost its name.
    (
        f"credential=AzureKeyCredential(`k3Jd92LmQpXz7Rv4Wn8T`), - name: GITHUB_TOKEN\n  value: {SECRET}\n",
        "record name after a statement",
    ),
    (
        "export credential='k3Jd92LmQpXz7Rv4Wn8T', echo Pa$$w0rd3371 | "
        f"docker login -u x --password-stdin, - name: auth_token\n  value: {SECRET}\n",
        "record name after a statement",
    ),
]


# Withheld before the name passes, an armored PGP private key block took the
# start of a value that runs past its END line, and the rest of the value
# was shown. Main (d65b27f) withholds each secret.
_PGP_BEGIN = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
_PGP_END = "-----END PGP PRIVATE KEY BLOCK-----"
MAIN_WITHHELD_FORMS += [
    (f'{_PGP_BEGIN}\npassword: "abc\n{_PGP_END}\n{SECRET}"\n', "quoted mapping value past the block"),
    (f"{_PGP_BEGIN}\npassword:\n  x\n  {_PGP_END}\n  {SECRET}\n", "indented YAML value past the block"),
    (f"{_PGP_BEGIN}\nENV GPG_PASSWORD \\\n{_PGP_END} {SECRET}\n", "continued ENV value past the block"),
    (f"{_PGP_BEGIN}\n<password>abc\n{_PGP_END}\n{SECRET}</password>\n", "element content past the block"),
    (f'{_PGP_BEGIN}\napi_key = """abc\n{_PGP_END}\n{SECRET}"""\n', "triple-quoted value past the block"),
    (f"{_PGP_BEGIN}\npassword: [abc,\n{_PGP_END}\n{SECRET}]\n", "bracketed value past the block"),
]


@pytest.mark.parametrize(("source", "rule"), MAIN_WITHHELD_FORMS)
def test_what_main_withholds_stays_withheld(source, rule):
    assert SECRET in source
    safe = sanitize_text(source)
    assert SECRET not in safe, rule
    assert sanitize_text(safe) == safe


# More than _CLI_WORD_OPTIONS options inside one unquoted word. The first fix
# round withheld the rest of such a word in the established option pass,
# which hid what follows from the other passes. That pass now decides every
# option as bd16bd6 did, reading the word once (see _ValueRuns); only the
# last pass withholds the rest of a word crowded with options.
CROWDED = "-u=#" * 17


@pytest.mark.parametrize(
    "source",
    [
        f'tool {CROWDED}--password "{SECRET}" --verbose',
        f"tool {CROWDED}--password {SECRET} --verbose",
        f'tool {CROWDED}api_key="{SECRET}"',
        f"tool {CROWDED}--api-key={SECRET}",
        f"tool {CROWDED}-u=svc:{SECRET}",
        f"mysql {CROWDED}-p{SECRET} app",
        f"tool {CROWDED}--key={SECRET} --model gpt-4o",
    ],
)
def test_a_word_crowded_with_options_never_shows_a_value(source):
    safe = sanitize_text(source)
    assert SECRET not in safe
    assert sanitize_text(safe) == safe


def test_a_crowded_word_keeps_the_text_after_it():
    safe = sanitize_text(f"tool {CROWDED}--key={SECRET} --model gpt-4o")
    assert safe.endswith(f"{REDACTED} --model gpt-4o")


_RUN_PIECES = [
    "a",
    "Z",
    "9",
    "٣",
    "²",
    ":",
    "=",
    "#",
    "-",
    "--",
    "/",
    "//",
    "_",
    "$A",
    "$",
    "%K%",
    "%",
    "+",
    "X-Api-Key",
    "Authorization",
    "Bearer",
    "user",
    "svc",
    "a1B2c3D4e5",
    "credential:sha256:" + "a" * 64,
]


def test_reading_a_run_once_decides_as_reading_its_copy():
    # The established option pass reads an unquoted value in place, once per
    # run of value characters; it must decide as _cli_secret_span does on the
    # value's copy, which bd16bd6 read again for every option in the run.
    rng = random.Random(20260927)
    for _ in range(4000):
        run = "".join(rng.choice(_RUN_PIECES) for _ in range(rng.randint(1, 12)))
        text = "tool -u=" + run + " next"
        runs = redaction._ValueRuns(text)
        start = len("tool -u=")
        for offset in range(len(run)):
            position = start + offset
            if not redaction._CLI_BARE_CHARACTER.match(text, position):
                continue
            end = runs.end(position)
            assert end == start + len(run)
            for mode in ("user", "header", "secret"):
                for strict in (True, False):
                    expected = redaction._cli_secret_span(mode, text[position:end], position, strict)
                    assert redaction._run_secret_span(mode, runs, position, end, strict) == expected, (
                        mode,
                        strict,
                        text[position:end],
                    )


def _only_adds_markers(before: str, after: str) -> bool:
    """Whether ``after`` is ``before`` with some spans replaced by the marker.

    Newlines a marker keeps for the lines it replaced may follow it.
    """
    position = 0
    for index, piece in enumerate(after.split(REDACTED)):
        if index:
            piece = piece.lstrip("\n")
        found = before.find(piece, position)
        if found < 0 or (index == 0 and found != 0):
            return False
        position = found + len(piece)
    return after.endswith(REDACTED) or before.endswith(after.split(REDACTED)[-1].lstrip("\n"))


@pytest.mark.parametrize(
    "source",
    [source for source, _ in GLUED_FORMS]
    + [
        '<token key="openai.token" value="ignored">a8f3c91d7e2b4f6a9d0c</token>',
        "{name: OpenAIKey, value: a8f3c91d7e2b4f6a9d0c}\nKEY1=b7e2c4d6f8a0b2c4d6e8\n",
        "llm --key a8f3c91d7e2b4f6a9d0c --model gpt-4o\nopenaiKey: b7e2c4d6f8a0b2c4d6e8\n",
        'dotnet user-secrets set "AzureOpenAI:Key" "a8f3c91d7e2b4f6a9d0c"',
        f"tool {CROWDED}--key={SECRET} --model gpt-4o",
    ],
)
def test_the_added_passes_only_add_markers_to_what_the_established_ones_leave(source):
    established = redaction._sanitize_established(source)
    assert _only_adds_markers(established, sanitize_text(source))


def test_a_newly_known_argv_value_never_hides_a_sibling_fields_name():
    # The '--key' value is known only to the added rules. Replaced in the
    # note before the established text passes ran, it hid the name
    # 'a1B2c3D4e5F6g7H8password' from the assignment rule, and the
    # password after it was shown.
    name = "a1B2c3D4e5F6g7H8password"
    value = {"args": ["tool", "--key", name], "note": f"{name}={SECRET}"}
    for short in (False, True):
        safe = sanitize(value, redact_short_secrets=short)
        assert SECRET not in repr(safe)
        assert name not in repr(safe)
        assert safe["args"] == ["tool", "--key", REDACTED]


@pytest.mark.parametrize("source", [source for source, _ in GLUED_FORMS[:4]])
def test_structured_fields_withhold_what_the_established_rules_withhold(source):
    for short in (False, True):
        safe = sanitize({"excerpt": source, "items": [source]}, redact_short_secrets=short)
        assert SECRET not in repr(safe)


# The leaves nested in a credential container that clean withholds whole are
# credentials too, so their copies in other fields are removed. Such a leaf
# can also be what another rule reads to withhold the value beside it: an
# option name, a setting or record name, a tag, a command word. Removed in
# the established pass, it hid that context from the added rules and the
# value was shown (the merge of the nested discovery into bd4c8b3's passes).
# The nested pass runs last, so it only adds markers.
NESTED_VALUE = "0275d100d8d5d2092c3ca3fef21a7028"
NESTED_CONTEXT: dict[str, tuple[dict[str, Any], str, str]] = {
    "argv-min": (
        {
            "private_key": ["--webhook_secret", "a2a5c2a6c6bf1cd9c187d443bf208c0d"],
            "args": ["--webhook_secret", NESTED_VALUE],
        },
        NESTED_VALUE,
        "--webhook_secret",
    ),
    "argv-dict": (
        {"api_key": {"flag": "--webhook_secret"}, "args": ["--webhook_secret", NESTED_VALUE]},
        NESTED_VALUE,
        "--webhook_secret",
    ),
    "cmd-string": (
        {"secret": ["--webhook_secret"], "cmd": f"tool --webhook_secret {NESTED_VALUE}"},
        NESTED_VALUE,
        "--webhook_secret",
    ),
    "record": (
        {"secret": ["PASSWORD_1"], "settings": [{"name": "PASSWORD_1", "value": "Hunter2Xyz77"}]},
        "Hunter2Xyz77",
        "PASSWORD_1",
    ),
    "xml": (
        {"token": ["ConnectionPassword"], "doc": "<ConnectionPassword>Hunter2Xyz77</ConnectionPassword>"},
        "Hunter2Xyz77",
        "ConnectionPassword",
    ),
    "usersecrets": (
        {"token": ["user-secrets"], "cmd": 'dotnet user-secrets set "Api:Key" "Hunter2Xyz77abc"'},
        "Hunter2Xyz77abc",
        "user-secrets",
    ),
}


def _strings(value: Any) -> list[str]:
    """Every key and string of a sanitized copy, in order."""
    if isinstance(value, dict):
        return [text for key, child in value.items() for text in (key, *_strings(child))]
    if isinstance(value, (list, tuple)):
        return [text for child in value for text in _strings(child)]
    return [value] if isinstance(value, str) else []


def _two_passes(value: Any, monkeypatch: pytest.MonkeyPatch, *, short: bool) -> Any:
    """What the established and extended passes leave: ``sanitize`` with no nested leaf known."""
    with monkeypatch.context() as patch:
        patch.setattr(redaction._NestedSanitizer, "discover", lambda self, item, *args, **kwargs: None)
        return sanitize(value, redact_short_secrets=short)


@pytest.mark.parametrize("case", sorted(NESTED_CONTEXT))
def test_a_nested_credential_leaf_never_hides_the_context_of_a_value(case, monkeypatch):
    value, secret, leaf = NESTED_CONTEXT[case]
    for short in (False, True):
        safe = sanitize(value, redact_short_secrets=short)
        assert secret not in repr(safe), short
        # The leaf is withheld from every other field as well.
        assert leaf not in repr(safe), short
        assert sanitize(safe, redact_short_secrets=short) == safe
        before = _strings(_two_passes(value, monkeypatch, short=short))
        after = _strings(safe)
        assert len(before) == len(after)
        assert all(_only_adds_markers(old, new) for old, new in zip(before, after, strict=True)), short


def test_a_nested_option_name_never_reveals_its_value_in_any_report(tmp_path, index):
    server = {
        "command": "npx",
        "args": ["-y", "hook-server", "--webhook_secret", NESTED_VALUE],
        "env": {"API_TOKEN": ["--webhook_secret"]},
    }
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"hooks": server}}), encoding="utf-8")
    spec = ConnectorSpec("code.filesystem", {"path": str(tmp_path), "use_git": False})
    result = Engine(ScanConfig(connectors=[spec]), index).run()
    assert result.complete, [error for stats in result.stats for error in stats.errors]
    for name, render in RENDERERS.items():
        assert NESTED_VALUE not in render(result), name
    (finding,) = json.loads(RENDERERS["json"](result))["findings"]
    assert finding["metadata"]["servers"][0]["args"] == ["-y", "hook-server", REDACTED, REDACTED]


NESTED_SECRET = "opaque-nested-test-credential-271828"


@pytest.mark.parametrize(
    "container",
    [
        # A record named by the added rules withholds its value whole.
        {"settings": [{"name": "OpenAI:Secret", "value": {"key": NESTED_SECRET}}]},
        # So does a record's value under any casing.
        {"settings": [{"name": "password", "VALUE": {"key": NESTED_SECRET}}]},
        {"settings": [{"name": "password", "VALUE": NESTED_SECRET}]},
        # A known value the text passes withheld only in part.
        {"credentials": {"value": f"prefix sk-proj-{'x' * 40} {NESTED_SECRET}"}},
    ],
)
def test_the_nested_pass_removes_what_the_first_two_leave_of_a_leaf(container):
    note = f"prefix sk-proj-{'x' * 40} {NESTED_SECRET} rejected"
    for short in (False, True):
        safe = sanitize({**container, "note": note}, redact_short_secrets=short)
        assert NESTED_SECRET not in repr(safe), short
        assert safe["note"].endswith(f"{REDACTED} rejected"), short


def test_a_short_nested_leaf_is_not_found_inside_a_marker():
    # 'ACT' occurs in the marker the established pass left in the note, not
    # in the note itself; a field that does contain it is withheld.
    value = {"credentials": {"tier": "ACT"}, "note": "token=abc123xyz789", "other": "ACTIVE"}
    assert sanitize(value) == {"credentials": REDACTED, "note": f"token={REDACTED}", "other": REDACTED}


def test_a_value_without_a_credential_container_is_left_to_the_first_two_passes(monkeypatch):
    # A record's value the established pass knew is not known again: it is
    # already removed from every field. An 'id' names a key's identity.
    def fail(self: object, item: Any, depth: int = 0) -> Any:
        raise AssertionError("the nested pass copied a value it has nothing to remove from")

    monkeypatch.setattr(redaction._NestedSanitizer, "clean", fail)
    value = {
        "password": "Hunter2Xyz77",
        "args": ["--key", "a8f3c91d7e2b4f6a9d0c", "--token", NESTED_VALUE],
        "settings": [{"name": "PASSWORD", "value": "b7e2c4d6f8a0b2c4d6e8"}],
        "env": {"API_TOKEN": "c9d1e3f5a7b9c1d3e5f7"},
        "api_key": {"id": "k"},
        "note": f"token={NESTED_VALUE}",
    }
    for short in (False, True):
        safe = sanitize(value, redact_short_secrets=short)
        assert NESTED_VALUE not in repr(safe)
        assert safe["api_key"] == REDACTED
