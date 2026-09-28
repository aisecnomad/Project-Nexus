"""Rules added to redaction never reveal what the established rules withheld.

Every pass reads the text the passes before it leave. An added rule that
withheld more inside the established passes changed what the later ones
read: a value withheld together with the name, tag or scheme glued after it
hid that context from the pass that withholds by it, and the credential
behind it reached reports. The established passes therefore run first,
exactly as before the rules were added, and the added passes read what they
leave; ``sanitize`` runs its structured rules in the same two steps.

The forms below are shrunk from a differential fuzz run. The established
rules (bd16bd6) withhold each secret; the first fix round (94a52e2) showed it.
"""

from __future__ import annotations

import random

import pytest

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
