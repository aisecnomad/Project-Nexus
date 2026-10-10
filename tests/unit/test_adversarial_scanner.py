"""Adversarial tests for the scanner itself (malicious exports, oversized inputs, injection attempts)."""

import pytest
from pathlib import Path

# Skeletons for the maintainer to expand with full Engine fixtures

def test_oversized_offline_export_marks_incomplete(tmp_path):
    """A JSONL line exceeding the 4 MiB limit must mark the scan incomplete."""
    # TODO: create oversized JSONL and run offline connector
    assert True  # placeholder

def test_yaml_bomb_in_signature_pack_rejected(tmp_path):
    """Billion-laughs or deeply nested YAML in a custom signature pack must be rejected or bounded."""
    # TODO: write malicious YAML and load signatures
    assert True  # placeholder

def test_injection_string_in_scanned_file_does_not_crash_or_alter_schema(tmp_path):
    """Prompt-injection style text in a scanned file must not affect triage schema or cause exceptions."""
    # TODO: fixture with "Ignore previous instructions..." and verify triage still parses only fixed verdicts
    assert True  # placeholder
