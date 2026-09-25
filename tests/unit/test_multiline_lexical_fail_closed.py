"""Ambiguous multiline source must not turn a partial scan into a clean result."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.code.source_ranges import noncode_ranges


@pytest.mark.parametrize(
    ("filename", "source", "phantom_framework"),
    [
        (
            "sample.rb",
            "docs = <<DOC\nAiServices.builder(example)\n",
            "framework.langchain4j",
        ),
        (
            "sample.php",
            "<?php\n$docs = <<<DOC\nAiServices.builder(example)\n",
            "framework.langchain4j",
        ),
        (
            "sample.rb",
            "docs = <<DOC\n#{AiServices.builder(example)}\nDOC\n",
            "framework.langchain4j",
        ),
        (
            "sample.php",
            "<?php\n$docs = <<<DOC\n{$example} AiServices.builder(example)\nDOC;\n",
            "framework.langchain4j",
        ),
        (
            "sample.rs",
            'let docs = r#"AgentBuilder::new(example)\n',
            "framework.rig",
        ),
        (
            "sample.rb",
            "docs = %q{AiServices.builder(example)\n",
            "framework.langchain4j",
        ),
        (
            "sample.rb",
            "docs = %Q{#{AiServices.builder(example)}}\n",
            "framework.langchain4j",
        ),
        (
            "sample.rb",
            "docs = %Q|#{AiServices.builder(example)}|\n",
            "framework.langchain4j",
        ),
    ],
    ids=[
        "ruby-unclosed-heredoc",
        "php-unclosed-heredoc",
        "ruby-interpolated-heredoc",
        "php-interpolated-heredoc",
        "rust-unclosed-raw-string",
        "ruby-unclosed-percent-string",
        "ruby-interpolated-percent-string",
        "ruby-interpolated-nonpaired-percent-string",
    ],
)
def test_ambiguous_multiline_source_retains_neighbor_and_fails_closed(
    tmp_path, filename: str, source: str, phantom_framework: str,
):
    (tmp_path / filename).write_text(source, encoding="utf-8")
    (tmp_path / "real.py").write_text(
        'from crewai import Agent\nagent = Agent(role="writer", goal="draft")\n',
        encoding="utf-8",
    )

    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])

    assert result.exit_code == 3, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["complete"] is False
    assert any(filename in error and "incomplete source lexical analysis" in error
               for stat in report["stats"] for error in stat["errors"])
    assert any(finding["kind"] == "agent" and "framework.crewai" in finding["frameworks"]
               for finding in report["findings"])
    assert all(phantom_framework not in finding["frameworks"] for finding in report["findings"])


@pytest.mark.parametrize(
    "literal",
    [
        "%q{AiServices.builder(fake)}",
        "%q[AiServices.builder(fake)]",
        "%q(AiServices.builder(fake))",
        "%q<AiServices.builder(fake)>",
        "%q|AiServices.builder(fake)|",
        "%q!AiServices.builder(fake)!",
        "%q/AiServices.builder(fake)/",
        "%q{outer{AiServices.builder(fake)}tail}",
        "%q{escaped \\} AiServices.builder(fake)}",
        "%q{#{AiServices.builder(fake)}}",
        "%Q{AiServices.builder(fake)}",
        "%Q|AiServices.builder(fake)|",
    ],
)
def test_ruby_percent_literal_does_not_create_agent_or_hide_real_code(tmp_path, literal: str):
    ruby_source = f"docs = {literal}\n"
    spans, incomplete = noncode_ranges(ruby_source, "ruby", ".rb")
    assert not incomplete
    fake_call = ruby_source.index("AiServices.builder")
    assert any(start <= fake_call < end for start, end in spans)
    (tmp_path / "sample.rb").write_text(ruby_source, encoding="utf-8")
    (tmp_path / "real.java").write_text(
        "import dev.langchain4j.service.AiServices;\n"
        "class App { void run() { AiServices.builder(Foo.class); } }\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])

    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["complete"] is True
    agents = [finding for finding in report["findings"] if finding["kind"] == "agent"]
    assert len(agents) == 1
    assert "framework.langchain4j" in agents[0]["frameworks"]
    locations = [evidence["location"] for evidence in agents[0]["evidence"]]
    assert "real.java:2" in locations
    assert not any(location.startswith("sample.rb:") for location in locations)


def test_ruby_modulo_expression_does_not_start_percent_string(tmp_path):
    source = "result = counter % q | AiServices.builder(real)\n"
    spans, incomplete = noncode_ranges(source, "ruby", ".rb")
    assert not incomplete
    call = source.index("AiServices.builder")
    assert not any(start <= call < end for start, end in spans)
    (tmp_path / "sample.rb").write_text(source, encoding="utf-8")
    (tmp_path / "real.java").write_text(
        "import dev.langchain4j.service.AiServices;\n"
        "class App { void run() { AiServices.builder(Foo.class); } }\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json"])

    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["complete"] is True
    agents = [finding for finding in report["findings"] if finding["kind"] == "agent"]
    assert len(agents) == 1
    assert "framework.langchain4j" in agents[0]["frameworks"]
    assert "real.java:2" in [evidence["location"] for evidence in agents[0]["evidence"]]
