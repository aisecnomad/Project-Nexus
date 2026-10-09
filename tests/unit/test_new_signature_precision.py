"""Precision of the Elixir, R, Rust, MLflow gateway and Devin signatures.

General numerical, tensor and Python-bridge libraries, experiment tracking and
generic file names are not LLM usage. The LLM-specific idioms of the same
signatures still match. The evaluation corpus holds the same cases.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.signatures.schema import ECOSYSTEMS

NEGATIVES = {
    "framework.nx-bumblebee": {
        "lib/metrics/stats.ex": (
            "defmodule Metrics.Stats do\n"
            "  import Nx, only: [tensor: 1]\n\n"
            "  def mean(samples), do: samples |> tensor() |> Nx.mean() |> Nx.to_number()\n"
            "end\n"
        ),
    },
    "framework.r-ai": {
        "R/forecast.R": (
            "library(reticulate)\nlibrary(torch)\nlibrary(keras)\n\n"
            'np <- import("numpy")\n'
            "fit <- function(series) np$polyfit(seq_along(series), series, 1L)\n"
        ),
    },
    "framework.rust-ai": {
        "Cargo.toml": (
            '[package]\nname = "filters"\nversion = "0.1.0"\n\n'
            '[dependencies]\ncandle-core = "0.8"\ncandle-nn = "0.8"\n'
        ),
        "src/lib.rs": "use candle_core::{Device, Tensor};\nuse candle_nn::ops::sigmoid;\n",
    },
    "platform.mlflow-ai-gateway": {
        "requirements.txt": "mlflow==3.4.0\nscikit-learn==1.7.2\n",
        "train.py": "import mlflow\n\nwith mlflow.start_run():\n    mlflow.log_metric('accuracy', 0.9)\n",
        "gateway_config.yaml": "routes:\n  - id: orders\n    uri: http://orders:8080\n",
    },
    "coding-agent.devin": {
        "content/authors/devin.md": "# Devin Park\n\nPlatform engineer on the payments team.\n",
    },
}

POSITIVES = {
    "framework.nx-bumblebee": {
        "lib/summarizer.ex": (
            "defmodule Summarizer do\n"
            '  def serving(repo \\\\ {:hf, "facebook/bart-large-cnn"}) do\n'
            "    {:ok, model} = Bumblebee.load_model(repo)\n"
            "    {:ok, tokenizer} = Bumblebee.load_tokenizer(repo)\n"
            "    Bumblebee.Text.generation(model, tokenizer, %{})\n"
            "  end\n"
            "end\n"
        ),
    },
    "framework.r-ai": {
        "R/triage.R": (
            "library(ellmer)\n\n"
            'classify <- function(text) chat_openai(model = "gpt-4o-mini")$chat(text)\n'
        ),
    },
    "framework.rust-ai": {
        "Cargo.toml": '[package]\nname = "local-llm"\nversion = "0.1.0"\n\n[dependencies]\ncandle-transformers = "0.8"\n',
        "src/main.rs": "use candle_transformers::models::llama::Llama;\n",
    },
    "platform.mlflow-ai-gateway": {
        "ask.py": (
            "from mlflow.deployments import get_deploy_client\n\n"
            'client = mlflow.deployments.get_deploy_client("http://gateway:5000")\n'
        ),
    },
    "coding-agent.devin": {
        ".devin/config.json": '{"setup": "npm ci", "test": "npm test"}\n',
    },
}


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _signatures(findings) -> set[str]:
    return {sig for finding in findings for sig in [*finding.frameworks, *finding.model_providers]}


@pytest.mark.parametrize("signature", sorted(NEGATIVES))
def test_general_libraries_and_generic_names_are_not_llm_products(tmp_path: Path, run_connector, signature):
    _write(tmp_path, NEGATIVES[signature])
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors and not ctx.stats.incomplete
    assert signature not in _signatures(findings)


@pytest.mark.parametrize("signature", sorted(POSITIVES))
def test_llm_specific_idioms_of_the_narrowed_signatures_still_match(tmp_path: Path, run_connector, signature):
    _write(tmp_path, POSITIVES[signature])
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors and not ctx.stats.incomplete
    assert signature in _signatures(findings)


def test_no_signature_declares_an_ecosystem_without_a_manifest_parser():
    # No parser reads mix.exs, DESCRIPTION or renv.lock: hex and cran dependency
    # signals could never match.
    assert not {"hex", "cran"} & ECOSYSTEMS
