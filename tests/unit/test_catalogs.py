"""Catalog-like data files: which files only list technologies, and how that is reported."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from shadowscan.connectors.code.catalogs import (
    CATALOG_MIN_SIGNATURES,
    MAX_CATALOG_FILES,
    catalog_files,
    catalog_metadata,
    configuration_document,
    project_catalog_files,
)
from shadowscan.signatures import Match, Signal, Signature

SIGNAL_KEYS = {
    "domain": {"values": ["example.test"]},
    "env": {"names": ["EXAMPLE_KEY"]},
    "name": {"patterns": ["Example"]},
    "dependency": {"names": ["example"]},
    "import": {"patterns": ["example"]},
    "code": {"patterns": ["example"]},
    "file": {"globs": ["example"]},
    "image": {"patterns": ["example"]},
    "iac": {"values": ["example"]},
    "model": {"patterns": ["example"]},
    "secret": {"patterns": ["example"]},
}


def mention(rel: str, signal_type: str = "domain", number: int = 0, category: str = "provider"):
    """One observation of the number-th synthetic signature, in the shape _Project stores them."""
    signal = Signal(type=signal_type, weight=0.9, **SIGNAL_KEYS[signal_type])
    signature = Signature(id=f"{category}.test{number}", name="Test", category=category, signals=[signal])
    return Match(signature, signal, "example.test", 0.9, 1), rel, None


def products(rel: str, count: int, signal_type: str = "domain"):
    return [mention(rel, signal_type, number) for number in range(count)]


def test_the_threshold_is_four_distinct_signatures():
    assert CATALOG_MIN_SIGNATURES == 4
    assert catalog_files(products("data/vendors.yaml", 3)) == frozenset()
    assert catalog_files(products("data/vendors.yaml", 4)) == {"data/vendors.yaml"}
    # Several observations of one signature are one product, however many.
    assert catalog_files([mention("data/vendors.yaml", "domain", 0)] * 10) == frozenset()
    # Domain, variable and name mentions of one product count once.
    mixed = [
        mention("data/vendors.yaml", kind, number % 3) for number, kind in enumerate(["domain", "env"] * 6)
    ]
    assert catalog_files(mixed) == frozenset()


@pytest.mark.parametrize(
    "rel",
    [
        "net/blocklist.yaml",
        "net/blocklist.yml",
        "net/blocklist.json",
        "net/blocklist.JSON",
        "net/blocklist.jsonc",
        "net/blocklist.toml",
        "net/blocklist.ini",
        "net/blocklist.cfg",
        "net/blocklist.conf",
        "net/blocklist.properties",
        "net/blocklist.xml",
        "net/blocklist.csv",
        "net/blocklist.txt",
        "docs/vendors.md",
        "docs/vendors.mdx",
    ],
)
def test_data_and_prose_formats_can_be_catalogs(rel):
    assert catalog_files(products(rel, 5)) == {rel}


@pytest.mark.parametrize(
    "rel",
    [
        "router/providers.go",
        "app/providers.py",
        "Providers.java",
        "src/providers.ts",
        "run.sh",
        "notes.ipynb",
    ],
)
def test_source_code_that_lists_providers_is_multi_provider_code(rel):
    assert catalog_files(products(rel, 8)) == frozenset()


@pytest.mark.parametrize(
    "rel",
    [
        ".env",
        ".env.example",
        "config/.env.sample",
        "docker-compose.yml",
        "deploy/compose.yaml",
        "chart/values.yaml",
        "Dockerfile",
        "serverless.yml",
        ".github/workflows/ci.yml",
        "requirements.txt",
        "package.json",
        "infra/main.tf",
    ],
)
def test_manifests_declare_the_environment_they_do_not_list_it(rel):
    assert catalog_files(products(rel, 8, "env")) == frozenset()


@pytest.mark.parametrize(
    "rel",
    [
        ".gitlab-ci.yml",
        "ci/.gitlab-ci.yaml",
        ".gitlab/ci/eval.yml",
        "azure-pipelines.yml",
        "build/azure-pipelines.yaml",
        "bitbucket-pipelines.yml",
        ".circleci/config.yml",
        ".buildkite/pipeline.yml",
        "buildspec.yml",
        ".travis.yml",
        ".drone.yml",
        "src/main/resources/application.yml",
        "src/main/resources/application-prod.yaml",
        "config/application.properties",
        "src/main/resources/bootstrap.yml",
    ],
)
def test_ci_pipelines_and_service_configuration_are_never_catalogs(rel):
    # A pipeline or a Spring profile hands variables and endpoints to what it runs.
    assert catalog_files(products(rel, 8, "env")) == frozenset()


def test_a_configuration_document_is_never_a_catalog():
    observations = [*products("k8s/deployment.yaml", 6, "env"), *products("net/blocklist.yaml", 5)]
    assert catalog_files(observations) == {"k8s/deployment.yaml", "net/blocklist.yaml"}
    assert catalog_files(observations, configuration={"k8s/deployment.yaml"}) == {"net/blocklist.yaml"}
    # Configuration also counts as evidence beside small mention-only data files.
    small = mention("identity/policies.yaml", "domain", 20)
    assert catalog_files([*observations, small], configuration={"k8s/deployment.yaml"}) == {
        "net/blocklist.yaml"
    }


KUBERNETES_STREAM = (
    "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: llm\ndata:\n"
    "  OPENAI_BASE_URL: https://api.openai.com/v1\n---\napiVersion: v1\nkind: Service\n"
)


@pytest.mark.parametrize(
    "rel,text,parsed,names",
    [
        ("k8s/configmap.yaml", KUBERNETES_STREAM, None, set()),
        ("k8s/pod.json", "{}", {"apiVersion": "v1", "kind": "Pod", "spec": {}}, set()),
        ("ecs/task.json", "{}", {"family": "bot", "containerDefinitions": []}, set()),
        ("ecs/describe.json", "{}", {"taskDefinition": {"containerDefinitions": []}}, set()),
        (
            "deploy/service.json",
            "{}",
            {"containers": [{"env": [{"name": "OPENAI_API_KEY", "value": ""}]}]},
            {"OPENAI_API_KEY"},
        ),
        ("deploy/job.yaml", "", {"job": {"Environment": {"OPENAI_API_KEY": "x"}}}, {"OPENAI_API_KEY"}),
        ("deploy/job.yaml", "", {"job": {"variables": {"OPENAI_API_KEY": "x"}}}, {"OPENAI_API_KEY"}),
        ("deploy/render.yaml", "", {"services": [{"envVars": [{"key": "GROQ_API_KEY"}]}]}, {"GROQ_API_KEY"}),
        ("deploy/run.yaml", "", {"env": ["OPENAI_API_KEY=${OPENAI_API_KEY}"]}, {"OPENAI_API_KEY"}),
    ],
    ids=[
        "kubernetes-stream",
        "kubernetes-json",
        "ecs",
        "ecs-describe",
        "env-list",
        "environment",
        "variables",
        "env-vars",
        "env-strings",
    ],
)
def test_configuration_documents_are_recognized(rel, text, parsed, names):
    assert configuration_document(rel, text, parsed, names)


@pytest.mark.parametrize(
    "rel,text,parsed,names",
    [
        # A vendor policy names each product's variable as a value, not as configuration.
        (
            "governance/vendors.yaml",
            "",
            {"vendors": [{"name": "OpenAI", "host": "api.openai.com", "key_env": "OPENAI_API_KEY"}]},
            {"OPENAI_API_KEY"},
        ),
        ("net/blocklist.yaml", "blocked:\n  - api.openai.com\n", {"blocked": ["api.openai.com"]}, set()),
        # The variable a file configures must be one it names, and a key in prose is not a resource.
        ("deploy/job.yaml", "", {"env": {"PATH": "/bin"}}, {"OPENAI_API_KEY"}),
        ("docs/kinds.yaml", "notes: |\n  apiVersion: v1\n  kind: Pod\n", None, set()),
        # Source code and manifests are never catalogs, so they need no exemption.
        ("app/settings.py", "", {"env": {"OPENAI_API_KEY": ""}}, {"OPENAI_API_KEY"}),
    ],
    ids=["vendor-policy", "blocklist", "other-variable", "indented-keys", "source"],
)
def test_lists_are_not_configuration_documents(rel, text, parsed, names):
    assert not configuration_document(rel, text, parsed, names)


@pytest.mark.parametrize(
    "anchor", ["dependency", "import", "code", "file", "image", "iac", "model", "secret"]
)
def test_a_structural_anchor_keeps_a_file_a_configuration(anchor):
    observations = [*products("config/gateway.yaml", 6), mention("config/gateway.yaml", anchor, 99)]
    assert catalog_files(observations) == frozenset()


def test_heuristic_and_policy_matches_neither_count_nor_disqualify():
    rel = "net/blocklist.yaml"
    ignored = [
        mention(rel, "env", 10, category="heuristic"),
        mention(rel, "domain", 11, category="policy"),
    ]
    # They are not products of the list: three products and two extras stay below the threshold.
    assert catalog_files([*products(rel, 3), *ignored]) == frozenset()
    # They are not anchors either: a heuristic code idiom or a policy match does not make the file configuration.
    anchors = [mention(rel, "code", 12, category="heuristic"), mention(rel, "code", 13, category="policy")]
    assert catalog_files([*products(rel, 4), *anchors]) == {rel}


def test_a_catalog_is_judged_per_file():
    observations = [*products("a.yaml", 2), *products("b.yaml", 4), *products("src/app.py", 1)]
    assert catalog_files(observations) == {"b.yaml"}


def test_small_data_files_join_a_catalog_only_when_no_code_names_a_technology():
    small = [mention("identity/policies.yaml", "domain", 20), *products("platforms/cloud.yaml", 3)]
    big = products("frameworks/orchestrators.yaml", 16)
    # In a project of data files alone, nothing uses the technologies they name.
    assert catalog_files([*big, *small]) == {
        "frameworks/orchestrators.yaml",
        "identity/policies.yaml",
        "platforms/cloud.yaml",
    }
    # Without a catalog the small files are ordinary configuration.
    assert catalog_files(small) == frozenset()
    # A file of code, or a dependency, names a technology the project may use.
    assert catalog_files([*big, *small, mention("src/app.py", "import", 30)]) == {
        "frameworks/orchestrators.yaml"
    }
    assert catalog_files([*big, *small, mention("pyproject.toml", "dependency", 31)]) == {
        "frameworks/orchestrators.yaml"
    }
    # So does a single configuration file with a base URL and a catalog beside it.
    assert catalog_files([*big, mention("config/app.json", "file", 32)]) == {"frameworks/orchestrators.yaml"}


def test_project_catalogs_include_coding_agent_matches():
    proj = SimpleNamespace(
        matches=products("net/allow.yaml", 2),
        coding_agent_matches={
            "coding-agent.one": [mention("net/allow.yaml", "domain", 40, "coding-agent")],
            "coding-agent.two": [mention("net/allow.yaml", "domain", 41, "coding-agent")],
        },
    )
    assert project_catalog_files(proj) == {"net/allow.yaml"}
    proj.coding_agent_matches = {}
    assert project_catalog_files(proj) == frozenset()


def test_catalog_metadata_is_sorted_and_bounded():
    files = frozenset(f"data/list-{number:03}.yaml" for number in range(MAX_CATALOG_FILES + 5))
    metadata = catalog_metadata(files)
    assert metadata["min_signatures"] == CATALOG_MIN_SIGNATURES
    assert metadata["files"] == sorted(files)[:MAX_CATALOG_FILES] and len(metadata["files"]) == 20
