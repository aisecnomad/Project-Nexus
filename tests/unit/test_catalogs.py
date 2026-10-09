"""Catalog-like data files: which files only list technologies, and how that is reported."""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from types import SimpleNamespace

import pytest

from shadowscan.connectors.code.catalogs import (
    CATALOG_MIN_SIGNATURES,
    MAX_ASSIGNMENT_LINES,
    MAX_CATALOG_FILES,
    MAX_PATH_LITERALS,
    MAX_REFERENCES_PER_FILE,
    catalog_files,
    catalog_metadata,
    configuration_document,
    project_catalog_files,
    referenced_data_files,
    references_could_change,
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


def model_id(rel: str, number: int, data_mention: bool):
    """A model-identifier match, flagged ``data_mention`` when the connector found it in a data file."""
    match, rel, snippet = mention(rel, "model", number)
    if data_mention:
        match.extra["data_mention"] = True
    return match, rel, snippet


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


# A policy entry per variable, as a mapping value in any style.
POLICY_MAP = {
    "OPENAI_API_KEY": {"vendor": "OpenAI", "rotate_days": 90},
    "ANTHROPIC_API_KEY": {"vendor": "Anthropic", "rotate_days": 90},
}

# A credential file assigns the variables it names, on lines of its own; so do
# a settings document keyed by them and a development container's environment.
SAMPLE_KEYS = (
    "# Copy to keys.cfg and fill in\nOPENAI_API_KEY=sk-example\n"
    'export ANTHROPIC_API_KEY="x"\nTOGETHER_API_KEY = y\n[azure]\nAZURE_OPENAI_API_KEY: z\n'
)


@pytest.mark.parametrize(
    "rel,text,parsed,names",
    [
        ("keys/sample_keys.cfg", SAMPLE_KEYS, None, {"OPENAI_API_KEY"}),
        ("keys/sample_keys.cfg", SAMPLE_KEYS, None, {"ANTHROPIC_API_KEY"}),
        ("keys/sample_keys.cfg", SAMPLE_KEYS, None, {"TOGETHER_API_KEY"}),
        ("keys/sample_keys.cfg", SAMPLE_KEYS, None, {"AZURE_OPENAI_API_KEY"}),
        ("keys/llm.properties", "openai.key=x\nOPENAI_API_KEY: sk\n", None, {"OPENAI_API_KEY"}),
        ("keys/keys.json", '{\n  "OPENAI_API_KEY": "sk-",\n}', None, {"OPENAI_API_KEY"}),
        ("keys/keys.yaml", "OPENAI_API_KEY: sk\n", {"OPENAI_API_KEY": "sk"}, {"OPENAI_API_KEY"}),
        ("settings.json", "{}", {"OPENAI_API_KEY": "sk-..."}, {"OPENAI_API_KEY"}),
        ("settings.yaml", "", {"llm": {"keys": {"GROQ_API_KEY": "gsk-example"}}}, {"GROQ_API_KEY"}),
        ("settings.toml", "", {"providers": [{"MISTRAL_API_KEY": True}]}, {"MISTRAL_API_KEY"}),
        (
            "devcontainer.json",
            "{}",
            {"containerEnv": {"OPENAI_API_KEY": "${localEnv:OPENAI_API_KEY}"}},
            {"OPENAI_API_KEY"},
        ),
        ("devcontainer.json", "{}", {"remoteEnv": {"ANTHROPIC_API_KEY": ""}}, {"ANTHROPIC_API_KEY"}),
    ],
    ids=[
        "dotenv-line",
        "export-line",
        "spaced-line",
        "colon-line",
        "properties",
        "unparsed-json",
        "yaml-key",
        "json-key",
        "nested-key",
        "list-item-key",
        "container-env",
        "remote-env",
    ],
)
def test_credential_assignments_make_a_data_file_configuration(rel, text, parsed, names):
    assert configuration_document(rel, text, parsed, names)


@pytest.mark.parametrize(
    "rel,text,parsed,names",
    [
        # A vendor policy names each product's variable as a value, not as configuration.
        (
            "governance/vendors.yaml",
            "vendors:\n  - name: OpenAI\n    host: api.openai.com\n    key_env: OPENAI_API_KEY\n",
            {"vendors": [{"name": "OpenAI", "host": "api.openai.com", "key_env": "OPENAI_API_KEY"}]},
            {"OPENAI_API_KEY"},
        ),
        # A policy map keyed by variable assigns nothing: the key opens a mapping,
        # on the next line or on the same one, in YAML, JSON (parsed or not) or TOML.
        (
            "governance/keys.yaml",
            "OPENAI_API_KEY:  # reviewed\n  vendor: OpenAI\n",
            {"OPENAI_API_KEY": {"vendor": "OpenAI"}},
            {"OPENAI_API_KEY"},
        ),
        (
            "governance/keys.yaml",
            "OPENAI_API_KEY: {vendor: OpenAI, rotate_days: 90}\n",
            {"OPENAI_API_KEY": {"vendor": "OpenAI", "rotate_days": 90}},
            {"OPENAI_API_KEY"},
        ),
        (
            "governance/keys.json",
            json.dumps(POLICY_MAP, indent=2),
            POLICY_MAP,
            {"OPENAI_API_KEY"},
        ),
        (
            "governance/keys.jsonc",
            "// reviewed\n" + json.dumps(POLICY_MAP, indent=2),
            None,
            {"OPENAI_API_KEY"},
        ),
        (
            "governance/keys.toml",
            'OPENAI_API_KEY = { vendor = "OpenAI", rotate_days = 90 }\n',
            {"OPENAI_API_KEY": {"vendor": "OpenAI", "rotate_days": 90}},
            {"OPENAI_API_KEY"},
        ),
        (
            "governance/stages.json",
            '{\n  "OPENAI_API_KEY": ["prod", "staging"]\n}',
            {"OPENAI_API_KEY": ["prod", "staging"]},
            {"OPENAI_API_KEY"},
        ),
        # A list of names, or a name without a value, is not an assignment in any format.
        ("governance/required.json", '["OPENAI_API_KEY"]', ["OPENAI_API_KEY"], {"OPENAI_API_KEY"}),
        ("governance/keys.ini", "[providers]\nOPENAI_API_KEY\nGROQ_API_KEY\n", None, {"OPENAI_API_KEY"}),
        (
            "governance/required.yaml",
            "required_env:\n  OPENAI_API_KEY:\n  GROQ_API_KEY:\n",
            {"required_env": {"OPENAI_API_KEY": None, "GROQ_API_KEY": None}},
            {"OPENAI_API_KEY"},
        ),
        ("governance/required.json", "{}", {"OPENAI_API_KEY": None}, {"OPENAI_API_KEY"}),
        ("governance/keys.cfg", "OPENAI_ORG=acme\n", None, {"OPENAI_API_KEY"}),
        ("net/blocklist.yaml", "blocked:\n  - api.openai.com\n", {"blocked": ["api.openai.com"]}, set()),
        # The variable a file configures must be one it names, and a key in prose is not a resource.
        ("deploy/job.yaml", "", {"env": {"PATH": "/bin"}}, {"OPENAI_API_KEY"}),
        ("docs/kinds.yaml", "notes: |\n  apiVersion: v1\n  kind: Pod\n", None, set()),
        # Source code and manifests are never catalogs, so they need no exemption.
        ("app/settings.py", "", {"env": {"OPENAI_API_KEY": ""}}, {"OPENAI_API_KEY"}),
        ("app/settings.py", "OPENAI_API_KEY=x\n", None, {"OPENAI_API_KEY"}),
    ],
    ids=[
        "vendor-policy",
        "policy-map",
        "policy-map-flow",
        "policy-map-json",
        "policy-map-unparsed-json",
        "policy-map-toml",
        "list-value",
        "name-list",
        "names-without-values",
        "bare-keys",
        "null-value",
        "other-assignment",
        "blocklist",
        "other-variable",
        "indented-keys",
        "source",
        "source-line",
    ],
)
def test_lists_are_not_configuration_documents(rel, text, parsed, names):
    assert not configuration_document(rel, text, parsed, names)


def test_the_assignment_pass_is_bounded_per_file():
    names = {"OPENAI_API_KEY"}
    # Lower-case keys, the bulk of a properties or INI file, are not variable
    # names and cost no match: a large file is still read to its last line.
    big = "openai.timeout=30\n" * 30_000 + "OPENAI_API_KEY=sk-example\n"
    assert configuration_document("etc/llm.properties", big, None, names)
    # A truncated negative classification must disclose the unread assignments.
    within = "KEY_X=1\n" * (MAX_ASSIGNMENT_LINES - 1) + "OPENAI_API_KEY=sk-example\n"
    assert configuration_document("etc/keys.cfg", within, None, names)
    beyond = "KEY_X=1\n" * (MAX_ASSIGNMENT_LINES * 50) + "OPENAI_API_KEY=sk-example\n"
    limits = []
    assert not configuration_document("etc/keys.cfg", beyond, None, names, limits=limits)
    assert limits == ["catalog assignment line limit exceeded; later assignments were not read"]


@pytest.mark.parametrize(
    "rel",
    [
        ".devcontainer/sample_keys.cfg",
        ".devcontainer/devcontainer.json",
        "examples/agent/.devcontainer/keys.cfg",
        "config/llm.yaml",
        "Config/llm.yaml",
        "conf/providers.toml",
        "settings/models.json",
        "config/vendors.md",
    ],
)
def test_configuration_directories_hold_configuration_not_catalogs(rel):
    # A development container's files, and a top-level configuration directory,
    # configure the workspace or the service however many products they name.
    assert catalog_files(products(rel, 8, "env")) == frozenset()
    assert catalog_files(products(rel, 8)) == frozenset()
    if not rel.endswith(".md"):
        assert configuration_document(rel, "", None, set())


@pytest.mark.parametrize(
    "rel",
    [
        "src/main/resources/config/vendors.yaml",
        "tests/config/blocklist.yaml",
        "proxy/settings/blocklist.yaml",
    ],
)
def test_a_deeper_configuration_directory_is_not_exempt(rel):
    assert catalog_files(products(rel, 8)) == {rel}
    assert not configuration_document(rel, "", None, set())


def test_a_projects_own_configuration_directory_is_configuration():
    rel = "services/router/config/llm.yaml"
    assert catalog_files(products(rel, 8), root="services/router") == frozenset()
    assert configuration_document(rel, "", None, set(), root="services/router")
    # Relative to another project, or to the scan root, config/ is two levels down.
    assert catalog_files(products(rel, 8), root="services") == {rel}
    assert catalog_files(products(rel, 8)) == {rel}
    assert not configuration_document(rel, "", None, set())


@pytest.mark.parametrize(
    "text,expected",
    [
        (
            'settings = yaml.safe_load(open("aider/resources/model-settings.yml"))',
            {"aider/resources/model-settings.yml", "model-settings.yml"},
        ),
        (
            'const OVERRIDES: &str = include_str!("../provider_catalog_overrides.json");',
            {"provider_catalog_overrides.json"},
        ),
        (
            'source "$HOME/.devcontainer/sample_keys.cfg"\n',
            {"home/.devcontainer/sample_keys.cfg", "sample_keys.cfg"},
        ),
        ('path = f"{root}/Config/Models.TOML"', {"config/models.toml", "models.toml"}),
        (r'p = Path(r"configs\providers.ini")', {"configs/providers.ini", "providers.ini"}),
        ("load(`./data/routes.json5`)", {"data/routes.json5", "routes.json5"}),
        ("cfg = ini.read('etc/../keys.properties')", {"keys.properties"}),
        ('SCHEMA = "https://example.test/schemas/config.json"', set()),
        ('name = "models"  # see models.yaml', set()),
        ("x = 'prose with a .json suffix'", set()),
        ('long = "' + "a" * 201 + '.yaml"', set()),
        ('module = "settings.py"; page = "index.html"', set()),
        ('backup = "keys.json.bak"; pattern = "*.yamlx"', set()),
    ],
    ids=[
        "python-open",
        "rust-include",
        "shell-source",
        "f-string-tail",
        "windows-raw",
        "template-literal",
        "parent-segment",
        "url",
        "comment",
        "prose",
        "overlong",
        "other-suffixes",
        "suffix-not-last",
    ],
)
def test_referenced_data_files_collects_quoted_path_literals(text, expected):
    assert referenced_data_files(text) == expected


def test_referenced_data_files_are_bounded_per_file():
    text = "".join(f'load("file-{number}.json")\n' for number in range(MAX_REFERENCES_PER_FILE))
    limits = []
    assert len(referenced_data_files(text, limits=limits)) == MAX_REFERENCES_PER_FILE
    assert limits == []
    assert len(referenced_data_files(text + 'load("late.json")\n', limits=limits)) == MAX_REFERENCES_PER_FILE
    assert limits == ["catalog data-file reference limit exceeded; later references were not read"]
    # Literals without a data suffix cost no match, however many a bundle holds.
    assert referenced_data_files("x = \"abc\"; y = 'def'\n" * 50_000) == set()
    # The bounded pass discloses unread literals instead of claiming completeness.
    repeated = 'load("a.json")\n' * (MAX_PATH_LITERALS * 250)
    assert referenced_data_files(repeated) == {"a.json"}
    limits = []
    assert referenced_data_files('load("a.json")\n' * MAX_PATH_LITERALS, limits=limits) == {"a.json"}
    assert limits == []
    assert referenced_data_files(
        'load("a.json")\n' * MAX_PATH_LITERALS + 'load("late.json")\n', limits=limits
    ) == {"a.json"}
    assert limits == ["catalog data-file reference literal limit exceeded; later literals were not read"]


def test_truncated_references_matter_only_for_a_catalog_they_could_exempt():
    # References lift the discount of a data file outside documentation and
    # website directories; nothing else can change when one is unread.
    assert not references_could_change(frozenset())
    assert not references_could_change(frozenset({"docs/providers.yaml", "website/_data/models.yml"}))
    assert references_could_change(frozenset({"docs/providers.yaml", "config/providers.json"}))
    # Nor is a deny list exempted by a reference: an unread one changes nothing there either.
    assert not references_could_change(frozenset({"blocklist.yaml", "config/deny_list.json"}))
    assert references_could_change(frozenset({"blocklist.yaml", "providers.json"}))


def test_a_data_file_the_projects_code_loads_is_configuration():
    rel = "aider/resources/model-settings.yml"
    assert catalog_files(products(rel, 8)) == {rel}
    assert catalog_files(products(rel, 8), referenced={"model-settings.yml"}) == frozenset()
    assert catalog_files(products(rel, 8), referenced={"resources/model-settings.yml"}) == frozenset()
    assert catalog_files(products(rel, 8), referenced=["Model-Settings.yml".lower()]) == frozenset()
    # A longer path that does not end the file's own path names another file.
    assert catalog_files(products(rel, 8), referenced={"other/model-settings.yml"}) == {rel}
    assert catalog_files(products(rel, 8), referenced={"settings.yml"}) == {rel}


@pytest.mark.parametrize(
    "rel",
    [
        "aider/website/_data/edit_leaderboard.yml",
        "docs/providers.yaml",
        "doc/pricing.json",
        "site/gallery.json",
        "blog/_posts/vendors.yml",
        "web/_includes/models.csv",
    ],
)
def test_documentation_and_website_data_stay_catalogs_when_a_script_names_them(rel):
    name = rel.rsplit("/", 1)[-1]
    assert catalog_files(products(rel, 8), referenced={name, rel}) == {rel}


def test_a_loaded_data_file_keeps_small_neighbours_out_of_the_catalog():
    big = products("net/blocklist.yaml", 8)
    small = products("app/providers.yaml", 2)
    assert catalog_files([*big, *small]) == {"net/blocklist.yaml", "app/providers.yaml"}
    assert catalog_files([*big, *small], referenced={"providers.yaml"}) == {"net/blocklist.yaml"}


def test_model_identifiers_found_in_data_files_are_mentions():
    rel = "website/_data/edit_leaderboard.yml"
    leaderboard = [model_id(rel, number, data_mention=True) for number in range(8)]
    assert catalog_files(leaderboard) == {rel}
    assert catalog_files([*leaderboard, *products(rel, 2)]) == {rel}
    # A model id in a data file without the flag, or one a manifest or IaC file selects, anchors.
    assert catalog_files([*products(rel, 6), model_id(rel, 99, data_mention=False)]) == frozenset()
    assert (
        catalog_files([model_id("infra/main.tf", number, data_mention=True) for number in range(8)])
        == frozenset()
    )


@pytest.mark.parametrize(
    "anchor", ["dependency", "import", "code", "file", "image", "iac", "model", "secret"]
)
def test_a_structural_anchor_keeps_a_file_a_configuration(anchor):
    observations = [*products("router/gateway.yaml", 6), mention("router/gateway.yaml", anchor, 99)]
    assert catalog_files(observations) == frozenset()


def test_heuristic_and_policy_matches_neither_count_nor_disqualify():
    rel = "net/services.yaml"
    ignored = [
        mention(rel, "env", 10, category="heuristic"),
        mention(rel, "domain", 11, category="policy"),
    ]
    # They are not products of the list: three products and two extras stay below the threshold.
    assert catalog_files([*products(rel, 3), *ignored]) == frozenset()
    # They are not anchors either: a heuristic code idiom or a policy match does not make the file configuration.
    anchors = [mention(rel, "code", 12, category="heuristic"), mention(rel, "code", 13, category="policy")]
    assert catalog_files([*products(rel, 4), *anchors]) == {rel}


def test_policy_filename_is_catalog_below_threshold():
    rel = "net/blocklist.yaml"
    assert catalog_files([*products(rel, 3)]) == {rel}
    assert catalog_files([*products(rel, 1)]) == {rel}
    assert catalog_files([*products("config/denylist.yaml", 2)]) == {"config/denylist.yaml"}
    assert catalog_files([*products("config/services.yaml", 3)]) == frozenset()


@pytest.mark.parametrize(
    "rel",
    [
        # An allowlist or egress policy permits the traffic it names: evidence of use.
        "proxy/egress_allowlist.yaml",
        "proxy/whitelist.json",
        "net/ingress.yaml",
        "net/egress.yaml",
        "config/acl.yaml",
        # Deny words inside other words are not deny lists.
        "proxy/oracle_endpoints.yaml",
        "config/security_agent.yaml",
        "ui/dropdown.yaml",
        "chain/blockchain.yaml",
        "fab/wafer.yaml",
        "infra/firewalls.yaml",
        # A firewall or WAF rule set, or a default-deny policy, permits traffic
        # (often to exactly the hosts it names), so "block" or "deny" alone is no list.
        "gw/Firewall.yml",
        "infra/firewall-rules.json",
        "edge/waf.rules.yaml",
        "net/default-deny.yaml",
        "net/deny_hosts.json",
        "x/BLOCK.txt",
    ],
)
def test_only_whole_deny_list_words_make_a_small_file_a_catalog(rel):
    assert catalog_files(products(rel, 2)) == frozenset()


@pytest.mark.parametrize(
    "rel",
    [
        "proxy/ai-blocklist.yaml",
        "net/DenyList.json",
        "x/BLACKLIST.txt",
        # The same nouns spelled as two words.
        "net/deny_list.json",
        "proxy/ai-block-list.yaml",
        "x/Black.List.txt",
    ],
)
def test_whole_deny_list_words_in_any_case_make_a_small_file_a_catalog(rel):
    assert catalog_files(products(rel, 2)) == {rel}


def test_a_deny_list_name_outweighs_location_and_loading_not_an_assignment():
    # A proxy keeps its deny list beside its configuration and loads it by name.
    for rel in ("config/blocklist.yaml", ".devcontainer/deny_list.json", "net/blocklist.yaml"):
        assert catalog_files(products(rel, 2)) == {rel}
        assert catalog_files(products(rel, 2), referenced={PurePosixPath(rel).name}) == {rel}
        assert not configuration_document(rel, "", None, set())
    # An ordinary file there stays configuration.
    assert catalog_files(products("config/vendors.yaml", 8)) == frozenset()
    assert catalog_files(products("net/vendors.yaml", 8), referenced={"vendors.yaml"}) == frozenset()
    # A loaded deny list is a list, so a small unloaded neighbour joins it; loaded, it does not.
    neighbour = mention("upstreams/providers.yaml", "domain", 20)
    loaded = {"blocklist.yaml"}
    assert catalog_files([*products("blocklist.yaml", 2), neighbour], referenced=loaded) == {
        "blocklist.yaml",
        "upstreams/providers.yaml",
    }
    assert catalog_files(
        [*products("blocklist.yaml", 2), neighbour], referenced={*loaded, "providers.yaml"}
    ) == {"blocklist.yaml"}
    # A document that assigns the variables it names, or deploys a resource, stays configuration.
    rel = "config/denylist.cfg"
    assert configuration_document(rel, "OPENAI_API_KEY=sk-example\n", None, {"OPENAI_API_KEY"})
    assert catalog_files(products(rel, 2, "env"), configuration={rel}) == frozenset()
    resource = "apiVersion: v1\nkind: ConfigMap\n"
    assert configuration_document("config/blocklist.yaml", resource, None, set())


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
    assert catalog_files([*big, mention("router/app.json", "file", 32)]) == {"frameworks/orchestrators.yaml"}


def test_project_catalogs_include_coding_agent_matches():
    proj = SimpleNamespace(
        root=".",
        matches=products("net/allow.yaml", 2),
        coding_agent_matches={
            "coding-agent.one": [mention("net/allow.yaml", "domain", 40, "coding-agent")],
            "coding-agent.two": [mention("net/allow.yaml", "domain", 41, "coding-agent")],
        },
    )
    assert project_catalog_files(proj) == {"net/allow.yaml"}
    assert project_catalog_files(proj, referenced={"allow.yaml"}) == frozenset()
    proj.coding_agent_matches = {}
    assert project_catalog_files(proj) == frozenset()


def test_project_catalogs_are_judged_relative_to_the_project_root():
    rel = "services/router/config/llm.yaml"
    proj = SimpleNamespace(root="services/router", matches=products(rel, 8), coding_agent_matches={})
    assert project_catalog_files(proj) == frozenset()
    proj.root = "."
    assert project_catalog_files(proj) == {rel}


def test_catalog_metadata_is_sorted_and_bounded():
    files = frozenset(f"data/list-{number:03}.yaml" for number in range(MAX_CATALOG_FILES + 5))
    metadata = catalog_metadata(files)
    assert metadata["min_signatures"] == CATALOG_MIN_SIGNATURES
    assert metadata["files"] == sorted(files)[:MAX_CATALOG_FILES] and len(metadata["files"]) == 20
