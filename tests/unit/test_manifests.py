from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from shadowscan.connectors.code.manifests import (
    _LineIndex,
    is_manifest_name,
    manifest_comment_projection,
    parse_manifest,
    parse_requirements,
)
from shadowscan.signatures import SignatureIndex
from shadowscan.signatures import matcher as matcher_module
from shadowscan.signatures.loader import signature_from_dict
from shadowscan.signatures.matcher import MatchTimeoutError


def _deps(rel, text):
    res = parse_manifest(rel, text)
    assert res is not None
    return {(d.ecosystem, d.name) for d in res.deps}, res


def test_requirements_and_pyproject():
    deps, _ = _deps(
        "requirements.txt",
        "langchain>=0.3 # core\nlangchain-openai\n-r base.txt\ngit+https://github.com/openai/swarm.git#egg=swarm\ncrewai[tools]==0.80\n",
    )
    assert ("pypi", "langchain") in deps and ("pypi", "swarm") in deps and ("pypi", "crewai") in deps
    deps, _ = _deps(
        "pyproject.toml",
        '[project]\ndependencies=["google-adk>=1.0", "mcp"]\n[project.optional-dependencies]\ndev=["pytest"]\n[tool.poetry.dependencies]\npython="^3.11"\nstrands-agents="*"\n',
    )
    assert {("pypi", "google-adk"), ("pypi", "mcp"), ("pypi", "strands-agents")} <= deps


def test_package_json_go_cargo_maven_gradle_nuget():
    deps, _ = _deps(
        "package.json",
        '{"dependencies": {"@langchain/langgraph": "^0.2", "ai": "4"}, "devDependencies": {"typescript": "5"}, "scripts": {"mcp": "npx -y @modelcontextprotocol/server-filesystem ."}}',
    )
    assert {
        ("npm", "@langchain/langgraph"),
        ("npm", "ai"),
        ("npm", "@modelcontextprotocol/server-filesystem"),
    } <= deps
    deps, _ = _deps(
        "go.mod",
        "module x\nrequire (\n\tgithub.com/mark3labs/mcp-go v0.8.0\n)\nrequire github.com/tmc/langchaingo v0.1.12\n",
    )
    assert {("go", "github.com/mark3labs/mcp-go"), ("go", "github.com/tmc/langchaingo")} <= deps
    deps, _ = _deps(
        "Cargo.toml", '[dependencies]\nrig-core = "0.5"\ntokio = { version = "1", features = ["full"] }\n'
    )
    assert ("cargo", "rig-core") in deps
    deps, _ = _deps(
        "pom.xml",
        "<project><dependencies><dependency><groupId>dev.langchain4j</groupId><artifactId>langchain4j</artifactId><version>1.0</version></dependency></dependencies></project>",
    )
    assert ("maven", "dev.langchain4j:langchain4j") in deps
    deps, _ = _deps(
        "build.gradle.kts",
        'dependencies {\n    implementation("org.springframework.ai:spring-ai-openai-spring-boot-starter:1.0.0")\n}\n',
    )
    assert ("maven", "org.springframework.ai:spring-ai-openai-spring-boot-starter") in deps
    deps, _ = _deps(
        "Agent.csproj",
        '<Project><ItemGroup><PackageReference Include="Microsoft.Agents.AI" Version="1.0.0" /></ItemGroup></Project>',
    )
    assert ("nuget", "Microsoft.Agents.AI") in deps


def test_dockerfile_compose_and_terraform_artifacts():
    deps, res = _deps(
        "Dockerfile",
        "FROM ghcr.io/berriai/litellm:main\nENV OPENAI_API_KEY=x ANTHROPIC_API_KEY=y\nRUN pip install langchain openai && npm install -g @anthropic-ai/claude-code\n",
    )
    arts = {(a.kind, a.value) for a in res.artifacts}
    assert ("image", "ghcr.io/berriai/litellm:main") in arts and ("env", "OPENAI_API_KEY") in arts
    assert {("pypi", "langchain"), ("pypi", "openai"), ("npm", "@anthropic-ai/claude-code")} <= deps
    _, res = _deps(
        "docker-compose.yml",
        "services:\n  n8n:\n    image: n8nio/n8n\n    environment:\n      - N8N_API_KEY=abc\n",
    )
    arts = {(a.kind, a.value) for a in res.artifacts}
    assert ("image", "n8nio/n8n") in arts and ("env", "N8N_API_KEY") in arts
    _, res = _deps(
        "main.tf",
        'resource "aws_bedrockagent_agent" "ops" {\n  agent_name = "ops-provisioning-04"\n}\nresource "aws_s3_bucket" "b" {}\n',
    )
    iac = [a for a in res.artifacts if a.kind == "iac"]
    assert iac[0].value == "aws_bedrockagent_agent" and iac[0].extra["display_name"] == "ops-provisioning-04"


def test_env_file_and_cloudformation():
    _, res = _deps(".env", "OPENAI_API_KEY=sk-live\n# comment\nexport GEMINI_API_KEY='x'\n")
    names = {a.value for a in res.artifacts}
    assert {"OPENAI_API_KEY", "GEMINI_API_KEY"} <= names
    _, res = _deps(
        "template.yaml",
        "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Agent:\n    Type: AWS::Bedrock::Agent\n",
    )
    assert ("iac", "AWS::Bedrock::Agent") in {(a.kind, a.value) for a in res.artifacts}


def test_non_manifest_returns_none():
    assert parse_manifest("src/app.py", "print('hi')") is None


def test_parallel_manifest_parsing_preserves_all_artifacts():
    compose = "services:\n" + "".join(
        f"  agent{i}:\n    image: ghcr.io/acme/agent:1\n    environment:\n      OPENAI_API_KEY: placeholder\n"
        for i in range(100)
    )
    terraform = "\n".join(
        f'resource "aws_bedrockagent_agent" "agent{i}" {{\n  agent_name = "agent{i}"\n}}' for i in range(100)
    )
    jobs = [("compose.yaml", compose), ("main.tf", terraform)] * 18

    def scan(job):
        result = parse_manifest(*job)
        assert result is not None and not result.errors
        return [
            (artifact.kind, artifact.value, artifact.line, artifact.extra) for artifact in result.artifacts
        ]

    expected = [scan(job) for job in jobs[:2]]
    assert len(expected[0]) == 200 and len(expected[1]) == 100
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(scan, jobs))
    assert results == expected * 18


def test_yaml_artifacts_keep_source_lines_across_chunks():
    lines = ["services:"] + [f"  padding{i}: # {'x' * 55}" for i in range(120)]
    lines += [
        "  -",
        "    OPENAI_API_KEY: example",
        "    image: ghcr.io/acme/agent:1",
        "    uses: actions/checkout@v4",
        "    token: ${{ secrets.CI_TOKEN }}",
    ]
    result = parse_manifest("compose.yaml", "\n".join(lines) + "\n")
    assert result is not None and not result.errors
    assert {(artifact.kind, artifact.value, artifact.line) for artifact in result.artifacts} == {
        ("env", "OPENAI_API_KEY", 123),
        ("image", "ghcr.io/acme/agent:1", 124),
        ("action", "actions/checkout@v4", 125),
        ("secret_ref", "CI_TOKEN", 126),
    }


def _index(pattern="token"):
    return SignatureIndex(
        [
            signature_from_dict(
                {
                    "id": "custom.test",
                    "category": "framework",
                    "signals": [{"type": "code", "patterns": [pattern]}],
                }
            )
        ]
    )


def test_manifest_regex_respects_outer_input_deadline(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(matcher_module.time, "monotonic", lambda: clock[0])
    with pytest.raises(MatchTimeoutError, match="input execution budget"), _index().scan_budget(seconds=0.1):
        clock[0] = 0.2
        parse_manifest("Dockerfile", "FROM python:3.12\n")


@pytest.mark.parametrize("offset, expected", [(0, 1), (1, 1), (2, 2), (3, 2), (4, 3)])
def test_manifest_line_index_matches_original_source_offsets(offset, expected):
    assert _LineIndex("a\nb\nc").at(offset) == expected


def test_vcs_egg_fragments_and_editable_dependencies():
    result = parse_requirements(
        "git+https://github.com/acme/other.git#egg=crewai\n"
        "-e git+https://github.com/acme/other.git@main#egg=langgraph\n"
        "langchain>=0.3 # explanatory comment\n"
    )
    assert {(dep.name, dep.line) for dep in result.deps} == {
        ("crewai", 1),
        ("langgraph", 2),
        ("langchain", 3),
    }


@pytest.mark.parametrize(
    "reference",
    [
        "openai-agents @ https://example.org/distributions/agents-0.1.0.tar.gz",
        "openai-agents[voice] @ https://example.org/downloads/other.whl#sha256=abc123",
        "openai-agents @ git+https://github.com/example/other.git@main#subdirectory=python",
        "openai-agents @ file:///opt/packages/other.whl",
    ],
)
def test_named_requirement_urls_preserve_declared_identity(reference):
    result = parse_requirements("# installation\n" + reference + "\n")
    assert not result.errors
    assert [(dep.ecosystem, dep.name, dep.spec, dep.line) for dep in result.deps] == [
        ("pypi", "openai-agents", reference, 2)
    ]


def test_gradle_comments_and_example_strings_do_not_declare_dependencies():
    text = (
        '// implementation "dev.langchain4j:langchain4j:1.0.0"\n'
        '/* implementation("dev.langchain4j:langchain4j:1.0.0")\n'
        '   platform("dev.langchain4j:langchain4j-bom:1.0.0") */\n'
        "def example = '''implementation \"dev.langchain4j:langchain4j:1.0.0\"\n"
        "// this is still inside the example'''\n"
        'def mirror = "https://example.invalid/maven"; '
        'implementation /* comment */ ("org.springframework.ai:spring-ai-core:1.0.0")\n'
        'testImplementation("dev.langchain4j:langchain4j:1.0.0") // active dependency\n'
    )
    deps, result = _deps("build.gradle", text)
    assert not result.errors
    assert deps == {
        ("maven", "org.springframework.ai:spring-ai-core"),
        ("maven", "dev.langchain4j:langchain4j"),
    }
    assert [(dep.line, dep.dev) for dep in result.deps] == [(6, False), (7, True)]


def test_gradle_dollar_slashy_string_preserves_following_dependencies():
    deps, result = _deps(
        "build.gradle",
        "def mirror = $/https://example.invalid/maven/$; "
        'implementation("dev.langchain4j:langchain4j:1.0.0")\n',
    )
    assert not result.errors
    assert deps == {("maven", "dev.langchain4j:langchain4j")}


@pytest.mark.parametrize(
    "filename, example",
    [
        ("build.gradle", "def example = /it's/\n"),
        ("build.gradle", "def pattern = /https?:\\/\\/example/\n"),
        ("build.gradle.kts", 'val path = """C:\\"""\n'),
    ],
)
def test_gradle_raw_string_delimiters_do_not_consume_following_declarations(filename, example):
    deps, result = _deps(
        filename,
        example + 'dependencies { implementation("dev.langchain4j:langchain4j:1.0.0") }\n',
    )
    assert not result.errors
    assert deps == {("maven", "dev.langchain4j:langchain4j")}
    assert result.deps[0].line == 2


def test_kotlin_nested_comments_do_not_hide_following_dependencies():
    deps, result = _deps(
        "build.gradle.kts",
        '/* outer /* nested */ implementation("dev.langchain4j:langchain4j:1.0.0") */\n'
        'implementation("org.springframework.ai:spring-ai-core:1.0.0")\n',
    )
    assert not result.errors
    assert deps == {("maven", "org.springframework.ai:spring-ai-core")}
    assert result.deps[0].line == 2


def test_unterminated_gradle_comment_reports_incomplete_parsing():
    deps, result = _deps("build.gradle", '/* implementation("dev.langchain4j:langchain4j:1.0.0")\n')
    assert not deps
    assert result.errors == ["unterminated Gradle comment or string"]


def test_docker_comments_preserve_real_commands_quoted_hashes_and_source_lines():
    deps, result = _deps(
        "Dockerfile",
        "# pip install openai-agents\n"
        "FROM python:3.12\n"
        "RUN pip install langgraph # pip install crewai\n"
        'RUN echo "https://example.invalid/#fragment" && npm install @langchain/langgraph '
        "# npm install ai\n"
        "RUN echo \\# && uv pip install mcp\n",
    )
    assert not result.errors
    assert deps == {("pypi", "langgraph"), ("npm", "@langchain/langgraph"), ("pypi", "mcp")}
    assert {(dep.name, dep.line) for dep in result.deps} == {
        ("langgraph", 3),
        ("@langchain/langgraph", 4),
        ("mcp", 5),
    }


@pytest.mark.parametrize(
    "instruction",
    [
        "ENV NOTE literal # OPENAI_API_KEY",
        "ARG NOTE=literal # OPENAI_API_KEY",
        'LABEL note="literal" # OPENAI_API_KEY',
        "COPY files/#fragment /app/",
        'RUN ["echo", "literal # OPENAI_API_KEY"]',
        'RUN --mount=type=cache,target=/tmp ["echo", "literal # OPENAI_API_KEY"]',
        'CMD ["echo", "literal # OPENAI_API_KEY"]',
        'ENTRYPOINT ["echo", "literal # OPENAI_API_KEY"]',
    ],
)
def test_docker_non_shell_hashes_are_literal_data(instruction):
    text = instruction + "\n"
    assert manifest_comment_projection("Dockerfile", text) == text


def test_docker_shell_projection_keeps_quoted_hash_and_masks_inline_comment():
    text = 'RUN echo "# literal" && pip install langgraph # pip install crewai\n'
    projected = manifest_comment_projection("Dockerfile", text)
    assert len(projected) == len(text) and projected.count("\n") == text.count("\n")
    assert 'echo "# literal"' in projected and "pip install langgraph" in projected
    assert "crewai" not in projected


@pytest.mark.parametrize("escape", ["\\", "`"])
def test_docker_continuations_and_intervening_comments(escape):
    deps, result = _deps(
        "Dockerfile",
        f"# escape={escape}\nFROM python:3.12\nRUN pip install {escape}\n"
        "    # pip install crewai\n    openai-agents\n",
    )
    assert not result.errors
    assert deps == {("pypi", "openai-agents")}
    assert result.deps[0].line == 3


@pytest.mark.parametrize("escape", ["\\", "`"])
def test_docker_continuation_is_joined_before_shell_comment_detection(escape, tmp_path, run_connector):
    prefix = f"# escape={escape}\nFROM python:3.12\n"
    disabled = prefix + f"RUN echo ready # disabled install {escape}\n    pip install langgraph\n"
    active = prefix + f"RUN echo ready && {escape}\n    pip install langgraph\n"
    path = tmp_path / "Dockerfile"
    for text, expected in ((disabled, False), (active, True)):
        deps, result = _deps("Dockerfile", text)
        assert not result.errors
        assert deps == ({("pypi", "langgraph")} if expected else set())
        projection = manifest_comment_projection("Dockerfile", text)
        assert len(projection) == len(text) and projection.count("\n") == text.count("\n")
        assert ("pip install langgraph" in projection) == expected
        path.write_text(text)
        findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
        assert ctx.stats is not None and not ctx.stats.incomplete
        assert bool(findings) == expected


@pytest.mark.parametrize(
    "filename, declaration, signature",
    [
        (
            "requirements.txt",
            "openai-agents @ https://example.org/distributions/agents-0.1.0.tar.gz",
            "framework.openai-agents-sdk",
        ),
        ("build.gradle", 'implementation "dev.langchain4j:langchain4j:1.0.0"', "framework.langchain4j"),
        ("Dockerfile", "RUN pip install openai-agents", "framework.openai-agents-sdk"),
    ],
)
def test_comment_and_active_dependency_discovery_pair(
    tmp_path, run_connector, filename, declaration, signature
):
    path = tmp_path / filename
    comment = "// " if filename.endswith(".gradle") else "# "
    path.write_text(comment + declaration + "\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert not findings and ctx.stats is not None and not ctx.stats.incomplete
    path.write_text(declaration + "\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert ctx.stats is not None and not ctx.stats.incomplete
    assert len(findings) == 1 and findings[0].frameworks == [signature]


def test_containerfile_is_parsed_like_a_dockerfile():
    text = "FROM ghcr.io/berriai/litellm:main-latest\nENV OPENAI_API_KEY=\n"
    assert is_manifest_name("Containerfile")
    assert [(a.kind, a.value) for a in parse_manifest("Containerfile", text).artifacts] == [
        (a.kind, a.value) for a in parse_manifest("Dockerfile", text).artifacts
    ]


def test_manifest_line_index_and_dockerfile_dedupe():
    result = parse_manifest("Dockerfile", "FROM python:3.12\nENV OPENAI_API_KEY=\nENV AA=1 BB=2\n")
    assert result is not None
    env = [(a.value, a.line) for a in result.artifacts if a.kind == "env"]
    assert env == [("OPENAI_API_KEY", 2), ("AA", 3), ("BB", 3)]
    values = "".join(f"APP_SETTING_{i}: value\n" for i in range(4000))
    started = time.monotonic()
    result = parse_manifest("values.yaml", values)
    assert time.monotonic() - started < 5
    assert result is not None and not result.errors
    env = [a for a in result.artifacts if a.kind == "env"]
    assert len(env) == 4000 and env[-1].line == 4000
