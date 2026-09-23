from __future__ import annotations

from shadowscan.connectors.code.manifests import parse_manifest


def _deps(rel, text):
    res = parse_manifest(rel, text)
    assert res is not None
    return {(d.ecosystem, d.name) for d in res.deps}, res


def test_requirements_and_pyproject():
    deps, _ = _deps("requirements.txt", "langchain>=0.3 # core\nlangchain-openai\n-r base.txt\ngit+https://github.com/openai/swarm.git#egg=swarm\ncrewai[tools]==0.80\n")
    assert ("pypi", "langchain") in deps and ("pypi", "swarm") in deps and ("pypi", "crewai") in deps
    deps, _ = _deps("pyproject.toml", '[project]\ndependencies=["google-adk>=1.0", "mcp"]\n[project.optional-dependencies]\ndev=["pytest"]\n[tool.poetry.dependencies]\npython="^3.11"\nstrands-agents="*"\n')
    assert {("pypi", "google-adk"), ("pypi", "mcp"), ("pypi", "strands-agents")} <= deps


def test_package_json_go_cargo_maven_gradle_nuget():
    deps, _ = _deps("package.json", '{"dependencies": {"@langchain/langgraph": "^0.2", "ai": "4"}, "devDependencies": {"typescript": "5"}, "scripts": {"mcp": "npx -y @modelcontextprotocol/server-filesystem ."}}')
    assert {("npm", "@langchain/langgraph"), ("npm", "ai"), ("npm", "@modelcontextprotocol/server-filesystem")} <= deps
    deps, _ = _deps("go.mod", "module x\nrequire (\n\tgithub.com/mark3labs/mcp-go v0.8.0\n)\nrequire github.com/tmc/langchaingo v0.1.12\n")
    assert {("go", "github.com/mark3labs/mcp-go"), ("go", "github.com/tmc/langchaingo")} <= deps
    deps, _ = _deps("Cargo.toml", '[dependencies]\nrig-core = "0.5"\ntokio = { version = "1", features = ["full"] }\n')
    assert ("cargo", "rig-core") in deps
    deps, _ = _deps("pom.xml", "<project><dependencies><dependency><groupId>dev.langchain4j</groupId><artifactId>langchain4j</artifactId><version>1.0</version></dependency></dependencies></project>")
    assert ("maven", "dev.langchain4j:langchain4j") in deps
    deps, _ = _deps("build.gradle.kts", 'dependencies {\n    implementation("org.springframework.ai:spring-ai-openai-spring-boot-starter:1.0.0")\n}\n')
    assert ("maven", "org.springframework.ai:spring-ai-openai-spring-boot-starter") in deps
    deps, _ = _deps("Agent.csproj", '<Project><ItemGroup><PackageReference Include="Microsoft.Agents.AI" Version="1.0.0" /></ItemGroup></Project>')
    assert ("nuget", "Microsoft.Agents.AI") in deps


def test_dockerfile_compose_and_terraform_artifacts():
    deps, res = _deps("Dockerfile", "FROM ghcr.io/berriai/litellm:main\nENV OPENAI_API_KEY=x ANTHROPIC_API_KEY=y\nRUN pip install langchain openai && npm install -g @anthropic-ai/claude-code\n")
    arts = {(a.kind, a.value) for a in res.artifacts}
    assert ("image", "ghcr.io/berriai/litellm:main") in arts and ("env", "OPENAI_API_KEY") in arts
    assert {("pypi", "langchain"), ("pypi", "openai"), ("npm", "@anthropic-ai/claude-code")} <= deps
    _, res = _deps("docker-compose.yml", "services:\n  n8n:\n    image: n8nio/n8n\n    environment:\n      - N8N_API_KEY=abc\n")
    arts = {(a.kind, a.value) for a in res.artifacts}
    assert ("image", "n8nio/n8n") in arts and ("env", "N8N_API_KEY") in arts
    _, res = _deps("main.tf", 'resource "aws_bedrockagent_agent" "ops" {\n  agent_name = "ops-provisioning-04"\n}\nresource "aws_s3_bucket" "b" {}\n')
    iac = [a for a in res.artifacts if a.kind == "iac"]
    assert iac[0].value == "aws_bedrockagent_agent" and iac[0].extra["display_name"] == "ops-provisioning-04"


def test_env_file_and_cloudformation():
    _, res = _deps(".env", "OPENAI_API_KEY=sk-live\n# comment\nexport GEMINI_API_KEY='x'\n")
    names = {a.value for a in res.artifacts}
    assert {"OPENAI_API_KEY", "GEMINI_API_KEY"} <= names
    _, res = _deps("template.yaml", "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Agent:\n    Type: AWS::Bedrock::Agent\n")
    assert ("iac", "AWS::Bedrock::Agent") in {(a.kind, a.value) for a in res.artifacts}


def test_non_manifest_returns_none():
    assert parse_manifest("src/app.py", "print('hi')") is None
