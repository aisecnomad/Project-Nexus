"""A full code scan never places credential forms in any report format.

Each repository holds one credential form on a line that is itself evidence
(an endpoint, SDK or environment-name match), so the line is excerpted into
every report. The finding must still be reported with the value withheld.
"""

from __future__ import annotations

import io
import json
import random
import re
import string

import pytest
from click.testing import CliRunner
from rich.console import Console

from shadowscan.cli import main
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.reporters import RENDERERS
from shadowscan.reporters.table import print_table
from shadowscan.utils.redaction import REDACTED

_RANDOM = random.Random(4217)


def _random(alphabet: str, length: int) -> str:
    return "".join(_RANDOM.choice(alphabet) for _ in range(length))


HEX = _random("0123456789abcdef", 32)
BASE62 = _random(string.ascii_letters + string.digits, 40)
BASE64 = _random(string.ascii_letters + string.digits + "+/", 86) + "=="
PASSWORD = _random(string.ascii_letters + string.digits + "!@%^*-_.~", 20)
GOOGLE_TOKEN = "ya29" + "." + "a0Ad52N3" + _random(string.ascii_letters + string.digits + "_-", 60)
SLACK_APP_TOKEN = (
    "xapp" + "-1-A0B1C2D3E4F-" + _random(string.digits, 13) + "-" + _random(string.hexdigits, 60)
)
RUNNER_TOKEN = "glrt" + "-" + _random(string.ascii_letters + string.digits + "_-", 20)
AZURE = "https://contoso.openai.azure.com/"

CASES = {
    "csharp-credential-source-trivia": (
        "Program.cs",
        (
            "using Azure.AI.OpenAI;\n"
            f'var one = new OpenAIClient(new Uri("{AZURE}"), new AzureKeyCredential ("{HEX}"));\n'
            f'var two = new OpenAIClient(new Uri("{AZURE}"), new AzureKeyCredential/* key */("{HEX}"));\n'
            f'var three = new OpenAIClient(new Uri("{AZURE}"), new AzureKeyCredential(("{HEX}")));\n'
            f'var four = new OpenAIClient(new Uri("{AZURE}"), new AzureKeyCredential($"{HEX}"));\n'
        ),
        HEX,
    ),
    "python-credential-multiline-and-interpolation": (
        "client.py",
        (
            "from azure.ai.inference import ChatCompletionsClient\n"
            f"client = ChatCompletionsClient(\"{AZURE}\", AzureKeyCredential('''\n{HEX}\n'''))\n"
            f'other = ChatCompletionsClient("{AZURE}", AzureKeyCredential(f"{HEX}{{suffix}}"))\n'
        ),
        HEX,
    ),
    "json-value-before-credential-name": (
        "config.json",
        f'{{"endpoint": "{AZURE}", "settings": [{{"value": "{HEX}", "name": "Password"}}]}}\n',
        HEX,
    ),
    "yaml-value-before-credential-name": (
        "config.yml",
        f'env:\n  - value: "{HEX} {AZURE}"\n    name: OPENAI_API_KEY\n',
        HEX,
    ),
    "json-brace-inside-credential-value": (
        "config.json",
        f'{{"endpoint": "{AZURE}", "settings": [{{"name": "Password", "value": "p}}{HEX}"}}]}}\n',
        HEX,
    ),
    "csharp-azure-key-credential": (
        "Program.cs",
        (
            "using Azure.AI.OpenAI;\n"
            f'var client = new OpenAIClient(new Uri("{AZURE}"), new AzureKeyCredential("{HEX}"));\n'
        ),
        HEX,
    ),
    "java-azure-key-credential": (
        "src/App.java",
        (
            "import com.azure.ai.openai.OpenAIClient;\n"
            f'OpenAIClient client = new OpenAIClientBuilder().endpoint("{AZURE}")'
            f'.credential(new AzureKeyCredential("{HEX}")).buildClient();\n'
        ),
        HEX,
    ),
    "python-azure-key-credential": (
        "client.py",
        (
            "from azure.ai.inference import ChatCompletionsClient\n"
            f'client = ChatCompletionsClient("{AZURE}", AzureKeyCredential("{HEX}"))\n'
        ),
        HEX,
    ),
    "typescript-azure-key-credential": (
        "client.ts",
        (
            'import { OpenAIClient, AzureKeyCredential } from "@azure/openai";\n'
            f'const client = new OpenAIClient("{AZURE}", new AzureKeyCredential("{HEX}"));\n'
        ),
        HEX,
    ),
    "go-key-credential": (
        "main.go",
        (
            'import "github.com/Azure/azure-sdk-for-go/sdk/ai/azopenai"\n'
            f'client, err := azopenai.NewClientWithKeyCredential("{AZURE}", '
            f'azcore.NewKeyCredential("{HEX}"), nil)\n'
        ),
        HEX,
    ),
    "csharp-api-key-credential": (
        "Chat.cs",
        (
            "using OpenAI.Chat;\n"
            f'var chat = new ChatClient("gpt-4o", new ApiKeyCredential("{BASE62}"), '
            'new OpenAIClientOptions { Endpoint = new Uri("https://api.openai.com/v1") });\n'
        ),
        BASE62,
    ),
    "csharp-named-key-credential": (
        "Storage.cs",
        (
            f'var endpoint = new Uri("{AZURE}"); var cred = new AzureNamedKeyCredential("contoso", "{BASE64}");\n'
        ),
        BASE64,
    ),
    "python-http-basic-auth": (
        "basic.py",
        (
            "import requests\n"
            f'requests.post("{AZURE}openai/deployments", auth=HTTPBasicAuth("svc", "{PASSWORD}"))\n'
        ),
        PASSWORD,
    ),
    "python-auth-tuple": (
        "pair.py",
        (f'import requests\nrequests.get("https://api.openai.com/v1/models", auth=("svc", "{PASSWORD}"))\n'),
        PASSWORD,
    ),
    "bearer-token-helper": (
        "bearer.ts",
        (f'const res = await fetch("https://api.openai.com/v1/models", withBearerToken("{BASE62}"));\n'),
        BASE62,
    ),
    "curl-user-password": ("deploy.sh", (f'curl -u "svc:{HEX}" {AZURE}openai/deployments\n'), HEX),
    "flag-equals": ("models.sh", f"curl --api-key={HEX} https://api.openai.com/v1/models\n", HEX),
    "flag-space": ("list.sh", f"curl --api-key {HEX} https://api.openai.com/v1/models\n", HEX),
    "flag-token": ("proxy.sh", f"llm-proxy --token {BASE62} --upstream https://api.openai.com/v1\n", BASE62),
    "flag-password": ("gateway.sh", f"llm-gateway --password={PASSWORD} --upstream {AZURE}\n", PASSWORD),
    "flag-key": ("key.sh", f"llm --key {HEX} --base-url https://api.openai.com/v1\n", HEX),
    "dotnet-user-secrets": (
        "setup.sh",
        (f'dotnet user-secrets set "AzureOpenAI:Key" "{HEX}" && curl {AZURE}openai/deployments\n'),
        HEX,
    ),
    "numbered-key": ("env.sh", f"export AZURE_OPENAI_ENDPOINT={AZURE} AZURE_OPENAI_KEY1={BASE62}\n", BASE62),
    "header-without-space": (
        "claude.sh",
        (f'curl -H "x-api-key:{HEX}" https://api.anthropic.com/v1/messages\n'),
        HEX,
    ),
    "header-bearer": (
        "bearer.sh",
        (f'curl -H "Authorization: Bearer {HEX}" https://api.openai.com/v1/models\n'),
        HEX,
    ),
    "header-subscription-key": (
        "apim.sh",
        (f'curl -H "Ocp-Apim-Subscription-Key: {HEX}" {AZURE}openai/deployments\n'),
        HEX,
    ),
    "ci-workflow": (
        ".github/workflows/smoke.yml",
        (
            "name: smoke\non: push\njobs:\n  smoke:\n    runs-on: ubuntu-latest\n    steps:\n"
            f"      - run: curl --api-key {HEX} https://api.openai.com/v1/models\n"
        ),
        HEX,
    ),
    "makefile": ("Makefile", f"smoke:\n\tcurl -u svc:{HEX} {AZURE}openai/deployments\n", HEX),
    "dockerfile-env-pairs": (
        "worker/Dockerfile",
        (f"FROM python:3.12\nENV OPENAI_BASE_URL=https://api.openai.com/v1 OPENAI_API_KEY={HEX}\n"),
        HEX,
    ),
    "dotnet-app-settings": (
        "config/appsettings.xml",
        (
            f'<appSettings><add key="AZURE_OPENAI_API_KEY" value="{HEX}" /><add key="Endpoint" value="{AZURE}" />'
            "</appSettings>\n"
        ),
        HEX,
    ),
    # Hierarchical .NET setting names: the last segment names the credential.
    # (The walker does not read '.config' files, so App.config's shape is
    # scanned under an '.xml' name.)
    "dotnet-hierarchical-key": (
        "conf/app.xml",
        (
            "<configuration><appSettings>"
            f'<add key="AzureOpenAI:Endpoint" value="{AZURE}"/><add key="AzureOpenAI:Key" value="{HEX}"/>'
            "</appSettings></configuration>\n"
        ),
        HEX,
    ),
    "dotnet-hierarchical-secret": (
        "web.xml",
        (
            f'<appSettings><add key="OpenAI:Endpoint" value="{AZURE}"/>'
            f'<add key="OpenAI:Secret" value="{PASSWORD}"/></appSettings>\n'
        ),
        PASSWORD,
    ),
    "xml-credential-named-element": (
        "openai-settings.xml",
        (f"<openai><endpoint>{AZURE}</endpoint><OpenAIKey>{BASE62}</OpenAIKey></openai>\n"),
        BASE62,
    ),
    # Not under 'env', whose values the structural pass already withholds.
    "yaml-hierarchical-record": (
        "deploy/parameters.yaml",
        (
            f"parameters: [{{name: AzureOpenAI__Endpoint, value: {AZURE}}}, "
            f"{{name: AzureOpenAI__Key, value: {HEX}}}]\n"
        ),
        HEX,
    ),
    # An element's own name decides its content beside a key attribute that
    # names a setting ('openai.token' counts by its last segment).
    "xml-element-with-setting-key": (
        "openai-token.xml",
        (
            f"<configuration><openai><endpoint>{AZURE}</endpoint>"
            f'<token key="openai.token" value="">{HEX}</token></openai></configuration>\n'
        ),
        HEX,
    ),
    "yaml-credential-named-key": (
        "config/openai.yaml",
        (f"openai: {{endpoint: {AZURE}, openaiKey: {HEX}}}\n"),
        HEX,
    ),
    "mysql-attached-password": (
        "migrate.sh",
        (f"mysql -h db -u root -pS3cretKey2024 app < schema.sql && curl {AZURE}openai/deployments\n"),
        "S3cretKey2024",
    ),
    "xml-password-element": (
        "settings.xml",
        (f"<server><url>https://api.openai.com/v1</url><password>{PASSWORD}</password></server>\n"),
        PASSWORD,
    ),
    "xml-api-key-element": (
        "openai.xml",
        (f"<openai><endpoint>{AZURE}</endpoint><apiKey>{HEX}</apiKey></openai>\n"),
        HEX,
    ),
    "helm-name-value": (
        "chart/templates/deployment.yaml",
        (
            "spec:\n  containers:\n    - image: {{ .Values.image }}\n"
            f'      env: [{{name: OPENAI_API_KEY, value: "{HEX}"}}]\n'
        ),
        HEX,
    ),
    "prefixed-tokens": (
        "tokens.py",
        (
            "import openai\n"
            f'FIXTURES = ["https://api.openai.com/v1", "{GOOGLE_TOKEN}", "{SLACK_APP_TOKEN}", "{RUNNER_TOKEN}"]\n'
        ),
        (GOOGLE_TOKEN, SLACK_APP_TOKEN, RUNNER_TOKEN),
    ),
    # Methods called on a call result: the official OpenAI Java SDK builder.
    "java-builder-chain": (
        "src/Chat.java",
        (
            "import com.openai.client.okhttp.OpenAIOkHttpClient;\n"
            f'OpenAIClient client = OpenAIOkHttpClient.builder().apiKey("{HEX}")'
            '.baseUrl("https://api.openai.com/v1").build();\n'
        ),
        HEX,
    ),
    "java-builder-chain-lines": (
        "src/Client.java",
        (
            "import com.openai.client.okhttp.OpenAIOkHttpClient;\n"
            "OpenAIClient client = OpenAIOkHttpClient.builder()\n"
            f'    .apiKey("{BASE62}").baseUrl("https://api.openai.com/v1")\n'
            "    .build();\n"
        ),
        BASE62,
    ),
    "java-header-chain": (
        "src/Messages.java",
        (
            'Request request = new Request.Builder().url("https://api.anthropic.com/v1/messages")'
            f'.header("x-api-key", "{HEX}").build();\n'
        ),
        HEX,
    ),
    "docker-login": (
        "deploy.sh",
        (f"docker login -u svc -p {BASE62} contoso.azurecr.io && curl {AZURE}openai/deployments\n"),
        BASE62,
    ),
    "r-assignment": ("client.R", (f'api_key <- "{HEX}"; base_url <- "https://api.openai.com/v1"\n'), HEX),
    "js-credential-name": (
        "client.js",
        (f'const openaiKey = "{HEX}", baseURL = "https://api.openai.com/v1";\n'),
        HEX,
    ),
    # Unquoted flow-style record values: the withheld marker used to grow by
    # one ']' each time the pipeline sanitized the excerpt.
    "helm-unquoted-record": (
        "chart/templates/deployment.yaml",
        (f"url: https://api.openai.com/v1 {{name: OPENAI_API_KEY, value: {HEX}}}\n"),
        HEX,
    ),
    "helm-unquoted-env-list": (
        "chart/templates/worker.yaml",
        (
            "spec:\n  containers:\n    - image: {{ .Values.image }}\n"
            f"      env: [{{name: OPENAI_API_KEY, value: {BASE62}}}, "
            "{name: OPENAI_BASE_URL, value: https://api.openai.com/v1}]\n"
        ),
        BASE62,
    ),
    "csharp-target-typed-new": (
        "Target.cs",
        (
            "using Azure.AI.OpenAI;\n"
            f'AzureKeyCredential openai = new("{HEX}"); '
            f'var client = new OpenAIClient(new Uri("{AZURE}"), openai);\n'
        ),
        HEX,
    ),
    "rust-key-credential": (
        "src/main.rs",
        (
            "use azure_core::credentials::AzureKeyCredential;\n"
            f'let client = OpenAIClient::new("{AZURE}", AzureKeyCredential::new("{HEX}".to_string()));\n'
        ),
        HEX,
    ),
    "python-f-string": (
        "fclient.py",
        (
            "from azure.ai.inference import ChatCompletionsClient\n"
            f'client = ChatCompletionsClient("{AZURE}", AzureKeyCredential(f"{HEX}"))\n'
        ),
        HEX,
    ),
    "js-fallback-default": (
        "fallback.js",
        (f'const k = process.env.OPENAI_API_KEY || "{HEX}"; fetch("https://api.openai.com/v1/models");\n'),
        HEX,
    ),
    "csharp-fallback-default": (
        "Fallback.cs",
        (
            "using Azure.AI.OpenAI;\n"
            f'var k = Environment.GetEnvironmentVariable("AZURE_OPENAI_KEY") ?? "{HEX}"; '
            f'var client = new OpenAIClient(new Uri("{AZURE}"), new AzureKeyCredential(k));\n'
        ),
        HEX,
    ),
    "python-fallback-default": (
        "fallback.py",
        (f'import openai\nk = os.getenv("OPENAI_API_KEY") or "{HEX}"; client = openai.OpenAI(api_key=k)\n'),
        HEX,
    ),
    "shell-default": (
        "docker-compose.yml",
        (
            "services:\n  app:\n"
            f'    command: ["sh", "-c", "curl -H api-key:${{AZURE_OPENAI_KEY:-{HEX}}} {AZURE}openai"]\n'
        ),
        HEX,
    ),
    "az-login": (
        ".github/workflows/deploy.yml",
        (
            "name: deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n"
            f"      - run: az login --service-principal -u app -p {PASSWORD} --tenant t && curl {AZURE}openai\n"
        ),
        PASSWORD,
    ),
    "docker-login-stdin": (
        "push.sh",
        (f"echo {BASE62} | docker login contoso.azurecr.io -u svc --password-stdin && curl {AZURE}openai\n"),
        BASE62,
    ),
}
# A marker followed by another ']' (escaped or not): a corrupted marker.
_GROWN_MARKER = re.compile(r"REDACTED\\?\]\\?\]")


def _scan(root, index):
    return Engine(
        ScanConfig(
            connectors=[
                ConnectorSpec(
                    "code.filesystem",
                    {
                        "path": str(root),
                        "use_git": False,
                    },
                )
            ]
        ),
        index,
    ).run()


def _outputs(result) -> dict[str, str]:
    outputs = {name: render(result) for name, render in RENDERERS.items() if name != "md"}
    stream = io.StringIO()
    print_table(result, console=Console(file=stream, width=220, color_system=None), verbose=True)
    outputs["table"] = stream.getvalue()
    return outputs


@pytest.mark.parametrize("case", sorted(CASES))
def test_credential_forms_never_reach_any_report(tmp_path, index, case):
    relative, source, secrets = CASES[case]
    secrets = secrets if isinstance(secrets, tuple) else (secrets,)
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    result = _scan(tmp_path, index)
    assert result.complete, [error for stats in result.stats for error in stats.errors]
    assert result.findings
    outputs = _outputs(result)
    assert set(outputs) == {"json", "sarif", "cyclonedx", "csv", "markdown", "html", "table"}
    for name, output in outputs.items():
        for secret in secrets:
            assert secret not in output, name
        assert _GROWN_MARKER.search(output) is None, name
    # The credential line itself is evidence: the report shows it, withheld.
    assert REDACTED in outputs["json"]


def test_a_callee_that_names_nothing_leaves_the_scan_complete(tmp_path, index):
    # 'token.(' in a comment used to raise IndexError while redacting the
    # excerpt, which marked the whole scan incomplete (exit 3).
    (tmp_path / "app.py").write_text(
        'import openai\nclient = openai.OpenAI()\n# see token.("x") and auth._("y")\n',
        encoding="utf-8",
    )
    result = _scan(tmp_path, index)
    assert result.complete, [error for stats in result.stats for error in stats.errors]
    assert any("OpenAI" in finding.title for finding in result.findings)


@pytest.mark.parametrize("scan_secrets", [False, True])
@pytest.mark.parametrize(
    "case",
    [
        "csharp-credential-source-trivia",
        "python-credential-multiline-and-interpolation",
        "json-value-before-credential-name",
        "yaml-value-before-credential-name",
        "json-brace-inside-credential-value",
    ],
)
def test_fixed_credential_forms_are_redacted_in_actual_cli_json(tmp_path, scan_secrets, case):
    relative, source, secret = CASES[case]
    (tmp_path / relative).write_text(source, encoding="utf-8")
    args = ["code", str(tmp_path), "--format", "json"]
    if not scan_secrets:
        args.append("--no-secrets")
    completed = CliRunner().invoke(main, args)
    assert completed.exit_code == 0, completed.output
    report = json.loads(completed.stdout)
    assert report["summary"]["complete"] and report["findings"]
    assert secret not in completed.output and REDACTED in completed.stdout
