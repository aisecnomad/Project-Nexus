"""A full code scan never places credential forms in any report format.

Each repository holds one credential form on a line that is itself evidence
(an endpoint, SDK or environment-name match), so the line is excerpted into
every report. The finding must still be reported with the value withheld.
"""

from __future__ import annotations

import io
import random
import string

import pytest
from rich.console import Console

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
SLACK_APP_TOKEN = "xapp" + "-1-A0B1C2D3E4F-" + _random(string.digits, 13) + "-" + _random(string.hexdigits, 60)
RUNNER_TOKEN = "glrt" + "-" + _random(string.ascii_letters + string.digits + "_-", 20)
AZURE = "https://contoso.openai.azure.com/"

CASES = {
    "csharp-azure-key-credential": ("Program.cs", (
        "using Azure.AI.OpenAI;\n"
        f'var client = new OpenAIClient(new Uri("{AZURE}"), new AzureKeyCredential("{HEX}"));\n'
    ), HEX),
    "java-azure-key-credential": ("src/App.java", (
        "import com.azure.ai.openai.OpenAIClient;\n"
        f'OpenAIClient client = new OpenAIClientBuilder().endpoint("{AZURE}")'
        f'.credential(new AzureKeyCredential("{HEX}")).buildClient();\n'
    ), HEX),
    "python-azure-key-credential": ("client.py", (
        "from azure.ai.inference import ChatCompletionsClient\n"
        f'client = ChatCompletionsClient("{AZURE}", AzureKeyCredential("{HEX}"))\n'
    ), HEX),
    "typescript-azure-key-credential": ("client.ts", (
        'import { OpenAIClient, AzureKeyCredential } from "@azure/openai";\n'
        f'const client = new OpenAIClient("{AZURE}", new AzureKeyCredential("{HEX}"));\n'
    ), HEX),
    "go-key-credential": ("main.go", (
        'import "github.com/Azure/azure-sdk-for-go/sdk/ai/azopenai"\n'
        f'client, err := azopenai.NewClientWithKeyCredential("{AZURE}", '
        f'azcore.NewKeyCredential("{HEX}"), nil)\n'
    ), HEX),
    "csharp-api-key-credential": ("Chat.cs", (
        "using OpenAI.Chat;\n"
        f'var chat = new ChatClient("gpt-4o", new ApiKeyCredential("{BASE62}"), '
        'new OpenAIClientOptions { Endpoint = new Uri("https://api.openai.com/v1") });\n'
    ), BASE62),
    "csharp-named-key-credential": ("Storage.cs", (
        f'var endpoint = new Uri("{AZURE}"); var cred = new AzureNamedKeyCredential("contoso", "{BASE64}");\n'
    ), BASE64),
    "python-http-basic-auth": ("basic.py", (
        "import requests\n"
        f'requests.post("{AZURE}openai/deployments", auth=HTTPBasicAuth("svc", "{PASSWORD}"))\n'
    ), PASSWORD),
    "python-auth-tuple": ("pair.py", (
        "import requests\n"
        f'requests.get("https://api.openai.com/v1/models", auth=("svc", "{PASSWORD}"))\n'
    ), PASSWORD),
    "bearer-token-helper": ("bearer.ts", (
        f'const res = await fetch("https://api.openai.com/v1/models", withBearerToken("{BASE62}"));\n'
    ), BASE62),
    "curl-user-password": ("deploy.sh", (
        f'curl -u "svc:{HEX}" {AZURE}openai/deployments\n'
    ), HEX),
    "flag-equals": ("models.sh", f"curl --api-key={HEX} https://api.openai.com/v1/models\n", HEX),
    "flag-space": ("list.sh", f"curl --api-key {HEX} https://api.openai.com/v1/models\n", HEX),
    "flag-token": ("proxy.sh", f"llm-proxy --token {BASE62} --upstream https://api.openai.com/v1\n", BASE62),
    "flag-password": ("gateway.sh", f"llm-gateway --password={PASSWORD} --upstream {AZURE}\n", PASSWORD),
    "header-without-space": ("claude.sh", (
        f'curl -H "x-api-key:{HEX}" https://api.anthropic.com/v1/messages\n'
    ), HEX),
    "header-bearer": ("bearer.sh", (
        f'curl -H "Authorization: Bearer {HEX}" https://api.openai.com/v1/models\n'
    ), HEX),
    "header-subscription-key": ("apim.sh", (
        f'curl -H "Ocp-Apim-Subscription-Key: {HEX}" {AZURE}openai/deployments\n'
    ), HEX),
    "ci-workflow": (".github/workflows/smoke.yml", (
        "name: smoke\non: push\njobs:\n  smoke:\n    runs-on: ubuntu-latest\n    steps:\n"
        f"      - run: curl --api-key {HEX} https://api.openai.com/v1/models\n"
    ), HEX),
    "makefile": ("Makefile", f"smoke:\n\tcurl -u svc:{HEX} {AZURE}openai/deployments\n", HEX),
    "dockerfile-env-pairs": ("worker/Dockerfile", (
        f"FROM python:3.12\nENV OPENAI_BASE_URL=https://api.openai.com/v1 OPENAI_API_KEY={HEX}\n"
    ), HEX),
    "dotnet-app-settings": ("config/appsettings.xml", (
        f'<appSettings><add key="AZURE_OPENAI_API_KEY" value="{HEX}" /><add key="Endpoint" value="{AZURE}" />'
        "</appSettings>\n"
    ), HEX),
    "xml-password-element": ("settings.xml", (
        f"<server><url>https://api.openai.com/v1</url><password>{PASSWORD}</password></server>\n"
    ), PASSWORD),
    "xml-api-key-element": ("openai.xml", (
        f"<openai><endpoint>{AZURE}</endpoint><apiKey>{HEX}</apiKey></openai>\n"
    ), HEX),
    "helm-name-value": ("chart/templates/deployment.yaml", (
        "spec:\n  containers:\n    - image: {{ .Values.image }}\n"
        f'      env: [{{name: OPENAI_API_KEY, value: "{HEX}"}}]\n'
    ), HEX),
    "prefixed-tokens": ("tokens.py", (
        "import openai\n"
        f'FIXTURES = ["https://api.openai.com/v1", "{GOOGLE_TOKEN}", "{SLACK_APP_TOKEN}", "{RUNNER_TOKEN}"]\n'
    ), (GOOGLE_TOKEN, SLACK_APP_TOKEN, RUNNER_TOKEN)),
}


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
    result = Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem", {
        "path": str(tmp_path), "use_git": False,
    })]), index).run()
    assert result.complete, [error for stats in result.stats for error in stats.errors]
    assert result.findings
    outputs = _outputs(result)
    assert set(outputs) == {"json", "sarif", "csv", "markdown", "html", "table"}
    for name, output in outputs.items():
        for secret in secrets:
            assert secret not in output, name
    # The credential line itself is evidence: the report shows it, withheld.
    assert REDACTED in outputs["json"]
