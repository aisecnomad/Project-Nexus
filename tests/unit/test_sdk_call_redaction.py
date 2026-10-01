"""Well-known LLM SDK calls lose the literal at their credential position.

Semantic Kernel's connector registrations, go-openai's configuration helpers
and a few SDK constructors take an API key positionally, yet no word of their
names refers to a credential. The credential-callee rules did not read them,
so an unprefixed key (the Azure OpenAI shape) reached report excerpts verbatim.
"""

from __future__ import annotations

import random
import string

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.utils.redaction import REDACTED, sanitize_text

_RANDOM = random.Random(20261001)


def _random(alphabet: str, length: int) -> str:
    return "".join(_RANDOM.choice(alphabet) for _ in range(length))


HEX = _random("0123456789abcdef", 32)  # Azure OpenAI key shape: no provider prefix
BASE62 = _random(string.ascii_letters + string.digits, 40)
# Not opaque: a callee's 'client' word alone does not withhold it.
READABLE = "letmein-please"
AZURE = "https://contoso.openai.azure.com/"

# (source, secret, text that must survive)
SDK_CALLS: list[tuple[str, str, str]] = [
    # Semantic Kernel for .NET, Azure OpenAI: (deploymentName, endpoint, apiKey, ...).
    (f'builder.AddAzureOpenAIChatCompletion("gpt-4o", "{AZURE}", "{HEX}");', HEX, f'("gpt-4o", "{AZURE}", '),
    (
        f'services.AddAzureOpenAIChatClient("gpt-4o", endpoint, "{READABLE}");',
        READABLE,
        '("gpt-4o", endpoint, ',
    ),
    (
        f'builder.AddAzureOpenAITextEmbeddingGeneration("text-embedding-3-small", "{AZURE}", "{HEX}", "embed");',
        HEX,
        ', "embed");',
    ),
    (f'builder.AddAzureOpenAIEmbeddingGenerator("ada", endpoint, "{HEX}");', HEX, '("ada", endpoint, '),
    (f'builder.AddAzureOpenAITextToImage("dall-e-3", endpoint, "{HEX}");', HEX, '"dall-e-3"'),
    (f'builder.AddAzureOpenAIAudioToText("whisper", endpoint, "{HEX}");', HEX, '"whisper"'),
    (f'builder.AddAzureOpenAITextToAudio("tts", endpoint, "{HEX}");', HEX, '"tts"'),
    (
        f'var chat = new AzureOpenAIChatCompletionService("gpt-4o", "{AZURE}", "{HEX}");',
        HEX,
        f'new AzureOpenAIChatCompletionService("gpt-4o", "{AZURE}", ',
    ),
    (
        f'var embed = new AzureOpenAITextEmbeddingGenerationService("ada", endpoint, @"{HEX}");',
        HEX,
        '("ada", endpoint, ',
    ),
    # OpenAI: (modelId, apiKey, orgId, ...).
    (f'builder.AddOpenAIChatCompletion("gpt-4o-mini", "{BASE62}");', BASE62, '("gpt-4o-mini", '),
    (f'builder.AddOpenAIChatClient("gpt-4o", "{READABLE}", "org-contoso");', READABLE, '"org-contoso"'),
    (f'builder.AddOpenAITextEmbeddingGeneration("text-embedding-3-small", "{BASE62}");', BASE62, "small"),
    (f'builder.AddOpenAIEmbeddingGenerator("text-embedding-3-large", "{BASE62}");', BASE62, "large"),
    (f'builder.AddOpenAIAudioToText("whisper-1", "{BASE62}");', BASE62, '"whisper-1"'),
    (f'builder.AddOpenAITextToAudio("tts-1", "{BASE62}");', BASE62, '"tts-1"'),
    (f'var chat = new OpenAIChatCompletionService("gpt-4o", "{BASE62}");', BASE62, '("gpt-4o", '),
    (f'var embed = new OpenAITextEmbeddingGenerationService("ada", "{BASE62}");', BASE62, '("ada", '),
    # The endpoint overloads, (modelId, endpoint Uri, apiKey, orgId): the endpoint
    # expression is no literal, so the key third is withheld.
    (
        f'builder.AddOpenAIChatCompletion("llama3", new Uri("https://api.groq.com/openai/v1"), "{BASE62}");',
        BASE62,
        'new Uri("https://api.groq.com/openai/v1"), ',
    ),
    (f'var chat = new OpenAIChatCompletionService("gpt-4o", endpoint, "{BASE62}");', BASE62, "endpoint, "),
    # AddOpenAITextToImage takes (apiKey, orgId, modelId).
    (f'builder.AddOpenAITextToImage("{BASE62}", "org-contoso", "dall-e-3");', BASE62, '"dall-e-3"'),
    # A builder chain across lines, and the chained call on one line.
    (
        "var kernel = Kernel.CreateBuilder()\n"
        f'    .AddAzureOpenAIChatCompletion("gpt-4o", endpoint, "{HEX}")\n'
        "    .Build();\n",
        HEX,
        "    .Build();\n",
    ),
    (f'Kernel.CreateBuilder().AddOpenAIChatCompletion("gpt-4o", "{BASE62}").Build();', BASE62, ").Build();"),
    # go-openai: DefaultConfig(authToken), DefaultAzureConfig(apiKey, baseURL), NewClient(authToken).
    (f'config := openai.DefaultConfig("{HEX}")', HEX, "config := openai.DefaultConfig("),
    (f'config := openai.DefaultAzureConfig("{HEX}", "{AZURE}")', HEX, f'"{AZURE}")'),
    (f"config := openai.DefaultAzureConfig(`{HEX}`, baseURL)", HEX, ", baseURL)"),
    # A readable token is withheld at the known position too, where the
    # 'client' word alone withholds only an opaque one.
    (f'client := openai.NewClient("{READABLE}")', READABLE, "openai.NewClient("),
    # openai-java and the Google AI JavaScript SDK.
    (
        f'OpenAiService service = new OpenAiService("{HEX}", Duration.ofSeconds(30));',
        HEX,
        "Duration.ofSeconds(30)",
    ),
    (f'const genAI = new GoogleGenerativeAI("{HEX}");', HEX, "new GoogleGenerativeAI("),
    # Named arguments are read by the mapping rules, as for any call.
    (f'builder.AddOpenAIChatCompletion(modelId: "gpt-4o", apiKey: "{BASE62}");', BASE62, 'modelId: "gpt-4o"'),
    (
        f'builder.AddAzureOpenAIChatCompletion("gpt-4o", endpoint: "{AZURE}", apiKey: "{HEX}");',
        HEX,
        f'endpoint: "{AZURE}"',
    ),
]


@pytest.mark.parametrize(("source", "secret", "kept"), SDK_CALLS)
def test_sdk_call_credentials_are_withheld_with_context_and_lines_preserved(source, secret, kept):
    safe = sanitize_text(source)
    assert secret not in safe
    assert REDACTED in safe
    assert kept in safe
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize(
    "source",
    [
        # References, lookups and placeholders at the credential position.
        f'builder.AddAzureOpenAIChatCompletion("gpt-4o", "{AZURE}", apiKey);',
        'builder.AddAzureOpenAIChatCompletion(config["AzureOpenAI:Deployment"], endpoint, config["AzureOpenAI:Key"]);',
        'builder.AddOpenAIChatCompletion("gpt-4o", Environment.GetEnvironmentVariable("OPENAI_API_KEY")!);',
        'builder.AddOpenAIChatCompletion("gpt-4o", "<your-api-key>");',
        'builder.AddOpenAIChatCompletion("gpt-4o", "YOUR_OPENAI_API_KEY");',
        f'builder.AddAzureOpenAIChatCompletion("gpt-4o", "{AZURE}", "${{AZURE_OPENAI_KEY}}");',
        'config := openai.DefaultConfig(os.Getenv("OPENAI_API_KEY"))',
        "client := openai.NewClientWithConfig(config)",
        'service = new OpenAiService(System.getenv("OPENAI_TOKEN"));',
        "const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);",
        # Other positions of a listed call keep their values.
        f'builder.AddAzureOpenAIChatCompletion("gpt-4o", "{AZURE}", credential, "chat", "gpt-4o-2024-08-06");',
        # A generic name counts only through its SDK's package; distinctive
        # names elsewhere, and calls that only mention one, are ordinary.
        'cfg := retry.DefaultConfig("ingest-worker-7")',
        'cfg := DefaultConfig("ingest-worker-7")',
        'log.Info("calling AddOpenAIChatCompletion", "gpt-4o")',
        'AddOpenAIChatCompletionAsync("gpt-4o", "ingest-worker-7")',
    ],
)
def test_sdk_calls_without_a_credential_literal_are_unchanged(source):
    assert sanitize_text(source) == source


_SK_PROJECT = (
    '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
    '<PackageReference Include="Microsoft.SemanticKernel" Version="1.30.0" />'
    "</ItemGroup></Project>\n"
)
_GO_MODULE = "module example.com/chat\n\ngo 1.22\n\nrequire github.com/sashabaranov/go-openai v1.32.0\n"
_GO_KEY = _random("0123456789abcdef", 32)


@pytest.mark.parametrize("report_format", ["json", "sarif", "html", "markdown"])
def test_sdk_call_keys_never_reach_a_code_scan_report(tmp_path, report_format):
    # Both call lines are evidence the scan excerpts into every report.
    repository = tmp_path / "repository"
    (repository / "kernel").mkdir(parents=True)
    (repository / "kernel" / "app.csproj").write_text(_SK_PROJECT, encoding="utf-8")
    (repository / "kernel" / "Program.cs").write_text(
        f'builder.AddAzureOpenAIChatCompletion("gpt-4o", "{AZURE}", "{HEX}");\n', encoding="utf-8"
    )
    (repository / "chat").mkdir()
    (repository / "chat" / "go.mod").write_text(_GO_MODULE, encoding="utf-8")
    (repository / "chat" / "main.go").write_text(
        'package main\n\nimport openai "github.com/sashabaranov/go-openai"\n\nfunc main() {\n'
        f'\tconfig := openai.DefaultAzureConfig("{_GO_KEY}", "{AZURE}")\n'
        "\t_ = openai.NewClientWithConfig(config)\n}\n",
        encoding="utf-8",
    )
    report = tmp_path / f"report.{report_format}"
    result = CliRunner().invoke(main, ["code", str(repository), "--format", report_format, "-o", str(report)])
    assert result.exit_code == 0, result.output
    output = report.read_text(encoding="utf-8")
    assert HEX not in output and _GO_KEY not in output
    assert "AddAzureOpenAIChatCompletion" in output and "DefaultAzureConfig" in output
    assert output.count(REDACTED) >= 2
