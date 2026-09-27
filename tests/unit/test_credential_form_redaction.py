"""Opaque credentials in common call, command-line and configuration forms are withheld.

Values are random-looking but deterministic, and prefixed provider tokens are
assembled at runtime so this file does not itself trip secret scanners.
"""

from __future__ import annotations

import random
import string

import pytest

from shadowscan.utils.redaction import REDACTED, sanitize_text

_RANDOM = random.Random(20260927)


ALNUM = string.ascii_letters + string.digits
HEXDIGITS = "0123456789abcdef"
AZURE = "https://contoso.openai.azure.com/"


def _random(alphabet: str, length: int) -> str:
    return "".join(_RANDOM.choice(alphabet) for _ in range(length))


HEX = _random(HEXDIGITS, 32)  # Azure OpenAI / Cognitive Services key shape
BASE62 = _random(ALNUM, 40)
BASE64 = _random(ALNUM + "+/", 86) + "=="  # storage account key shape
PASSWORD = _random(ALNUM + "!@%^*-_.~", 20)

# (source, secret, text that must survive)
FORMS: list[tuple[str, str, str]] = [
    # Credential constructors and helpers with positional string arguments.
    ('var client = new OpenAIClient(new Uri("https://contoso.openai.azure.com/"), '
     f'new AzureKeyCredential("{HEX}"));', HEX, '"https://contoso.openai.azure.com/"'),
    (f'OpenAIClient client = new OpenAIClientBuilder().endpoint("{AZURE}")'
     f'.credential(new AzureKeyCredential("{HEX}")).buildClient();', HEX, AZURE),
    (f'client = ChatCompletionsClient("https://contoso.openai.azure.com/", AzureKeyCredential("{HEX}"))',
     HEX, "ChatCompletionsClient"),
    (f'const azureKey = new AzureKeyCredential("{HEX}");', HEX, "const azureKey = new AzureKeyCredential("),
    ('client, err := azopenai.NewClientWithKeyCredential("https://contoso.openai.azure.com/", '
     f'azcore.NewKeyCredential("{HEX}"), nil)', HEX, "https://contoso.openai.azure.com/"),
    (f'var cred = new KeyCredential("{BASE62}");', BASE62, "var cred = new KeyCredential("),
    (f'var chat = new ChatClient("gpt-4o", new ApiKeyCredential("{BASE62}"));', BASE62, '"gpt-4o"'),
    (f'var cred = new AzureNamedKeyCredential("contosostorage", "{BASE64}");', BASE64, '"contosostorage"'),
    (f'r = requests.post(url, auth=HTTPBasicAuth("svc-ingest", "{PASSWORD}"))', PASSWORD, '"svc-ingest"'),
    (f'session = aiohttp.ClientSession(auth=aiohttp.BasicAuth("svc", "{PASSWORD}"))', PASSWORD, '"svc"'),
    (f'r = requests.get("https://api.openai.com/v1/models", auth=("svc", "{PASSWORD}"))', PASSWORD, '"svc"'),
    (f'es = Elasticsearch(hosts, basic_auth=("elastic", "{PASSWORD}"))', PASSWORD, '"elastic"'),
    (f'client.setBearerToken("{BASE62}");', BASE62, "setBearerToken("),
    (f'client := openai.NewClient(option.WithAPIKey("{BASE62}"))', BASE62, "option.WithAPIKey("),
    (f'new PasswordAuthentication("svc", "{PASSWORD}".toCharArray())', PASSWORD, '"svc"'),
    (f'co = cohere.Client("{BASE62}")', BASE62, "cohere.Client("),
    (f'client.login("svc@example.test", "{PASSWORD}")', PASSWORD, '"svc@example.test"'),
    (f'cred = AzureKeyCredential("{HEX}" + suffix)', HEX, "AzureKeyCredential("),
    (f'cred = AzureKeyCredential("{HEX}\nnext_line()\n', HEX, "\nnext_line()\n"),
    (f'cred = AzureKeyCredential(\n    "{HEX}"\n', HEX, "AzureKeyCredential(\n"),
    # Command lines in shell scripts, CI YAML, Makefiles and argv lists.
    (f'curl -u "svc:{HEX}" https://contoso.openai.azure.com/openai/deployments', HEX,
     '"svc:'),
    (f"curl --api-key={HEX} https://api.openai.com/v1/models", HEX, "https://api.openai.com/v1/models"),
    (f"curl --api-key={HEX}=--token=chained", HEX, "curl --api-key="),
    (f'echo "prefix"--token {HEX}', HEX, 'echo "prefix"--token '),
    (f"curl --api-key {HEX} https://api.openai.com/v1/models", HEX, "https://api.openai.com/v1/models"),
    (f"openai-proxy --token {BASE62} --port 8080", BASE62, "--port 8080"),
    (f"llm-gateway --password={PASSWORD} --verbose", PASSWORD, "--verbose"),
    (f"curl --api-key \\\n  {HEX} https://api.openai.com/v1/models", HEX, "https://api.openai.com/v1/models"),
    (f'curl -H "Authorization: Bearer {HEX}" https://api.openai.com/v1/models', HEX, "Authorization"),
    (f'curl -H "api-key: {HEX}" https://contoso.openai.azure.com/', HEX, "api-key"),
    (f'curl -H "x-api-key: {HEX}" https://api.anthropic.com/v1/messages', HEX, "x-api-key"),
    (f'curl -H "x-api-key:{HEX}" https://api.anthropic.com/v1/messages', HEX, '-H "x-api-key:'),
    (f'curl -H "Ocp-Apim-Subscription-Key: {HEX}" https://contoso.azure-api.net/', HEX, "Ocp-Apim"),
    (f"      - run: curl --api-key {HEX} https://api.openai.com/v1/models", HEX, "- run: curl"),
    (f"smoke:\n\tcurl -u svc:{HEX} {AZURE}openai", HEX, AZURE),
    (f'args: ["--api-key", "{HEX}", "--model", "gpt-4o"]', HEX, '"--model", "gpt-4o"'),
    (f"args:\n  - --api-key\n  - {HEX}\n  - --model\n  - gpt-4o\n", HEX, "- gpt-4o"),
    (f'command: ["server", "--api-key={HEX}"]', HEX, '"server"'),
    # Dockerfile and environment commands.
    (f"FROM python:3.12\nENV OPENAI_API_KEY {HEX}\n", HEX, "ENV OPENAI_API_KEY"),
    (f"ENV OPENAI_API_KEY \\\n    {HEX}\n", HEX, "ENV OPENAI_API_KEY"),
    (f"ENV OPENAI_BASE_URL=https://api.openai.com/v1 OPENAI_API_KEY={HEX}", HEX, "OPENAI_BASE_URL="),
    (f'setx OPENAI_API_KEY "{HEX}"', HEX, "setx OPENAI_API_KEY"),
    (f"setenv AZURE_OPENAI_KEY {HEX}", HEX, "setenv AZURE_OPENAI_KEY"),
    # XML and .NET configuration.
    (f"<password>{PASSWORD}</password>", PASSWORD, "</password>"),
    (f"<apiKey>{HEX}</apiKey>", HEX, "</apiKey>"),
    (f"<api-key>\n  {HEX}\n</api-key>", HEX, "</api-key>"),
    (f"<password><![CDATA[{PASSWORD}]]></password>", PASSWORD, "</password>"),
    (f'<add key="OpenAIApiKey" value="{HEX}" />', HEX, 'key="OpenAIApiKey"'),
    (f'<add key="AzureOpenAI:ApiKey" value="{HEX}"/>', HEX, 'key="AzureOpenAI:ApiKey"'),
    (f'<setting name="ApiKey" serializeAs="String"><value>{HEX}</value></setting>', HEX, "</setting>"),
    (f'<entry key="openai.api.key">{HEX}</entry>', HEX, "</entry>"),
    (f'<property name="password" value="{PASSWORD}"/>', PASSWORD, 'name="password"'),
    (f'<Parameter Name="ApiKey" Value="{HEX}"/>', HEX, 'Name="ApiKey"'),
    # Properties, INI and YAML forms (already covered; kept as regressions).
    (f"spring.ai.openai.api-key={HEX}", HEX, "spring.ai.openai.api-key="),
    (f"[openai]\napi_key = {HEX}\n", HEX, "[openai]"),
    (f"openai:\n  api_key: {HEX}\n", HEX, "openai:"),
    (f'$headers = @{{"api-key" = "{HEX}"}}', HEX, '$headers = @{"api-key" = '),
    (f'[openai]\n"api-key" = "{HEX}"\n', HEX, '"api-key" = '),
    (f"if token:\n    return token\nopenai:\n  api_key: {HEX}\n", HEX, "    return token"),
    # Name/value records in container environments and parameter lists.
    (f"env:\n  - name: OPENAI_API_KEY\n    value: {HEX}\n  - name: MODEL\n    value: gpt-4o\n", HEX,
     "value: gpt-4o"),
    (f'{{"name": "AZURE_OPENAI_API_KEY", "value": "{HEX}"}}', HEX, '"AZURE_OPENAI_API_KEY"'),
    (f'environment = [{{ name = "OPENAI_API_KEY", value = "{HEX}" }}]', HEX, '"OPENAI_API_KEY"'),
    (f"- name: OPENAI_API_KEY\n  value: |\n    {HEX}\n- name: MODEL\n", HEX, "- name: MODEL"),
]


@pytest.mark.parametrize(("source", "secret", "kept"), FORMS)
def test_credential_forms_are_withheld_with_context_and_lines_preserved(source, secret, kept):
    safe = sanitize_text(source)
    assert secret not in safe
    assert REDACTED in safe
    assert kept in safe
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe


def _prefixed(prefix: str, body: str) -> str:
    return prefix + body


TOKENS = [
    _prefixed("ya29" + ".", "a0Ad52N3" + _random(string.ascii_letters + string.digits + "_-", 60)),
    _prefixed("1//0", "g" + _random(string.ascii_letters + string.digits + "_-", 60)),
    _prefixed("GOCSPX" + "-", _random(string.ascii_letters + string.digits, 28)),
    _prefixed("xapp" + "-", "1-A0B1C2D3E4F-" + _random(string.digits, 13) + "-" + _random(HEXDIGITS, 64)),
    _prefixed("xoxe" + ".xoxp-", "1-" + _random(string.ascii_letters + string.digits, 40)),
    _prefixed("xoxe" + "-", "1-" + _random(string.ascii_letters + string.digits, 40)),
    _prefixed("glrt" + "-", _random(string.ascii_letters + string.digits + "_-", 20)),
    _prefixed("glptt" + "-", _random("0123456789abcdef", 40)),
    _prefixed("gldt" + "-", _random(string.ascii_letters + string.digits + "_-", 20)),
    _prefixed("GR1348941", _random(string.ascii_letters + string.digits + "_-", 20)),
    _prefixed("npm" + "_", _random(string.ascii_letters + string.digits, 36)),
    _prefixed("pypi" + "-AgEIcHlwaS5vcmc", _random(string.ascii_letters + string.digits + "_-", 70)),
    _prefixed("dop" + "_v1_", _random("0123456789abcdef", 64)),
    _prefixed("sk" + "_live_", _random(string.ascii_letters + string.digits, 24)),
    _prefixed("SG" + ".", _random(ALNUM, 22) + "." + _random(string.ascii_letters, 43)),
    _prefixed("dapi", _random("0123456789abcdef", 32)),
    _prefixed("shpat" + "_", _random("0123456789abcdef", 32)),
    _prefixed("ATATT3", _random(string.ascii_letters + string.digits + "_-", 60)),
    _prefixed("lin" + "_api_", _random(string.ascii_letters + string.digits, 40)),
    _prefixed("ntn" + "_", _random(string.ascii_letters + string.digits, 46)),
    _prefixed("PMAK" + "-", _random("0123456789abcdef", 24) + "-" + _random("0123456789abcdef", 34)),
    _prefixed("dp" + ".pt.", _random(string.ascii_letters + string.digits, 43)),
    _prefixed("sbp" + "_", _random("0123456789abcdef", 40)),
    _prefixed("glsa" + "_", _random(ALNUM, 32) + "_" + _random(HEXDIGITS, 8)),
    _prefixed("sntrys" + "_", _random(string.ascii_letters + string.digits, 60)),
    _prefixed("hvs" + ".", _random(string.ascii_letters + string.digits + "_-", 90)),
    _prefixed(_random(ALNUM, 14), ".atlasv1." + _random(string.ascii_letters, 64)),
    _prefixed("sk" + "_", _random("0123456789abcdef", 48)),
]


@pytest.mark.parametrize("secret", TOKENS)
def test_recognizable_token_prefixes_are_withheld_in_plain_text(secret):
    source = f'fixtures = ["{secret}", "https://api.openai.com/v1"]\nnote {secret} in prose'
    safe = sanitize_text(source)
    assert secret not in safe
    assert "https://api.openai.com/v1" in safe
    assert safe.count(REDACTED) >= 2
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize("source", [
    'client = AzureKeyCredential(os.environ["AZURE_OPENAI_API_KEY"])',
    'var cred = new AzureKeyCredential(Environment.GetEnvironmentVariable("AZURE_OPENAI_API_KEY"));',
    'get_bearer_token_provider(DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default")',
    'cred = AzureKeyCredential("<your-api-key>")',
    'cred = AzureKeyCredential("YOUR_API_KEY")',
    'cred = AzureKeyCredential("your-azure-openai-key")',
    'var chat = new ChatClient("gpt-4o-mini", new ApiKeyCredential(key));',
    'AzureNamedKeyCredential("account", key)',
    'user_id = Column(Integer, ForeignKey("users.id"))',
    'ids = tokenizer.encode("hello world")',
    'raise KeyError("api_version")',
    'enc = tiktoken.encoding_for_model("gpt-4o")',
    'n = count_tokens("text-embedding-3-small")',
    'client = openai.NewClient(os.Getenv("OPENAI_API_KEY"))',
    "94 | Cosmetic | Spelling error on Login ('log|n')",
    "tool --token-file /run/secrets/token",
    "tool --token --verbose",
    'args: ["--password=--verbose"]',
    "curl --api-key $OPENAI_API_KEY https://api.openai.com",
    'curl --api-key "${OPENAI_API_KEY}" https://api.openai.com',
    'echo "$TOKEN" | docker login --password-stdin -u user',
    "usage: tool [--token TOKEN] [--api-key API_KEY]",
    "Use --token to authenticate against the API.",
    'parser.add_argument("--api-key", help="OpenAI key")',
    "docker run -u 1000:1000 image",
    'curl -u "$USER:$PASS" https://example.test',
    "python -u script.py --model gpt-4o",
    'curl -H "Content-Type:application/json" https://api.openai.com',
    'setx OPENAI_API_KEY "%OPENAI_API_KEY%"',
    "ENV OPENAI_BASE_URL https://api.openai.com/v1",
    "<password>${env.PASSWORD}</password>",
    '<add key="Endpoint" value="https://contoso.openai.azure.com/"/>',
    "List<Token> tokens = new ArrayList<>();",
    '<input type="password" name="password" value="">',
    "env:\n  - name: MODEL\n    value: gpt-4o\n",
    "env:\n  - name: OPENAI_API_KEY\n    valueFrom:\n      secretKeyRef: {name: openai, key: api-key}\n",
    "requests.get(url, auth=(username, password))",
    'if headers["token"] == "expected": pass',
    'value = lookup("token") or "default"',
])
def test_names_references_placeholders_and_ordinary_arguments_are_preserved(source):
    assert sanitize_text(source) == source


def test_authorization_scheme_spanning_lines_keeps_line_positions():
    # The scheme pattern accepts any whitespace; a newline inside the match
    # must not shift every following excerpt line by one.
    source = "it processes the basic\n        options like `stripnl`.\nimport langchain\n"
    safe = sanitize_text(source)
    assert safe.count("\n") == source.count("\n")
    assert safe.splitlines()[2] == "import langchain"
