"""Opaque credentials in common call, command-line and configuration forms are withheld.

Values are random-looking but deterministic, and prefixed provider tokens are
assembled at runtime so this file does not itself trip secret scanners.
"""

from __future__ import annotations

import random
import string

import pytest

from shadowscan.utils import redaction
from shadowscan.utils.redaction import REDACTED, sanitize, sanitize_text

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
    (f'new BasicAuthenticationInterceptor("svc", "{PASSWORD}")', PASSWORD, '"svc"'),
    (f'String auth = Credentials.basic("svc", "{PASSWORD}");', PASSWORD, '"svc"'),
    (f'AwsBasicCredentials.create("svc-reader", "{BASE62}")', BASE62, '"svc-reader"'),
    (f'co = Cohere::Client.new("{BASE62}")', BASE62, "Cohere::Client.new("),
    # Methods reached through a call result or down a builder chain.
    (f'OpenAIClient client = OpenAIOkHttpClient.builder().apiKey("{HEX}").build();', HEX, ".build();"),
    (f'client = OpenAIOkHttpClient.builder()\n    .apiKey("{HEX}")\n    .build()\n', HEX, "    .build()"),
    (f'headers.x().setBearerAuth("{BASE62}");', BASE62, "setBearerAuth("),
    (f'Request.builder().header("x-api-key", "{HEX}").build()', HEX, '.header("x-api-key", '),
    (f'given().auth().oauth2("{BASE62}").when().get("/v1/models")', BASE62, '.get("/v1/models")'),
    (f'given().auth().basic("svc", "{PASSWORD}").when()', PASSWORD, '.basic("svc", '),
    (f'given()\n    .auth()\n    .preemptive()\n    .basic("svc", "{PASSWORD}")\n', PASSWORD,
     '.basic("svc", '),
    (f'client?.setApiKey("{HEX}")', HEX, "client?.setApiKey("),
    # Python f-strings, backtick-only text, Rust paths and C# target-typed construction.
    (f'cred = AzureKeyCredential(f"{HEX}")', HEX, "cred = AzureKeyCredential("),
    (f'openaiKey = f"{HEX}"', HEX, "openaiKey = f"),
    (f"const cred = new AzureKeyCredential(`{HEX}`);", HEX, "new AzureKeyCredential("),
    (f"cred := azcore.NewKeyCredential(`{HEX}`)", HEX, "azcore.NewKeyCredential("),
    (f'let cred = AzureKeyCredential::new("{HEX}".to_string());', HEX, "AzureKeyCredential::new("),
    (f'AzureKeyCredential openai = new("{HEX}");', HEX, "AzureKeyCredential openai = new("),
    (f'private static readonly ApiKeyCredential? Openai = new("{BASE62}");', BASE62, "Openai = new("),
    (f'AzureKeyCredential @openai = new("{HEX}");', HEX, "AzureKeyCredential @openai = new("),
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
    (f"docker login -u svc -p {BASE62} registry.example.com", BASE62, "registry.example.com"),
    (f"docker login -u svc \\\n  -p {BASE62} registry.example.com", BASE62, "registry.example.com"),
    (f"sshpass -p '{PASSWORD}' ssh -p 2222 svc@build.example.com", PASSWORD, "ssh -p 2222 svc@"),
    (f"mysql -h db.example.com -u root -p{BASE62} app", BASE62, "-u root -p"),
    (f'mysqldump -u root -p"{PASSWORD}" app > app.sql', PASSWORD, "> app.sql"),
    (f"az login --service-principal -u app-id -p {PASSWORD} --tenant contoso", PASSWORD, "--tenant contoso"),
    (f"az acr login --name contoso -u svc -p {BASE62}", BASE62, "--name contoso -u svc -p "),
    (f"oc login https://api.example.com:6443 -u dev -p {PASSWORD}", PASSWORD, "-u dev -p "),
    (f"cf login -a https://api.example.com -u dev -p {PASSWORD}", PASSWORD,
     "cf login -a https://api.example.com"),
    (f"echo {HEX} | docker login -u svc --password-stdin contoso.azurecr.io", HEX, "| docker login -u svc"),
    (f"echo -n '{PASSWORD}' | helm registry login -u svc --password-stdin r.example.com", PASSWORD,
     "echo -n '"),
    # Literal defaults of credentials read from the environment.
    (f'const k = process.env.OPENAI_API_KEY || "{HEX}";', HEX, "process.env.OPENAI_API_KEY || "),
    (f'var k = Environment.GetEnvironmentVariable("AZURE_OPENAI_KEY") ?? "{HEX}";', HEX,
     'GetEnvironmentVariable("AZURE_OPENAI_KEY") ?? '),
    (f'k = os.getenv("OPENAI_API_KEY") or "{HEX}"', HEX, 'os.getenv("OPENAI_API_KEY") or '),
    (f'val k = System.getenv("OPENAI_API_KEY") ?: "{BASE62}"', BASE62, 'System.getenv("OPENAI_API_KEY") ?: '),
    (f'k = ENV["OPENAI_API_KEY"] || "{HEX}"', HEX, 'ENV["OPENAI_API_KEY"] || '),
    (f"echo ${{AZURE_OPENAI_KEY:-{HEX}}} | llm --stdin", HEX, "echo ${AZURE_OPENAI_KEY:-"),
    # Dockerfile and environment commands.
    (f"FROM python:3.12\nENV OPENAI_API_KEY {HEX}\n", HEX, "ENV OPENAI_API_KEY"),
    (f"ENV OPENAI_API_KEY \\\n    {HEX}\n", HEX, "ENV OPENAI_API_KEY"),
    (f"ENV OPENAI_BASE_URL=https://api.openai.com/v1 OPENAI_API_KEY={HEX}", HEX, "OPENAI_BASE_URL="),
    (f'setx OPENAI_API_KEY "{HEX}"', HEX, "setx OPENAI_API_KEY"),
    (f"setenv AZURE_OPENAI_KEY {HEX}", HEX, "setenv AZURE_OPENAI_KEY"),
    (f'#define OPENAI_API_KEY "{HEX}"\n', HEX, "#define OPENAI_API_KEY "),
    (f"#  define AZURE_OPENAI_KEY {HEX}\n", HEX, "#  define AZURE_OPENAI_KEY "),
    # R assignments, names ending in a credential word, and a value on the next line.
    (f'api_key <- "{HEX}"\n', HEX, "api_key <- "),
    (f'openai_token <<- "{BASE62}"\n', BASE62, "openai_token <<- "),
    (f'let openaiKey = "{HEX}";', HEX, "let openaiKey = "),
    (f'const azureOpenAIKey = `{BASE62}`;', BASE62, "const azureOpenAIKey = "),
    (f'const openaiKey: string = "{HEX}";', HEX, "const openaiKey: string = "),
    (f'val anthropicKey: String? = "{BASE62}"', BASE62, "val anthropicKey: String? = "),
    (f"OPENAI_KEY ?= {HEX}\n", HEX, "OPENAI_KEY ?= "),
    (f'openai.key={HEX}\n', HEX, "openai.key="),
    (f'{{"anthropicKey": "{BASE62}", "model": "claude-sonnet-4"}}', BASE62, '"model": "claude-sonnet-4"'),
    (f'key = "{HEX}"', HEX, "key = "),
    (f"invalid token:\n{BASE62}\n", BASE62, "invalid token:\n"),
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
    (f'- name: OPENAI_API_KEY\n  value: "{HEX}"  # rotated monthly\n', HEX, "  # rotated monthly"),
    (f"- name: OPENAI_API_KEY\n  value: {BASE62}   # rotated monthly\n", BASE62, "   # rotated monthly"),
    # Unquoted values in flow-style and inline records. Their pattern stopped
    # at ']', so each later sanitization withheld '[REDACTED' again and the
    # marker grew by one ']' per pass.
    (f"{{name: OPENAI_API_KEY, value: {HEX}}}", HEX, "{name: OPENAI_API_KEY, value: "),
    (f"      env: [{{name: OPENAI_API_KEY, value: {HEX}}}]\n", HEX, "}]\n"),
    (f"name=api_key value={HEX}", HEX, "name=api_key value="),
    (f'{{"name": "API_KEY", "value": {BASE62}}}', BASE62, '{"name": "API_KEY", "value": '),
    (f"Name: TOKEN Value: {BASE62}", BASE62, "Name: TOKEN Value: "),
    (f"{{key: token, value: {HEX}}}", HEX, "{key: token, value: "),
    (f'<add key="api_key" value="{HEX}', HEX, '<add key="api_key" value='),
    (f"{{name: OPENAI_API_KEY, value: https://svc:{BASE62}@api.openai.com/v1}}", BASE62,
     "{name: OPENAI_API_KEY"),
]


@pytest.mark.parametrize(("source", "secret", "kept"), FORMS)
def test_credential_forms_are_withheld_with_context_and_lines_preserved(source, secret, kept):
    safe = sanitize_text(source)
    assert secret not in safe
    assert REDACTED in safe
    assert kept in safe
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe
    assert REDACTED + "]" not in safe


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
    # Prose and checks that name a credential without presenting one.
    "Env token should be set before the job runs",
    'requireAuth("admin")',
    'const { user } = useAuth("github");',
    'if (!verifyToken("session")) return;',
    'names = list().stream().of("alpha", "beta2gamma9Delta")',
    'Stream.of("alpha", "beta2gamma9Delta").map(Token::new)',
    # '-p' is a port, a path flag or a password prompt outside a login.
    "docker run -p 8080:80 ghcr.io/example/app",
    "mkdir -p build/output",
    "ssh -p 2222 svc@build.example.com",
    "mysql -u root -p app",
    "docker login -u svc --password-stdin registry.example.com",
    'docker login -u svc -p "$REGISTRY_PASSWORD" registry.example.com',
    "docker login -u svc registry.example.com && docker run -p 8080:80 app",
    "docker login -u svc -p\n",
    # Types, identifiers and ordinary values under names ending in a credential word.
    "def sign(self, msg: bytes, key: EllipticCurvePrivateKey) -> bytes:",
    "key: Ed25519PrivateKey | Ed448PrivateKey",
    "key = Ed25519PrivateKey",
    'sortKey = "createdAtDescending"',
    'cacheKey = "user:123"',
    'const cacheKey: string = "users-by-id";',
    "nextPageToken = response.next_page_token",
    f'monkey = "{HEX}"',
    f'bypass = "{HEX}"',
    f"const openaiKey = `${{prefix}}{HEX}`;",
    f"name:\n{BASE62}\n",
    "#define API_KEY_LENGTH 32",
    "#define GET_TOKEN(name) lookup(name)",
    "if (count<-1) return;",
    "x <- c(1, 2, 3)",
    "token:\nexpired\n",
    # Fallback defaults, construction and paths that present no credential.
    'k = os.environ.get("OPENAI_API_KEY") or "default"',
    'const name = user.name || "anonymous"',
    'const key = process.env.OPENAI_API_KEY || ""',
    'const key = process.env.OPENAI_API_KEY || "<your-api-key>"',
    'const model = process.env.OPENAI_MODEL || "gpt-4o-mini"',
    f'const region = process.env.AZURE_REGION ?? "{HEX}"',
    "echo ${OPENAI_API_KEY:-}",
    "echo ${OPENAI_API_KEY:-$FALLBACK_API_KEY}",
    "echo ${OPENAI_MODEL:-gpt-4o}",
    "echo ${GITHUB_TOKEN:-none} ${OPENAI_API_KEY:-your-api-key}",
    'cred = AzureKeyCredential(f"{key}")',
    'var cred = new AzureKeyCredential($"{prefix}{suffix}");',
    'const label = format(item) ?? "untitled-9"',
    f'Uri endpoint = new("{AZURE}");',
    f'List<string> names = new("{HEX}");',
    f'Map<String,\n    String> names = new("{HEX}");',
    f'if (cache == new("{HEX}")) return;',
    f'items[0] = new("{HEX}");',
    f'c = new("{HEX}");',
    'let kind = TokenKind::Ident("name".to_string());',
    # A URL after '-a' is an API endpoint, not user:password.
    "cf login -a https://api.example.com -u dev",
    "http -a https://example.com/items",
    "az login --use-device-code && az acr login --name contoso",
    "echo ${{ secrets.ACR_PASSWORD }} | docker login -u svc --password-stdin contoso.azurecr.io",
    "echo hello | tee out.txt; docker login -u svc --password-stdin",
])
def test_names_references_placeholders_and_ordinary_arguments_are_preserved(source):
    assert sanitize_text(source) == source


# One form per context-named pass, and values that an earlier pass or an
# earlier sanitization may already have withheld in part.
_PASS_FORMS = [
    "{{name: OPENAI_API_KEY, value: {v}}}",
    '{{"name": "API_KEY", "value": {v}}}',
    "name=api_key value={v}",
    "Name: TOKEN Value: {v}",
    "- name: OPENAI_API_KEY\n  value: {v}\n",
    '<add key="api_key" value="{v}"/>',
    '<add key="api_key" value={v}',
    "<password>{v}</password>",
    '<setting name="ApiKey"><value>{v}</value></setting>',
    "curl -u svc:{v} https://contoso.openai.azure.com/",
    "tool --api-key={v} --verbose",
    "tool --api-key {v} --verbose",
    '["--api-key", "{v}"]',
    'curl -H "x-api-key:{v}" https://api.anthropic.com',
    "docker login -u svc -p {v} registry.example.com",
    "mysql -u root -p{v} app",
    "echo {v} | docker login -u svc --password-stdin r.example.com",
    "ENV OPENAI_API_KEY {v}\n",
    "setx OPENAI_API_KEY {v}",
    "#define OPENAI_API_KEY {v}\n",
    'auth=("svc", "{v}")',
    'AzureKeyCredential("{v}")',
    'builder().apiKey("{v}").build()',
    'AzureKeyCredential openai = new("{v}");',
    'let openaiKey = "{v}";',
    "openai.key={v}\n",
    "token:\n{v}\n",
    'const k = process.env.OPENAI_API_KEY || "{v}";',
    "echo ${{OPENAI_API_KEY:-{v}}}",
]
_PASS_VALUES = [
    HEX, PASSWORD, REDACTED, f"{BASE62[:6]}{REDACTED}{BASE62[6:14]}",
    f"https://svc:{BASE62}@api.example.com/v1", f"<![CDATA[{HEX}]]>",
    f"eyJ{BASE62[:10]}.{BASE62[10:20]}.{BASE62[20:30]}", f"Bearer {HEX}", "",
    f"{HEX[:8]} {HEX[8:16]}", "${OPENAI_API_KEY}",
]


@pytest.mark.parametrize("form", _PASS_FORMS)
def test_every_context_named_pass_is_stable_under_resanitization(form):
    # Reports sanitize an excerpt several times. A pass that withholds part of
    # its own marker again ('[REDACTED' inside '[REDACTED]') grows it by one
    # ']' each time; a stable pass leaves its first result unchanged.
    for value in _PASS_VALUES:
        source = form.format(v=value)
        once = sanitize_text(source)
        assert sanitize_text(once) == once, (source, once)
        if "]" not in value.replace(REDACTED, ""):
            assert REDACTED + "]" not in once, (source, once)


@pytest.mark.parametrize("source", [
    # A nested sensitive assignment inside an unquoted value: the value was
    # cut inside the marker, so each pass withheld '[REDACTED' again.
    f"Value: a.api_key={REDACTED}",
    "Value: sk-...OPENAI_API_KEY=${OPENAI_API_KEY:-$(cat /run/secrets/key)}",
    f"note: {{name: OPENAI_API_KEY, value: {REDACTED}}}",
])
def test_resanitizing_never_grows_a_marker(source):
    once = sanitize_text(source)
    assert sanitize_text(once) == once
    assert REDACTED + "]" not in once


def test_a_record_value_that_is_already_withheld_is_kept():
    for source in (
        f"{{name: TOKEN, value: {REDACTED}}}",
        f"name=api_key value={REDACTED}",
        f"Name: TOKEN Value: {REDACTED}",
    ):
        assert redaction._redact_name_value_pairs(source) == source


@pytest.mark.parametrize("source", [
    'see token.("x")',
    'auth._("x")',
    'Key.__("abc")',
    'call a.secret.("value", "other") here',
])
def test_callees_that_name_nothing_are_ordinary_text(source):
    # 'token.(' has no name after the dot: reading one raised IndexError,
    # which made any scan with such a line (even a comment) incomplete.
    assert sanitize_text(source) == source
    assert sanitize({"description": source}) == {"description": source}


def test_authorization_scheme_spanning_lines_keeps_line_positions():
    # The scheme pattern accepts any whitespace; a newline inside the match
    # must not shift every following excerpt line by one.
    source = "it processes the basic\n        options like `stripnl`.\nimport langchain\n"
    safe = sanitize_text(source)
    assert safe.count("\n") == source.count("\n")
    assert safe.splitlines()[2] == "import langchain"
