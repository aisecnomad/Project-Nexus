from shadowscan.utils.secret_shape import is_credential_value


def test_empty_openai_key_is_not_a_secret():
    assert is_credential_value("") is False
    assert is_credential_value("   ") is False


def test_placeholders_are_not_secrets():
    assert is_credential_value("your-key-here") is False
    assert is_credential_value("changeme") is False
    assert is_credential_value("${OPENAI_API_KEY}") is False
    assert is_credential_value("${OPENAI_API_KEY:-sk-test}") is False


def test_known_prefixes_are_secrets():
    assert is_credential_value("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789") is True
    assert is_credential_value("sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaa") is True
    assert is_credential_value("ghp_exampletokenvalue1234567890abcd") is True
