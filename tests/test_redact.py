from conftest import fake_aws_key, fake_github_token

from pr_sentinel.redact import find_secrets, redact, shannon_entropy


def test_detects_provider_tokens() -> None:
    line = f'token = "{fake_github_token()}"  # aws {fake_aws_key()}'
    ids = {m.rule_id for m in find_secrets(line)}
    assert {"github-token", "aws-access-key-id"} <= ids


def test_redact_removes_value_completely() -> None:
    token = fake_github_token()
    out = redact(f"Authorization: Bearer {token}\nnext line")
    assert token not in out
    assert "[REDACTED:github-token]" in out
    assert out.endswith("next line")


def test_generic_assignment_requires_entropy() -> None:
    assert find_secrets('password = "aaaaaaaaaaaaaaaa"') == []
    assert find_secrets('api_key = "changeme"') == []
    assert find_secrets('api_key = "${API_KEY_FROM_ENV}"') == []
    hits = find_secrets('client_secret = "q8Zr2LmV9xTe4KpW7nBy3HsD6fJc1Ua"')
    assert [h.rule_id for h in hits] == ["generic-secret"]


def test_private_key_header_and_url_credentials() -> None:
    assert find_secrets("-----BEGIN RSA PRIVATE KEY-----")[0].rule_id == "private-key"
    hit = find_secrets("DATABASE_URL=postgres://app:s3cr3tpass@db:5432/x")
    assert hit and hit[0].rule_id == "url-credentials"
    assert "s3cr3tpass" not in redact("postgres://app:s3cr3tpass@db:5432/x")


def test_entropy_ordering() -> None:
    assert shannon_entropy("aaaa") < shannon_entropy("a1B2c3D4")
    assert shannon_entropy("") == 0.0


def test_plain_code_is_untouched() -> None:
    code = "def handler(event):\n    return {'statusCode': 200}"
    assert redact(code) == code
