import os
from pathlib import Path

import pytest

from pr_sentinel.envfile import load_env_file, parse_env


def test_parse_env_formats() -> None:
    text = "# comment\n\nGEMINI_API_KEY=abc123\nexport A='x y'\nB=\"q\"\nC=v # note\nnot a line\n"
    assert parse_env(text) == {"GEMINI_API_KEY": "abc123", "A": "x y", "B": "q", "C": "v"}


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for key in ("GEMINI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_API_URL", "GITHUB_ACTIONS"):
        monkeypatch.delenv(key, raising=False)
    return monkeypatch


def test_loads_only_provider_keys(tmp_path: Path, clean_env: pytest.MonkeyPatch) -> None:
    env = tmp_path / ".env"
    env.write_text("GEMINI_API_KEY=k1\nGITHUB_API_URL=https://evil.example\nANTHROPIC_API_KEY=\n")
    assert load_env_file(env) == ["GEMINI_API_KEY"]
    assert os.environ["GEMINI_API_KEY"] == "k1"
    assert "GITHUB_API_URL" not in os.environ, "a .env must not be able to redirect the GitHub token"
    assert "ANTHROPIC_API_KEY" not in os.environ, "empty values are skipped"


def test_real_environment_wins(tmp_path: Path, clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("GEMINI_API_KEY", "from-env")
    (tmp_path / ".env").write_text("GEMINI_API_KEY=from-file\n")
    assert load_env_file(tmp_path / ".env") == []
    assert os.environ["GEMINI_API_KEY"] == "from-env"


def test_disabled_in_github_actions(tmp_path: Path, clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("GITHUB_ACTIONS", "true")
    (tmp_path / ".env").write_text("GEMINI_API_KEY=k\n")
    assert load_env_file(tmp_path / ".env") == []


def test_missing_file(tmp_path: Path) -> None:
    assert load_env_file(tmp_path / ".env") == []
