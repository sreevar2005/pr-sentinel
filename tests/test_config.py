from pathlib import Path

import pytest
from conftest import ROOT

from pr_sentinel.config import ConfigError, ForkPolicy, SentinelConfig, load_config


def test_missing_file_gives_secure_defaults(tmp_path: Path) -> None:
    cfg = load_config(tmp_path / "absent.yml")
    assert cfg.review.forks is ForkPolicy.REQUIRE_LABEL
    assert cfg.review.ai.min_confidence == 0.7
    assert cfg.review.ai.model_name == "claude-opus-5-5"


def test_model_default_follows_provider() -> None:
    cfg = SentinelConfig.model_validate({"review": {"ai": {"provider": "gemini"}}})
    assert cfg.review.ai.model_name == "gemini-flash-latest"


def test_repository_config_is_valid() -> None:
    cfg = load_config(ROOT / ".github" / "pr-sentinel.yml")
    assert {c.kind for c in cfg.checks} == {"command", "gitleaks", "osv"}
    assert "examples/**" in cfg.review.exclude


@pytest.mark.parametrize(
    "text",
    [
        "review: {ai: {min_confidence: 3}}",
        "review: {unknown_key: 1}",  # typos must fail loudly, not silently fall back to defaults
        "checks: [{name: x, kind: shell}]",
        "- not a mapping",
        "review: [unclosed",
    ],
)
def test_invalid_config_is_rejected(tmp_path: Path, text: str) -> None:
    path = tmp_path / "c.yml"
    path.write_text(text)
    with pytest.raises(ConfigError):
        load_config(path)


def test_model_and_effort_are_configurable() -> None:
    cfg = SentinelConfig.model_validate({"review": {"ai": {"model": "claude-sonnet-5-5", "effort": "medium"}}})
    assert (cfg.review.ai.model, cfg.review.ai.effort) == ("claude-sonnet-5-5", "medium")
