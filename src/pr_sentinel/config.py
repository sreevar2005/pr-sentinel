"""Configuration loaded from `.github/pr-sentinel.yml`.

The review job reads this file from the *base* branch checkout (trusted). The checks job
reads it from the PR checkout, which is acceptable because that job is already untrusted
and runs with no secrets and a read-only token.
"""

from __future__ import annotations

import shlex
from enum import StrEnum
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from pr_sentinel.models import Category, Severity

DEFAULT_CONFIG_PATH = Path(".github/pr-sentinel.yml")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CheckSpec(_Strict):
    name: str = Field(min_length=1, max_length=100)
    kind: Literal["command", "gitleaks", "osv"] = "command"
    run: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=600, ge=5, le=3600)
    category: Category = Category.TEST_FAILURE
    severity_on_failure: Severity = Severity.HIGH
    # Extra args appended to the built-in invocation for gitleaks/osv.
    args: list[str] = Field(default_factory=list)

    @field_validator("run", mode="before")
    @classmethod
    def _split_run(cls, v: object) -> object:
        # Accept a string for convenience; it is split into argv, never passed to a shell.
        if isinstance(v, str):
            return shlex.split(v)
        return v


class ForkPolicy(StrEnum):
    ALWAYS = "always"
    REQUIRE_LABEL = "require-label"
    NEVER = "never"


class AIConfig(_Strict):
    enabled: bool = True
    provider: Literal["anthropic", "fake"] = "anthropic"
    model: str = "claude-opus-5-5"
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"
    refusal_fallback: bool = True
    min_confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    max_findings: int = Field(default=15, ge=0, le=50)
    request_timeout_seconds: float = Field(default=240, ge=10, le=900)
    max_retries: int = Field(default=3, ge=0, le=8)
    max_output_tokens: int = Field(default=16000, ge=1024, le=32000)


class Limits(_Strict):
    max_files: int = Field(default=150, ge=1, le=3000)
    max_file_patch_chars: int = Field(default=40_000, ge=1_000)
    max_chunk_chars: int = Field(default=120_000, ge=5_000)
    max_chunks: int = Field(default=4, ge=1, le=20)
    max_artifact_bytes: int = Field(default=2_000_000, ge=10_000)


class ReviewConfig(_Strict):
    ai: AIConfig = Field(default_factory=AIConfig)
    limits: Limits = Field(default_factory=Limits)
    inline_min_severity: Severity = Severity.MEDIUM
    max_inline_comments: int = Field(default=20, ge=0, le=50)
    exclude: list[str] = Field(default_factory=list)
    forks: ForkPolicy = ForkPolicy.REQUIRE_LABEL
    fork_label: str = "sentinel:review"
    disabled_rules: list[str] = Field(default_factory=list)


class SentinelConfig(_Strict):
    version: Literal[1] = 1
    checks: list[CheckSpec] = Field(default_factory=list, max_length=20)
    review: ReviewConfig = Field(default_factory=ReviewConfig)


class ConfigError(ValueError):
    pass


def load_config(path: Path | None = None) -> SentinelConfig:
    path = path or DEFAULT_CONFIG_PATH
    if not path.exists():
        return SentinelConfig()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    try:
        return SentinelConfig.model_validate(raw)
    except ValueError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
