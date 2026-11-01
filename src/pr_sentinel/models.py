"""Core domain models shared by every stage of the pipeline."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def at_least(self, other: Severity) -> bool:
        return self.rank >= other.rank


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Source(StrEnum):
    """Where a finding came from. Deterministic sources are never filtered by confidence."""

    CHECK = "check"  # external tool run in the untrusted checks job (gitleaks, osv, tests)
    RULE = "rule"  # built-in deterministic diff rule run in the trusted review job
    AI = "ai"  # model-generated, grounded and validated

    @property
    def deterministic(self) -> bool:
        return self is not Source.AI


class Category(StrEnum):
    BUG = "bug"
    SECURITY = "security"
    SECRET = "secret"  # noqa: S105 - category name, not a credential
    DEPENDENCY = "dependency"
    CI_SECURITY = "ci-security"
    PROMPT_INJECTION = "prompt-injection"
    RELIABILITY = "reliability"
    PERFORMANCE = "performance"
    RISKY_CHANGE = "risky-change"
    TEST_FAILURE = "test-failure"
    LINT = "lint"


_WS = re.compile(r"\s+")


class Finding(BaseModel):
    """A single actionable issue. `line` is a RIGHT-side (new file) line number."""

    model_config = ConfigDict(frozen=True)

    source: Source
    rule_id: str = Field(min_length=1, max_length=80)
    category: Category
    severity: Severity
    title: str = Field(min_length=1, max_length=200)
    path: str | None = None
    line: int | None = Field(default=None, ge=1)
    evidence: str = Field(default="", max_length=500)
    explanation: str = Field(default="", max_length=2000)
    recommendation: str = Field(default="", max_length=2000)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    @property
    def fingerprint(self) -> str:
        """Stable identity across pushes.

        Built from the evidence text rather than the line number so a finding does not
        get re-posted just because unrelated lines above it moved.
        """
        evidence = _WS.sub(" ", self.evidence).strip().lower()
        raw = "|".join([self.source, self.rule_id, self.path or "", evidence or self.title.lower()])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def location(self) -> str:
        if self.path and self.line:
            return f"{self.path}:{self.line}"
        return self.path or "(repository)"


class CheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"  # the tool itself could not run (missing binary, crash)
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"


class CheckResult(BaseModel):
    name: str = Field(max_length=100)
    kind: str = Field(max_length=40)
    status: CheckStatus
    duration_seconds: float = Field(ge=0)
    exit_code: int | None = None
    summary: str = Field(default="", max_length=500)
    output_tail: str = Field(default="", max_length=4000)
    findings: list[Finding] = Field(default_factory=list, max_length=200)


class ChecksArtifact(BaseModel):
    """Produced by the untrusted checks job and consumed (as untrusted data) by the review job."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    pr_number: int = Field(ge=1)
    head_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    checks: list[CheckResult] = Field(default_factory=list, max_length=50)
