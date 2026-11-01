"""Review orchestration for the trusted `workflow_run` job.

Trust boundaries handled here:
* The checks artifact was produced by PR-controlled code. It is size-capped, schema
  validated, and its PR number is only trusted after the PR's head SHA (from the API)
  matches `workflow_run.head_sha` (from GitHub's event payload).
* The diff comes from the GitHub API, never from a checkout of PR code.
* Fork PRs only get an AI review (which spends API credit) when the configured policy allows.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from pr_sentinel.ai.provider import ProviderError, ReviewProvider
from pr_sentinel.ai.reviewer import AIReviewer, AIReviewResult
from pr_sentinel.config import ForkPolicy, SentinelConfig
from pr_sentinel.diff import FileDiff
from pr_sentinel.filters import SkippedFile, select_files
from pr_sentinel.github import GitHubClient, GitHubError
from pr_sentinel.models import CheckResult, ChecksArtifact, Finding, Severity
from pr_sentinel.report import (
    FP_PATTERN,
    SUMMARY_MARKER,
    SummaryInput,
    render_inline_comment,
    render_summary,
)
from pr_sentinel.rules import run_rules

log = logging.getLogger(__name__)

ARTIFACT_FILE = "checks.json"
BOT_LOGIN = "github-actions[bot]"


class PipelineAbort(Exception):
    """Stop without posting (stale run, closed PR, policy). Not a failure."""


@dataclass
class AnalysisResult:
    findings: list[Finding]
    skipped: list[SkippedFile]
    ai: AIReviewResult | None
    ai_status: str
    files: list[FileDiff]


@dataclass
class ReviewOutcome:
    summary: str
    inline: list[dict[str, Any]] = field(default_factory=list)
    posted: bool = False
    aborted_reason: str = ""


ProviderFactory = Callable[[], ReviewProvider]


def load_artifact(directory: Path | None, max_bytes: int) -> tuple[ChecksArtifact | None, str]:
    if directory is None:
        return None, "no checks artifact supplied"
    path = directory / ARTIFACT_FILE
    if not path.is_file():
        return None, "checks artifact not found (the checks job may have failed before uploading)"
    if path.stat().st_size > max_bytes:
        return None, f"checks artifact larger than {max_bytes} bytes; ignored"
    try:
        return ChecksArtifact.model_validate_json(path.read_bytes()), ""
    except ValidationError as exc:
        return None, f"checks artifact failed validation ({exc.error_count()} error(s)); ignored"


def files_from_api(items: list[dict[str, Any]]) -> list[FileDiff]:
    return [
        FileDiff.from_patch(
            path=str(it["filename"]),
            patch=it.get("patch"),
            status=str(it.get("status", "modified")),
            previous_path=it.get("previous_filename"),
        )
        for it in items
    ]


def merge_findings(groups: list[list[Finding]]) -> list[Finding]:
    """Deduplicate across sources. Deterministic findings win over AI at the same spot."""
    best: dict[str, Finding] = {}
    by_fp: set[str] = set()
    for f in (f for g in groups for f in g):
        if f.fingerprint in by_fp:
            continue
        by_fp.add(f.fingerprint)
        # Line-level findings collide by location; file/repo-level ones (a failing test run,
        # several advisories in one lockfile) are distinct unless their fingerprints match.
        key = f"{f.path}:{f.line}:{f.category.value}" if f.line is not None else f"fp:{f.fingerprint}"
        prev = best.get(key)
        if prev is None:
            best[key] = f
            continue
        if (f.source.deterministic, f.severity.rank) > (prev.source.deterministic, prev.severity.rank):
            best[key] = f
    return sorted(best.values(), key=lambda f: (-f.severity.rank, not f.source.deterministic, f.location))


def analyze(
    files: list[FileDiff],
    config: SentinelConfig,
    provider_factory: ProviderFactory | None,
    *,
    check_findings: list[Finding] | None = None,
    pr_title: str = "",
    pr_body: str = "",
    run_ai: bool = True,
) -> AnalysisResult:
    rc = config.review
    selected, skipped = select_files(files, rc.exclude, rc.limits.max_files, rc.limits.max_file_patch_chars)
    rule_findings = run_rules(selected, rc.disabled_rules)

    ai_result: AIReviewResult | None = None
    if not rc.ai.enabled:
        ai_status = "disabled in configuration"
    elif not run_ai:
        ai_status = "skipped by fork policy"
    elif provider_factory is None:
        ai_status = "unavailable (no provider configured)"
    elif not selected:
        ai_status = "nothing to review"
    else:
        try:
            provider = provider_factory()
        except ProviderError as exc:
            ai_status = f"unavailable ({exc})"
        else:
            ai_result = AIReviewer(provider, rc.ai, rc.limits).review(selected, pr_title, pr_body)
            skipped += ai_result.skipped
            if ai_result.chunks_total == 0:
                ai_status = "no files fit the AI budget"
            elif ai_result.chunks_failed == ai_result.chunks_total:
                ai_status = "failed: " + "; ".join(ai_result.errors[:3])
            elif ai_result.degraded:
                ai_status = (
                    f"partial ({ai_result.chunks_failed}/{ai_result.chunks_total} request(s) failed: "
                    + "; ".join(ai_result.errors[:2])
                    + ")"
                )
            else:
                ai_status = f"completed with `{ai_result.model}`"

    findings = merge_findings(
        [
            check_findings or [],
            rule_findings,
            ai_result.findings if ai_result else [],
        ]
    )
    return AnalysisResult(findings=findings, skipped=skipped, ai=ai_result, ai_status=ai_status, files=files)


def select_inline(
    findings: list[Finding],
    files: list[FileDiff],
    already_posted: set[str],
    min_severity: Severity,
    limit: int,
) -> list[Finding]:
    """Findings eligible for a line comment: severe enough, new, and on a line GitHub will accept."""
    commentable = {fd.path: fd.right_side for fd in files if not fd.binary}
    chosen: list[Finding] = []
    for f in findings:
        if len(chosen) >= limit:
            break
        if not f.severity.at_least(min_severity) or f.fingerprint in already_posted:
            continue
        if f.path is None or f.line is None or f.line not in commentable.get(f.path, {}):
            continue
        chosen.append(f)
    return chosen


def _bot_comments(items: list[dict[str, Any]], bot_login: str) -> list[dict[str, Any]]:
    # Only trust markers in comments we authored; anyone can type a marker into a comment.
    return [c for c in items if (c.get("user") or {}).get("login") == bot_login]


class ReviewPipeline:
    def __init__(
        self,
        gh: GitHubClient,
        config: SentinelConfig,
        provider_factory: ProviderFactory | None,
        bot_login: str = BOT_LOGIN,
    ) -> None:
        self.gh = gh
        self.config = config
        self.provider_factory = provider_factory
        self.bot_login = bot_login

    def run(self, event: dict[str, Any], artifact_dir: Path | None, dry_run: bool = False) -> ReviewOutcome:
        wr = event.get("workflow_run") or {}
        head_sha = str(wr.get("head_sha", ""))
        conclusion = wr.get("conclusion")
        if wr.get("event") != "pull_request" or not head_sha:
            raise PipelineAbort("triggering run was not a pull_request run")
        if conclusion in ("skipped", "cancelled"):
            raise PipelineAbort(f"checks run was {conclusion}")

        artifact, artifact_note = load_artifact(artifact_dir, self.config.review.limits.max_artifact_bytes)
        pr_number = artifact.pr_number if artifact else None
        if pr_number is None:
            prs = wr.get("pull_requests") or []  # populated for same-repo PRs only
            pr_number = int(prs[0]["number"]) if prs else None
        if pr_number is None:
            raise PipelineAbort("could not determine the pull request number")

        pr = self.gh.get_pull(pr_number)
        if (pr.get("head") or {}).get("sha") != head_sha:
            raise PipelineAbort("PR head has moved on since the checks ran (a newer run will review it)")
        if artifact and artifact.head_sha != head_sha:
            artifact, artifact_note = None, "checks artifact is for a different commit; ignored"
        if pr.get("state") != "open":
            raise PipelineAbort("pull request is not open")

        base_repo = (pr.get("base") or {}).get("repo", {}).get("full_name")
        head_repo = ((pr.get("head") or {}).get("repo") or {}).get("full_name")
        is_fork = head_repo != base_repo
        labels = {lbl.get("name") for lbl in pr.get("labels", [])}
        policy = self.config.review.forks
        run_ai = (
            (not is_fork)
            or policy is ForkPolicy.ALWAYS
            or (policy is ForkPolicy.REQUIRE_LABEL and self.config.review.fork_label in labels)
        )
        notes: list[str] = []
        if is_fork and not run_ai:
            notes.append(
                f"Fork PR: AI review needs the `{self.config.review.fork_label}` label "
                "from a maintainer (deterministic rules still ran)."
            )

        files = files_from_api(self.gh.list_pull_files(pr_number))
        checks: list[CheckResult] | None = artifact.checks if artifact else None
        check_findings = [f for c in checks for f in c.findings] if checks else []

        result = analyze(
            files,
            self.config,
            self.provider_factory,
            check_findings=check_findings,
            pr_title=str(pr.get("title") or ""),
            pr_body=str(pr.get("body") or ""),
            run_ai=run_ai,
        )

        posted_fps: set[str] = set()
        for c in _bot_comments(self.gh.list_review_comments(pr_number), self.bot_login):
            posted_fps.update(FP_PATTERN.findall(c.get("body") or ""))

        rc = self.config.review
        inline = select_inline(result.findings, files, posted_fps, rc.inline_min_severity, rc.max_inline_comments)
        comments = [{"path": f.path, "line": f.line, "side": "RIGHT", "body": render_inline_comment(f)} for f in inline]
        summary_input = SummaryInput(
            head_sha=head_sha,
            findings=result.findings,
            inline_fingerprints={f.fingerprint for f in inline},
            previously_posted=posted_fps,
            checks=checks,
            checks_note=artifact_note
            or (
                "Check results come from this PR's own `pull_request` workflow; "
                "the authoritative status is the GitHub check run."
            ),
            workflow_conclusion=str(conclusion) if conclusion else None,
            ai_enabled=rc.ai.enabled,
            ai_status=result.ai_status,
            ai_dropped=result.ai.dropped if result.ai else Counter(),
            files_reviewed=len(set(result.ai.files_reviewed)) if result.ai else 0,
            skipped=result.skipped,
            notes=notes,
        )
        outcome = ReviewOutcome(summary=render_summary(summary_input), inline=comments)
        if dry_run:
            return outcome

        if comments:
            body = f"PR Sentinel found {len(comments)} new issue(s) on changed lines. Summary in the PR conversation."
            try:
                self.gh.create_comment_review(pr_number, head_sha, body, comments)
            except GitHubError as exc:
                if exc.status != 422:
                    raise
                # 422: GitHub rejected a line position (e.g. diff changed). Keep everything in the summary.
                log.warning("inline review rejected (%s); falling back to summary only", exc)
                summary_input.inline_fingerprints = set()
                summary_input.notes.append("Inline comments could not be placed; all findings are listed above.")
                outcome.summary = render_summary(summary_input)
                outcome.inline = []

        existing = next(
            (
                c
                for c in _bot_comments(self.gh.list_issue_comments(pr_number), self.bot_login)
                if SUMMARY_MARKER in (c.get("body") or "")
            ),
            None,
        )
        if existing:
            self.gh.update_issue_comment(int(existing["id"]), outcome.summary)
        else:
            self.gh.create_issue_comment(pr_number, outcome.summary)
        outcome.posted = True
        return outcome


def read_event(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("event payload must be a JSON object")
    return data
