"""Render findings as GitHub markdown.

All finding text is treated as untrusted (it may quote PR content or come from the model):
* Anything that could open an HTML tag or comment gets a zero-width space after `<`, so
  content cannot inject markup or forge our hidden markers. (Entity-escaping would also
  work, but renders literally inside code spans and mangles e.g. `List<String>`.)
* @mentions are broken with a zero-width space, so content cannot ping people or teams.
* Markdown images and links are defanged.
* Code evidence goes in a fence longer than any backtick run inside it.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from pr_sentinel.filters import SkippedFile
from pr_sentinel.models import CheckResult, CheckStatus, Finding, Severity, Source

SUMMARY_MARKER = "<!-- pr-sentinel:summary -->"
FP_MARKER = "<!-- pr-sentinel:fp={fp} -->"
FP_PATTERN = re.compile(r"<!-- pr-sentinel:fp=([0-9a-f]{16}) -->")

SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}
STATUS_ICON = {
    CheckStatus.PASSED: "✅ passed",
    CheckStatus.FAILED: "❌ failed",
    CheckStatus.ERROR: "⚠️ error",
    CheckStatus.TIMED_OUT: "⏱️ timed out",
    CheckStatus.SKIPPED: "⏭️ skipped",
}
SOURCE_LABEL = {Source.CHECK: "check", Source.RULE: "rule", Source.AI: "AI"}

# GitHub only links a mention after a non-word character, so `pkg@1.2` and emails are left alone.
_MENTION = re.compile(r"(?<![\w.])@(?=[A-Za-z0-9])")
_TAG_OPEN = re.compile(r"<(?=[A-Za-z/!?])")
_ZWSP = "\u200b"
_MAX_BODY = 60_000  # GitHub's comment limit is 65,536 characters


def neutralize(text: str) -> str:
    """Break @mentions and HTML tag/comment openers without changing how the text reads."""
    return _MENTION.sub("@" + _ZWSP, _TAG_OPEN.sub("<" + _ZWSP, text))


def sanitize(text: str, limit: int = 2000) -> str:
    text = neutralize(text)
    text = text.replace("![", "!\\[").replace("](", "]\\(")
    text = text.replace("\r", "")
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text.strip()


def _cell(text: str, limit: int = 160) -> str:
    return sanitize(text, limit).replace("|", "\\|").replace("\n", " ")


def _inline_code(text: str, limit: int = 120) -> str:
    text = text.replace("\n", " ").strip()[:limit]
    text = neutralize(text)
    # Inline code cannot contain its own delimiter run; pick a longer one.
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    ticks = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{ticks}{pad}{text.replace('|', '¦')}{pad}{ticks}"


def code_fence(text: str) -> str:
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    # Code fences render HTML comments literally, but our marker parser reads raw bodies, so
    # PR content must not be able to plant a fingerprint marker that suppresses a finding.
    return f"{fence}\n{neutralize(text)}\n{fence}"


def render_inline_comment(f: Finding) -> str:
    header = f"{SEVERITY_ICON[f.severity]} {f.severity.value.upper()} · {f.category.value}"
    parts = [f"**{header}** — {sanitize(f.title, 200)}"]
    if f.evidence:
        parts.append(code_fence(f.evidence))
    if f.explanation:
        parts.append(sanitize(f.explanation))
    if f.recommendation:
        parts.append(f"**Recommendation:** {sanitize(f.recommendation)}")
    meta = f"Source: {SOURCE_LABEL[f.source]} `{f.rule_id}`"
    if f.source is Source.AI:
        meta += f" · confidence {f.confidence:.2f} · AI-generated, verify before acting"
    parts.append(f"<sub>{sanitize(meta, 300)}</sub>")
    parts.append(FP_MARKER.format(fp=f.fingerprint))
    return "\n\n".join(parts)


@dataclass
class SummaryInput:
    head_sha: str
    findings: list[Finding]
    inline_fingerprints: set[str] = field(default_factory=set)
    previously_posted: set[str] = field(default_factory=set)
    checks: list[CheckResult] | None = None
    checks_note: str = ""
    workflow_conclusion: str | None = None
    ai_enabled: bool = True
    ai_status: str = ""
    ai_dropped: Counter[str] = field(default_factory=Counter)
    files_reviewed: int = 0
    skipped: list[SkippedFile] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _counts(findings: list[Finding]) -> str:
    c = Counter(f.severity for f in findings)
    parts = [f"{SEVERITY_ICON[s]} {c[s]} {s.value}" for s in Severity if c[s]]
    return " · ".join(parts) if parts else "no findings"


def render_summary(s: SummaryInput) -> str:
    out = [
        SUMMARY_MARKER,
        "## PR Sentinel review",
        f"Advisory review of `{s.head_sha[:7]}`: **{_counts(s.findings)}**. "
        "PR Sentinel never approves, blocks, or merges; a maintainer makes that call.",
    ]

    out.append("\n### Checks")
    if s.workflow_conclusion:
        out.append(f"Checks workflow conclusion (reported by GitHub): **{sanitize(s.workflow_conclusion, 40)}**")
    if s.checks:
        out += ["", "| Check | Result | Details |", "| --- | --- | --- |"]
        for c in s.checks:
            details = f"{_cell(c.summary)} ({c.duration_seconds:.0f}s)"
            out.append(f"| {_cell(c.name, 60)} | {STATUS_ICON[c.status]} | {details} |")
        failing = [c for c in s.checks if c.status is not CheckStatus.PASSED and c.output_tail]
        for c in failing[:5]:
            out.append(
                f"<details><summary>Output: {sanitize(c.name, 60)}</summary>\n\n"
                f"{code_fence(c.output_tail[-2500:])}\n\n</details>"
            )
    else:
        out.append("_No check results were available._")
    if s.checks_note:
        out.append(f"> {sanitize(s.checks_note, 400)}")

    out.append("\n### Findings")
    if s.findings:
        out += ["", "| Severity | Source | Location | Finding | |", "| --- | --- | --- | --- | --- |"]
        for f in s.findings:
            where = _inline_code(f.location, 100)
            if f.fingerprint in s.inline_fingerprints:
                status = "inline"
            elif f.fingerprint in s.previously_posted:
                status = "posted earlier"
            else:
                status = ""
            out.append(
                f"| {SEVERITY_ICON[f.severity]} {f.severity.value} | {SOURCE_LABEL[f.source]} | "
                f"{where} | {_cell(f.title)} | {status} |"
            )
        summary_only = [
            f
            for f in s.findings
            if f.fingerprint not in s.inline_fingerprints | s.previously_posted and f.severity is not Severity.INFO
        ]
        if summary_only:
            out.append("<details><summary>Details for findings not posted inline</summary>\n")
            for f in summary_only[:25]:
                out.append(f"**{_inline_code(f.location, 100)}: {sanitize(f.title, 200)}**  ")
                if f.explanation:
                    out.append(f"{sanitize(f.explanation, 600)}  ")
                if f.recommendation:
                    out.append(f"_Recommendation:_ {sanitize(f.recommendation, 600)}\n")
            out.append("</details>")
    else:
        out.append("No issues met the reporting bar.")

    out.append("\n### Coverage")
    if not s.ai_enabled:
        out.append("- AI review: disabled")
    else:
        out.append(f"- AI review: {sanitize(s.ai_status, 300)}; {s.files_reviewed} file(s) reviewed")
        if s.ai_dropped:
            dropped = ", ".join(f"{k.replace('_', ' ')}: {v}" for k, v in sorted(s.ai_dropped.items()))
            out.append(f"- AI findings filtered out: {dropped}")
    if s.skipped:
        out.append(f"<details><summary>{len(s.skipped)} file(s) not reviewed</summary>\n")
        for sk in s.skipped[:100]:
            out.append(f"- {_inline_code(sk.path, 150)}: {sanitize(sk.reason, 120)}")
        out.append("\n</details>")
    for note in s.notes:
        out.append(f"- {sanitize(note, 400)}")

    out.append(
        "\n<sub>Deterministic checks and rules are independent of the AI reviewer. "
        "AI findings are grounded against the diff and filtered for confidence, but can still be wrong.</sub>"
    )
    body = "\n".join(out)
    if len(body) > _MAX_BODY:
        body = body[:_MAX_BODY] + "\n\n_…summary truncated._"
    return body
