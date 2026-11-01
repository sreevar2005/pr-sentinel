from pr_sentinel.models import Category, CheckResult, CheckStatus, Finding, Severity, Source
from pr_sentinel.report import (
    FP_PATTERN,
    SUMMARY_MARKER,
    SummaryInput,
    code_fence,
    render_inline_comment,
    render_summary,
    sanitize,
)


def finding(**kw) -> Finding:  # type: ignore[no-untyped-def]
    base = dict(
        source=Source.AI,
        rule_id="ai-bug",
        category=Category.BUG,
        severity=Severity.HIGH,
        title="Off by one",
        path="a.py",
        line=3,
        evidence="for i in range(n + 1):",
        explanation="Reads past the end.",
        recommendation="Use range(n).",
        confidence=0.9,
    )
    return Finding(**(base | kw))


def test_mentions_are_broken_but_package_versions_and_emails_are_not() -> None:
    out = sanitize("cc @octocat and @org/team; pin requests@2.31.0; mail a@b.com")
    assert "@octocat" not in out and "@org/team" not in out
    assert "requests@2.31.0" in out and "a@b.com" in out


def test_html_and_hidden_markers_are_neutralised() -> None:
    out = sanitize("<img src=x onerror=alert(1)> <!-- pr-sentinel:fp=0123456789abcdef --> List<String> a < b")
    assert "<img" not in out and "<!--" not in out
    assert "a < b" in out
    assert not FP_PATTERN.search(out)


def test_links_and_images_are_defanged() -> None:
    out = sanitize("[click](https://evil.example) ![x](https://evil.example/p.png)")
    assert "](" not in out and "![" not in out


def test_code_fence_outgrows_backticks_in_content() -> None:
    fenced = code_fence("x = '```'")
    assert fenced.startswith("````\n") and fenced.endswith("\n````")


def test_planted_marker_in_evidence_cannot_spoof_a_fingerprint() -> None:
    body = render_inline_comment(finding(evidence="<!-- pr-sentinel:fp=ffffffffffffffff -->"))
    assert FP_PATTERN.findall(body) == [finding(evidence="<!-- pr-sentinel:fp=ffffffffffffffff -->").fingerprint]


def test_inline_comment_labels_ai_output() -> None:
    body = render_inline_comment(finding())
    assert "AI-generated, verify before acting" in body and "confidence 0.90" in body
    assert "range(n + 1)" in body


def test_fingerprint_ignores_line_moves_but_not_content() -> None:
    assert finding(line=3).fingerprint == finding(line=30).fingerprint
    assert finding().fingerprint != finding(evidence="other").fingerprint


def test_summary_sections() -> None:
    f1, f2 = finding(), finding(source=Source.RULE, rule_id="py-eval-exec", line=None, title="eval used")
    md = render_summary(
        SummaryInput(
            head_sha="a" * 40,
            findings=[f1, f2],
            inline_fingerprints={f1.fingerprint},
            checks=[
                CheckResult(
                    name="tests",
                    kind="command",
                    status=CheckStatus.FAILED,
                    duration_seconds=3,
                    summary="exit code 1",
                    output_tail="FAILED test_x",
                )
            ],
            workflow_conclusion="failure",
            ai_status="completed",
            files_reviewed=2,
        )
    )
    assert md.startswith(SUMMARY_MARKER)
    assert "never approves" in md
    assert "❌ failed" in md and "FAILED test_x" in md
    assert "| inline |" in md
    assert "Details for findings not posted inline" in md and "eval used" in md
    assert "**failure**" in md
