from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from conftest import fake_github_token

from pr_sentinel.checks import CheckRunner, parse_gitleaks, parse_osv
from pr_sentinel.config import CheckSpec
from pr_sentinel.models import Category, CheckStatus, Severity


def py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_passing_and_failing_commands(tmp_path: Path) -> None:
    runner = CheckRunner(tmp_path)
    ok = runner.run(CheckSpec(name="ok", run=py("print('fine')")))
    assert ok.status is CheckStatus.PASSED and ok.findings == [] and ok.output_tail == ""

    bad = runner.run(CheckSpec(name="tests", run=py("import sys; print('1 failed'); sys.exit(3)")))
    assert bad.status is CheckStatus.FAILED and bad.exit_code == 3
    assert "1 failed" in bad.output_tail
    [f] = bad.findings
    assert f.category is Category.TEST_FAILURE and f.severity is Severity.HIGH


def test_timeout_and_missing_binary(tmp_path: Path) -> None:
    runner = CheckRunner(tmp_path)
    slow = runner.run(CheckSpec(name="slow", run=py("import time; time.sleep(30)"), timeout_seconds=5))
    assert slow.status is CheckStatus.TIMED_OUT
    missing = runner.run(CheckSpec(name="nope", run=["definitely-not-a-real-binary-xyz"]))
    assert missing.status is CheckStatus.ERROR and "not found" in missing.summary


def test_output_is_redacted_and_credentials_are_not_passed_to_pr_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOME_API_TOKEN", "should-not-leak")
    monkeypatch.setenv("HARMLESS", "visible")
    code = (
        "import os, sys; "
        f"print('{fake_github_token()}'); "
        "print('TOKEN=' + os.environ.get('SOME_API_TOKEN', 'absent')); "
        "print('H=' + os.environ.get('HARMLESS', '')); sys.exit(1)"
    )
    result = CheckRunner(tmp_path).run(CheckSpec(name="leaky", run=py(code)))
    assert fake_github_token() not in result.output_tail
    assert "TOKEN=absent" in result.output_tail and "H=visible" in result.output_tail


def test_string_commands_are_split_not_shelled() -> None:
    spec = CheckSpec.model_validate({"name": "x", "run": "pytest -q 'tests/a b.py'; rm -rf /"})
    assert spec.run == ["pytest", "-q", "tests/a b.py;", "rm", "-rf", "/"]


class StubRun:
    """Fake subprocess.run that writes scanner reports based on argv."""

    def __init__(self, reports: dict[str, Any]) -> None:
        self.reports = reports
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        tool = Path(argv[0]).name
        if tool == "gitleaks":
            out = argv[argv.index("--report-path") + 1]
            Path(out).write_text(json.dumps(self.reports["gitleaks"]))
        elif tool == "osv-scanner":
            out = argv[argv.index("--output") + 1]
            key = "osv_base" if "base" in Path(argv[-1]).parts else "osv_head"
            Path(out).write_text(json.dumps(self.reports[key]))
            return subprocess.CompletedProcess(argv, 1, "", "")
        return subprocess.CompletedProcess(argv, 0, "", "")


GITLEAKS = [
    {"RuleID": "github-pat", "Description": "GitHub PAT", "File": "cfg.py", "StartLine": 3, "Match": "REDACTED"},
    {"RuleID": "github-pat", "Description": "GitHub PAT", "File": "cfg.py", "StartLine": 3, "Match": "REDACTED"},
]


def osv_report(root: Path, vulns: list[tuple[str, str, str]]) -> dict[str, Any]:
    return {
        "results": [
            {
                "source": {"path": str(root / "requirements.txt")},
                "packages": [
                    {
                        "package": {"name": name, "version": version, "ecosystem": "PyPI"},
                        "vulnerabilities": [{"id": vid, "summary": f"{name} issue"}],
                        "groups": [{"ids": [vid], "max_severity": "7.5"}],
                    }
                    for name, version, vid in vulns
                ],
            }
        ]
    }


def test_gitleaks_scans_pr_range_and_dedupes(tmp_path: Path) -> None:
    stub = StubRun({"gitleaks": GITLEAKS})
    result = CheckRunner(tmp_path, "a" * 40, "b" * 40, run=stub).run(CheckSpec(name="secrets", kind="gitleaks"))
    assert result.status is CheckStatus.FAILED
    [f] = result.findings
    assert (f.path, f.line, f.category) == ("cfg.py", 3, Category.SECRET)
    argv = stub.calls[0]
    assert "--redact" in argv and argv[argv.index("--log-opts") + 1] == f"{'a' * 40}..{'b' * 40}"


def test_osv_reports_only_vulnerabilities_new_in_the_pr(tmp_path: Path) -> None:
    head = osv_report(tmp_path, [("requests", "2.31.0", "GHSA-1"), ("jinja2", "3.1.2", "GHSA-2")])
    base = osv_report(tmp_path, [("jinja2", "3.1.2", "GHSA-2")])
    stub = StubRun({"osv_head": head, "osv_base": base})
    result = CheckRunner(tmp_path, base_sha="a" * 40, run=stub).run(CheckSpec(name="deps", kind="osv"))
    assert [f.rule_id for f in result.findings] == ["GHSA-1"]
    assert "introduced by this PR" in result.summary
    assert result.findings[0].severity is Severity.HIGH and result.findings[0].path == "requirements.txt"
    assert any(c[:3] == ["git", "worktree", "add"] for c in stub.calls)


def test_parsers_tolerate_sparse_reports(tmp_path: Path) -> None:
    assert parse_gitleaks([{}])[0].path is None
    assert parse_osv({}, tmp_path) == []
    report = {"results": [{"source": {}, "packages": [{"package": {}, "groups": [{"ids": []}]}]}]}
    assert parse_osv(report, tmp_path)[0].severity is Severity.MEDIUM
