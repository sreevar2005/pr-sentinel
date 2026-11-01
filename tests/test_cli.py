from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from fake_github import HEAD_SHA, workflow_run_event

from pr_sentinel import cli


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = cli.main(list(argv))
    return code, capsys.readouterr().out


def test_review_local_json(capsys: pytest.CaptureFixture[str], demo_dir: Path, tmp_path: Path) -> None:
    code, out = run(
        capsys,
        "--config",
        str(tmp_path / "none.yml"),
        "review-local",
        "--diff",
        str(demo_dir / "pr.diff"),
        "--fake-response",
        str(demo_dir / "ai-response.json"),
        "--format",
        "json",
    )
    assert code == 0
    data = json.loads(out)
    sources = {(f["source"], f["rule_id"]) for f in data["findings"]}
    assert ("ai", "ai-security") in sources
    assert ("rule", "py-sql-string-format") in sources
    assert data["ai_dropped"] == {"low_confidence": 1, "ungrounded": 1, "unknown_file": 1}


def test_review_local_without_ai(capsys: pytest.CaptureFixture[str], demo_dir: Path, tmp_path: Path) -> None:
    cfg = tmp_path / "c.yml"
    cfg.write_text("review: {ai: {enabled: false}}")
    code, out = run(capsys, "--config", str(cfg), "review-local", "--diff", str(demo_dir / "pr.diff"))
    assert code == 0 and "AI review: disabled" in out and "SQL built with string formatting" in out


def test_run_checks_writes_artifact_and_fails_on_failures(tmp_path: Path) -> None:
    cfg = tmp_path / "c.yml"
    cfg.write_text(
        "checks:\n"
        "  - {name: ok, run: [python, -c, 'pass']}\n"
        "  - {name: bad, run: [python, -c, 'raise SystemExit(2)']}\n"
    )
    out = tmp_path / "out" / "checks.json"
    code = cli.main(
        [
            "--config",
            str(cfg),
            "run-checks",
            "--output",
            str(out),
            "--pr-number",
            "7",
            "--head-sha",
            HEAD_SHA,
            "--repo-dir",
            str(tmp_path),
        ]
    )
    assert code == 1
    artifact = json.loads(out.read_text())
    assert artifact["pr_number"] == 7
    assert [c["status"] for c in artifact["checks"]] == ["passed", "failed"]


def test_review_requires_github_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert cli.main(["--config", str(tmp_path / "x.yml"), "review", "--event-path", str(tmp_path / "e.json")]) == 2


def test_review_abort_is_success(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/shop")
    event = tmp_path / "event.json"
    event.write_text(json.dumps(workflow_run_event(conclusion="skipped")))
    assert cli.main(["--config", str(tmp_path / "x.yml"), "review", "--event-path", str(event)]) == 0


def test_bad_config_exit_code(tmp_path: Path, demo_dir: Path) -> None:
    cfg = tmp_path / "c.yml"
    cfg.write_text("review: {nope: 1}")
    shutil.copy(demo_dir / "pr.diff", tmp_path / "d.diff")
    assert cli.main(["--config", str(cfg), "review-local", "--diff", str(tmp_path / "d.diff")]) == 2
