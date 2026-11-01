"""Security invariants of the GitHub Actions integration.

These are policy tests: they fail the build if someone later loosens permissions, adds a
PR-code checkout to the privileged workflow, or interpolates untrusted context into a
script. actionlint (in CI) covers syntax; these cover intent.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from conftest import ROOT

from pr_sentinel.diff import FileDiff
from pr_sentinel.rules import run_rules

WORKFLOWS = ROOT / ".github" / "workflows"
ACTION = ROOT / "action.yml"
SHA_PIN = re.compile(r"^[\w.\-]+/[\w.\-/]+@[0-9a-f]{40}$")


def load(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    # PyYAML parses the bare key `on` as boolean True.
    if True in data:
        data["on"] = data.pop(True)
    return data


def all_steps(doc: dict[str, Any]) -> list[dict[str, Any]]:
    if "runs" in doc:
        return list(doc["runs"]["steps"])
    return [s for job in doc["jobs"].values() for s in job.get("steps", [])]


ALL_FILES = [*sorted(WORKFLOWS.glob("*.yml")), ACTION]


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda p: p.name)
def test_every_remote_action_is_pinned_to_a_sha(path: Path) -> None:
    for step in all_steps(load(path)):
        uses = step.get("uses")
        if uses and not uses.startswith("./"):
            assert SHA_PIN.match(uses), f"{path.name}: {uses} is not pinned to a commit SHA"


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda p: p.name)
def test_no_untrusted_context_in_scripts(path: Path) -> None:
    for step in all_steps(load(path)):
        script = step.get("run", "")
        assert "${{" not in script, f"{path.name}: use env vars, not expressions, inside run: ({script[:60]!r})"


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda p: p.name)
def test_sentinel_rules_pass_on_our_own_workflows(path: Path) -> None:
    text = path.read_text(encoding="utf-8").splitlines()
    patch = f"@@ -0,0 +1,{len(text)} @@\n" + "\n".join("+" + ln for ln in text)
    rel = path.relative_to(ROOT).as_posix()
    findings = [f for f in run_rules([FileDiff.from_patch(rel, patch)]) if f.rule_id != "sensitive-path-changed"]
    assert findings == []


@pytest.mark.parametrize("path", sorted(WORKFLOWS.glob("*.yml")), ids=lambda p: p.name)
def test_top_level_permissions_are_minimal(path: Path) -> None:
    perms = load(path).get("permissions")
    assert perms in ({}, {"contents": "read"}), f"{path.name}: top-level permissions {perms!r}"
    for job in load(path)["jobs"].values():
        assert "write-all" not in str(job.get("permissions", ""))
        assert "timeout-minutes" in job, "every job needs a timeout"


def test_checks_workflow_is_unprivileged() -> None:
    doc = load(WORKFLOWS / "sentinel-checks.yml")
    assert set(doc["on"]) == {"pull_request"}
    assert doc["permissions"] == {"contents": "read"}
    text = (WORKFLOWS / "sentinel-checks.yml").read_text()
    assert "secrets." not in text, "the untrusted job must not receive secrets"
    for step in all_steps(doc):
        if step.get("uses", "").startswith("actions/checkout"):
            assert step["with"]["persist-credentials"] is False


def test_review_workflow_never_touches_pr_code() -> None:
    doc = load(WORKFLOWS / "sentinel-review.yml")
    assert set(doc["on"]) == {"workflow_run"}
    assert doc["permissions"] == {}
    [job] = doc["jobs"].values()
    assert job["permissions"] == {"contents": "read", "pull-requests": "write", "actions": "read"}
    for step in all_steps(doc):
        with_ = step.get("with", {}) or {}
        if step.get("uses", "").startswith("actions/checkout"):
            assert "ref" not in with_ and "repository" not in with_, "must check out the default branch only"
            assert with_["persist-credentials"] is False
        assert "head_sha" not in str(with_) and "head_branch" not in str(with_)
    assert "pull_request_target" not in (WORKFLOWS / "sentinel-review.yml").read_text()


def test_action_runs_scanners_only_in_checks_mode_and_secrets_only_in_review_mode() -> None:
    steps = all_steps(load(ACTION))
    for step in steps:
        env = step.get("env", {}) or {}
        if {"ANTHROPIC_API_KEY", "GEMINI_API_KEY"} & set(env):
            assert step.get("if") == "inputs.mode == 'review'"
        if "install-scanners" in step.get("run", "") or "run-checks" in step.get("run", ""):
            assert step.get("if") == "inputs.mode == 'checks'"
    setup_uv = next(s for s in steps if s.get("uses", "").startswith("astral-sh/setup-uv"))
    assert setup_uv["with"]["enable-cache"] is False, "no cache sharing between trust levels"


def test_install_script_pins_checksums() -> None:
    script = (ROOT / "scripts" / "install-scanners.sh").read_text()
    assert script.count("sha256sum --check") == 1  # single verified download helper
    assert len(re.findall(r"_SHA256=[0-9a-f]{64}\n", script)) == 3
