"""Run deterministic project checks in the *untrusted* checks job.

This module executes PR code (tests, linters). It therefore only ever runs in the
`pull_request` workflow, which has a read-only token and no secrets. Its output is an
artifact that the review job treats as untrusted data.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pr_sentinel.config import CheckSpec
from pr_sentinel.models import Category, CheckResult, CheckStatus, Finding, Severity, Source
from pr_sentinel.redact import redact

log = logging.getLogger(__name__)

TAIL_CHARS = 3500
_SENSITIVE_ENV = re.compile(r"TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY|CREDENTIAL", re.IGNORECASE)
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _safe_env() -> dict[str, str]:
    """Defence in depth: the job has no secrets, but never hand any credential-like env to PR code."""
    return {k: v for k, v in os.environ.items() if not _SENSITIVE_ENV.search(k)}


def _tail(text: str) -> str:
    text = _ANSI.sub("", text)
    return redact(text[-TAIL_CHARS:])


Runner = Callable[..., subprocess.CompletedProcess[str]]


class CheckRunner:
    def __init__(
        self,
        repo_dir: Path,
        base_sha: str | None = None,
        head_sha: str | None = None,
        run: Runner = subprocess.run,
    ) -> None:
        self.repo_dir = repo_dir
        self.base_sha = base_sha
        self.head_sha = head_sha
        self._run = run

    def _exec(self, argv: list[str], timeout: int, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return self._run(
            argv,
            cwd=cwd or self.repo_dir,
            env=_safe_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            shell=False,
        )

    def run(self, spec: CheckSpec) -> CheckResult:
        start = time.monotonic()
        try:
            if spec.kind == "command":
                result = self._command(spec)
            elif spec.kind == "gitleaks":
                result = self._gitleaks(spec)
            else:
                result = self._osv(spec)
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout if isinstance(exc.stdout, str) else ""
            result = CheckResult(
                name=spec.name,
                kind=spec.kind,
                status=CheckStatus.TIMED_OUT,
                duration_seconds=0,
                summary=f"timed out after {spec.timeout_seconds}s",
                output_tail=_tail(out),
            )
        except FileNotFoundError as exc:
            result = CheckResult(
                name=spec.name,
                kind=spec.kind,
                status=CheckStatus.ERROR,
                duration_seconds=0,
                summary=f"executable not found: {Path(exc.filename or '?').name}",
            )
        except Exception as exc:  # a broken check must not hide the others
            log.exception("check %s crashed", spec.name)
            result = CheckResult(
                name=spec.name,
                kind=spec.kind,
                status=CheckStatus.ERROR,
                duration_seconds=0,
                summary=redact(f"{type(exc).__name__}: {exc}")[:400],
            )
        return result.model_copy(update={"duration_seconds": round(time.monotonic() - start, 2)})

    # -- command ---------------------------------------------------------------------------

    def _command(self, spec: CheckSpec) -> CheckResult:
        if not spec.run:
            return CheckResult(
                name=spec.name,
                kind="command",
                status=CheckStatus.SKIPPED,
                duration_seconds=0,
                summary="no command configured",
            )
        proc = self._exec(spec.run, spec.timeout_seconds)
        passed = proc.returncode == 0
        findings: list[Finding] = []
        if not passed:
            findings.append(
                Finding(
                    source=Source.CHECK,
                    rule_id=f"check-{spec.name}",
                    category=spec.category,
                    severity=spec.severity_on_failure,
                    title=f"`{spec.name}` failed (exit {proc.returncode})",
                    explanation="See the check output in the summary or the workflow log.",
                    recommendation=f"Run `{' '.join(spec.run)}` locally and fix the reported failures.",
                )
            )
        return CheckResult(
            name=spec.name,
            kind="command",
            status=CheckStatus.PASSED if passed else CheckStatus.FAILED,
            duration_seconds=0,
            exit_code=proc.returncode,
            summary="passed" if passed else f"exit code {proc.returncode}",
            output_tail="" if passed else _tail((proc.stdout or "") + "\n" + (proc.stderr or "")),
            findings=findings,
        )

    # -- gitleaks --------------------------------------------------------------------------

    def _gitleaks(self, spec: CheckSpec) -> CheckResult:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "gitleaks.json"
            argv = [
                "gitleaks",
                "git",
                "--no-banner",
                "--redact",
                "--exit-code",
                "0",
                "--report-format",
                "json",
                "--report-path",
                str(report),
            ]
            if self.base_sha and self.head_sha:
                argv += ["--log-opts", f"{self.base_sha}..{self.head_sha}"]
            argv += [*spec.args, "."]
            proc = self._exec(argv, spec.timeout_seconds)
            if proc.returncode != 0 or not report.exists():
                return CheckResult(
                    name=spec.name,
                    kind="gitleaks",
                    status=CheckStatus.ERROR,
                    duration_seconds=0,
                    exit_code=proc.returncode,
                    summary="gitleaks failed to run",
                    output_tail=_tail(proc.stderr or ""),
                )
            findings = parse_gitleaks(json.loads(report.read_text(encoding="utf-8") or "[]"))
        return CheckResult(
            name=spec.name,
            kind="gitleaks",
            status=CheckStatus.FAILED if findings else CheckStatus.PASSED,
            duration_seconds=0,
            exit_code=0,
            summary=f"{len(findings)} potential secret(s) in PR commits" if findings else "no secrets found",
            findings=findings[:200],
        )

    # -- osv-scanner -----------------------------------------------------------------------

    def _osv_scan(self, spec: CheckSpec, directory: Path) -> list[Finding] | None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "osv.json"
            argv = [
                "osv-scanner",
                "scan",
                "source",
                "--recursive",
                "--format",
                "json",
                "--output",
                str(report),
                *spec.args,
                str(directory),
            ]
            proc = self._exec(argv, spec.timeout_seconds, cwd=directory)
            # osv-scanner: 0 = clean, 1 = vulnerabilities found, 128 = no packages found.
            if proc.returncode == 128:
                return []
            if proc.returncode not in (0, 1) or not report.exists():
                log.warning("osv-scanner exit %s: %s", proc.returncode, (proc.stderr or "")[-300:])
                return None
            return parse_osv(json.loads(report.read_text(encoding="utf-8")), directory)

    def _osv(self, spec: CheckSpec) -> CheckResult:
        head = self._osv_scan(spec, self.repo_dir)
        if head is None:
            return CheckResult(
                name=spec.name,
                kind="osv",
                status=CheckStatus.ERROR,
                duration_seconds=0,
                summary="osv-scanner failed to run",
            )
        note = ""
        baseline = self._osv_baseline(spec)
        if baseline is not None:
            known = {f.fingerprint for f in baseline}
            head = [f for f in head if f.fingerprint not in known]
            note = " introduced by this PR"
        elif self.base_sha:
            note = " (baseline scan failed: may include pre-existing issues)"
        return CheckResult(
            name=spec.name,
            kind="osv",
            status=CheckStatus.FAILED if head else CheckStatus.PASSED,
            duration_seconds=0,
            exit_code=0,
            summary=f"{len(head)} vulnerable dependenc(ies){note}" if head else f"no vulnerable dependencies{note}",
            findings=head[:200],
        )

    def _osv_baseline(self, spec: CheckSpec) -> list[Finding] | None:
        """Scan the base commit in a throwaway worktree so only *new* vulnerabilities are reported."""
        if not self.base_sha or shutil.which("git") is None:
            return None
        with tempfile.TemporaryDirectory() as tmp:
            wt = Path(tmp) / "base"
            add = self._exec(["git", "worktree", "add", "--detach", str(wt), self.base_sha], 120)
            if add.returncode != 0:
                return None
            try:
                return self._osv_scan(spec, wt)
            finally:
                self._exec(["git", "worktree", "remove", "--force", str(wt)], 60)


def _cvss_to_severity(score: Any) -> Severity:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return Severity.MEDIUM
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def parse_gitleaks(report: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for item in report:
        path = str(item.get("File", ""))
        line = int(item.get("StartLine") or 0)
        rule = str(item.get("RuleID", "unknown"))
        if (rule, path, line) in seen:
            continue
        seen.add((rule, path, line))
        findings.append(
            Finding(
                source=Source.CHECK,
                rule_id=f"gitleaks-{rule}"[:80],
                category=Category.SECRET,
                severity=Severity.CRITICAL,
                title=f"Secret detected by gitleaks: {str(item.get('Description') or rule)[:150]}",
                path=path or None,
                line=line or None,
                # gitleaks --redact already masks the value; redact again in case a rule leaks context.
                evidence=redact(str(item.get("Match", "")))[:200],
                explanation="The secret exists in the PR's commit history, even if a later commit removed it.",
                recommendation="Revoke and rotate the credential; rewriting history does not un-leak it.",
            )
        )
    return findings


def parse_osv(report: dict[str, Any], root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for result in report.get("results", []) or []:
        src = str((result.get("source") or {}).get("path", ""))
        try:
            rel = Path(src).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = Path(src).name
        for pkg in result.get("packages", []) or []:
            meta = pkg.get("package") or {}
            name, version = meta.get("name", "?"), meta.get("version", "?")
            vulns = {v.get("id"): v for v in pkg.get("vulnerabilities", []) or []}
            for group in pkg.get("groups", []) or []:
                ids = [i for i in group.get("ids", []) if i]
                primary = next((i for i in ids if i in vulns), ids[0] if ids else "unknown")
                summary = str((vulns.get(primary) or {}).get("summary") or "known vulnerability")
                findings.append(
                    Finding(
                        source=Source.CHECK,
                        rule_id=str(primary)[:80],
                        category=Category.DEPENDENCY,
                        severity=_cvss_to_severity(group.get("max_severity")),
                        title=f"{name}@{version}: {summary}"[:200],
                        path=rel or None,
                        evidence=f"{meta.get('ecosystem', '')} {name} {version}".strip(),
                        explanation=f"Advisories: {', '.join(ids)[:300]}",
                        recommendation=f"Upgrade {name} to a fixed version (see https://osv.dev/{primary}).",
                    )
                )
    return findings
