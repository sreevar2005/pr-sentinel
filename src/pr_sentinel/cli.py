"""Command-line entry points.

pr-sentinel run-checks    untrusted job: run tests/lint/scanners, write checks.json
pr-sentinel review        trusted job: review the PR via the API and post a COMMENT review
pr-sentinel review-local  offline: review a local diff file and print the report
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections import Counter
from pathlib import Path

from pr_sentinel import __version__
from pr_sentinel.ai.factory import provider_factory
from pr_sentinel.ai.provider import ProviderError
from pr_sentinel.checks import CheckRunner
from pr_sentinel.config import ConfigError, load_config
from pr_sentinel.diff import parse_unified_diff
from pr_sentinel.envfile import load_env_file
from pr_sentinel.github import GitHubClient, GitHubError
from pr_sentinel.models import ChecksArtifact
from pr_sentinel.pipeline import (
    PipelineAbort,
    ReviewPipeline,
    analyze,
    load_artifact,
    read_event,
)
from pr_sentinel.report import SummaryInput, render_inline_comment, render_summary

log = logging.getLogger("pr_sentinel")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    # HTTP client debug logs can include request headers; keep them quiet even with -v.
    for noisy in ("httpx", "httpx2", "httpcore", "anthropic", "google_genai"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _write_step_summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(markdown + "\n")


def cmd_run_checks(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    runner = CheckRunner(args.repo_dir, base_sha=args.base_sha, head_sha=args.head_sha)
    results = []
    for spec in config.checks:
        log.info("running check %s (%s)", spec.name, spec.kind)
        result = runner.run(spec)
        log.info("check %s: %s in %.1fs", spec.name, result.status, result.duration_seconds)
        results.append(result)
    artifact = ChecksArtifact(pr_number=args.pr_number, head_sha=args.head_sha, checks=results)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
    failed = [r.name for r in results if r.status != "passed" and r.status != "skipped"]
    # Exit non-zero so the checks workflow (the branch-protection signal) reflects failures.
    if failed:
        log.error("failing checks: %s", ", ".join(failed))
        return 1
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not token or not repo:
        log.error("GITHUB_TOKEN and GITHUB_REPOSITORY must be set")
        return 2
    gh = GitHubClient(token, repo, os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    try:
        pipeline = ReviewPipeline(gh, config, provider_factory(config), bot_login=args.bot_login)
        outcome = pipeline.run(read_event(args.event_path), args.artifact_dir, dry_run=args.dry_run)
    except PipelineAbort as exc:
        log.info("nothing to do: %s", exc)
        return 0
    except GitHubError as exc:
        log.error("GitHub API error: %s", exc)
        return 1
    finally:
        gh.close()
    _write_step_summary(outcome.summary)
    if args.dry_run:
        print(outcome.summary)
        print(json.dumps(outcome.inline, indent=2))
    log.info("review %s with %d inline comment(s)", "posted" if outcome.posted else "rendered", len(outcome.inline))
    return 0


def cmd_review_local(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    ai = config.review.ai
    if args.provider and args.provider != ai.provider:
        ai.provider, ai.model = args.provider, None  # a model name from another provider is meaningless
    if args.model:
        ai.model = args.model
    files = parse_unified_diff(args.diff.read_text(encoding="utf-8"))
    artifact, note = load_artifact(args.checks_dir, config.review.limits.max_artifact_bytes)
    checks = artifact.checks if artifact else None
    result = analyze(
        files,
        config,
        provider_factory(config, args.fake_response),
        check_findings=[f for c in checks for f in c.findings] if checks else [],
        pr_title=args.title,
    )
    if args.format == "json":
        print(
            json.dumps(
                {
                    "findings": [f.model_dump(mode="json") | {"fingerprint": f.fingerprint} for f in result.findings],
                    "ai_status": result.ai_status,
                    "ai_dropped": dict(result.ai.dropped) if result.ai else {},
                    "skipped": [{"path": s.path, "reason": s.reason} for s in result.skipped],
                },
                indent=2,
            )
        )
        return 0
    summary = render_summary(
        SummaryInput(
            head_sha="0" * 40 if not artifact else artifact.head_sha,
            findings=result.findings,
            checks=checks,
            checks_note=note if args.checks_dir else "",
            ai_enabled=config.review.ai.enabled,
            ai_status=result.ai_status,
            ai_dropped=result.ai.dropped if result.ai else Counter(),
            files_reviewed=len(set(result.ai.files_reviewed)) if result.ai else 0,
            skipped=result.skipped,
        )
    )
    print(summary)
    if args.show_inline:
        for f in result.findings:
            if f.line is not None and f.severity.at_least(config.review.inline_min_severity):
                print(f"\n---- inline comment @ {f.location} ----\n{render_inline_comment(f)}")
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    from pr_sentinel.gui import serve  # imported lazily: only this command needs the web server

    serve(Path.cwd(), args.config, args.port, open_browser=not args.no_browser)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pr-sentinel", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--config", type=Path, default=Path(".github/pr-sentinel.yml"))
    sub = p.add_subparsers(dest="command", required=True)

    rc = sub.add_parser("run-checks", help="run configured checks (untrusted job)")
    rc.add_argument("--output", type=Path, required=True)
    rc.add_argument("--pr-number", type=int, required=True)
    rc.add_argument("--head-sha", required=True)
    rc.add_argument("--base-sha")
    rc.add_argument("--repo-dir", type=Path, default=Path.cwd())
    rc.set_defaults(func=cmd_run_checks)

    rv = sub.add_parser("review", help="review a PR from a workflow_run event (trusted job)")
    rv.add_argument("--event-path", type=Path, default=Path(os.environ.get("GITHUB_EVENT_PATH", "event.json")))
    rv.add_argument("--artifact-dir", type=Path)
    rv.add_argument("--bot-login", default="github-actions[bot]")
    rv.add_argument("--dry-run", action="store_true", help="render but do not post")
    rv.set_defaults(func=cmd_review)

    rl = sub.add_parser("review-local", help="review a local unified diff")
    rl.add_argument("--diff", type=Path, required=True)
    rl.add_argument("--checks-dir", type=Path, help="directory containing checks.json")
    rl.add_argument("--provider", choices=["anthropic", "gemini", "fake"])
    rl.add_argument("--model", help="override the configured model")
    rl.add_argument("--fake-response", type=Path, help="canned model JSON for the fake provider")
    rl.add_argument("--title", default="")
    rl.add_argument("--format", choices=["markdown", "json"], default="markdown")
    rl.add_argument("--show-inline", action="store_true")
    rl.set_defaults(func=cmd_review_local)

    gu = sub.add_parser("gui", help="open the local web GUI in your browser")
    gu.add_argument("--port", type=int, default=8765)
    gu.add_argument("--no-browser", action="store_true", help="print the URL instead of opening it")
    gu.set_defaults(func=cmd_gui)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    loaded = load_env_file(Path(".env"))
    if loaded:
        log.info("loaded %s from .env", ", ".join(loaded))  # names only, never values
    # Reports contain emoji; legacy Windows consoles default to a non-UTF-8 code page.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        code: int = args.func(args)
    except ConfigError as exc:
        log.error("configuration error: %s", exc)
        return 2
    except ProviderError as exc:
        log.error("provider error: %s", exc)
        return 1
    return code


if __name__ == "__main__":
    sys.exit(main())
