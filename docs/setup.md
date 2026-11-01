# Setup and deployment

## Local development

```bash
# Prerequisites: Python 3.12+, uv (https://docs.astral.sh/uv/)
uv sync                      # creates .venv from uv.lock (hash-verified)
uv run pytest                # 153 tests
uv run ruff check . && uv run ruff format --check . && uv run mypy
```

Open the local app (Windows: double-click `run.bat`):

```bash
uv run pr-sentinel gui            # opens http://127.0.0.1:8765 in your browser
```

It reviews the demo PR, your changes against `main`, or a pasted diff, and can run the tests.
It listens on 127.0.0.1 only and every API call needs a token generated at launch.

Review a diff offline, with no API key and no GitHub access:

```bash
uv run pr-sentinel review-local --diff examples/demo/pr.diff \
  --checks-dir examples/demo/checks \
  --fake-response examples/demo/ai-response.json --show-inline
```

Review your own branch with the real model:

```bash
git diff origin/main...HEAD > /tmp/pr.diff
# Put your key in .env (git-ignored) as GEMINI_API_KEY=... or ANTHROPIC_API_KEY=...
# The CLI loads only those two names from .env, and never inside GitHub Actions.
uv run pr-sentinel review-local --diff /tmp/pr.diff --provider gemini
```

Exit codes: `0` success or nothing to do, `1` runtime/API failure (or failing checks for
`run-checks`), `2` configuration error.

## Installing in a GitHub repository

### Option A: this repository (dogfooding)

The workflows in `.github/workflows/` use the local action (`uses: ./`). Push the repository to
GitHub, then do the configuration below.

### Option B: another repository

Copy `.github/workflows/sentinel-checks.yml`, `.github/workflows/sentinel-review.yml` and
`.github/pr-sentinel.yml` into the target repository, and replace each `uses: ./` with a pinned
reference to your published copy of this action, for example
`uses: your-org/pr-sentinel@<40-char-commit-sha> # v0.1.0`. Edit `checks:` in the config to run
that project's test and lint commands.

### GitHub configuration

1. **Secret:** Settings → Secrets and variables → Actions → New repository secret
   `GEMINI_API_KEY` (if `review.ai.provider` is `gemini`, the default here) or
   `ANTHROPIC_API_KEY` (if `anthropic`). Gemini needs billing enabled on the Google project
   unless that project has free-tier access. Without a working key, the review still runs and posts deterministic findings,
   and the summary states the AI review was unavailable.
2. **Actions permissions:** Settings → Actions → General
   - Workflow permissions: **Read repository contents** (the workflows request what they need).
   - "Allow GitHub Actions to create and approve pull requests": **leave unchecked**.
     PR Sentinel never needs it.
   - Fork pull request workflows: **Require approval for first-time contributors** (or stricter).
3. **Branch protection / ruleset** on `main`:
   - Require status check **`checks`** (from *PR Sentinel / Checks*).
   - Require at least one human approving review.
   - Do *not* require the review workflow: `workflow_run` results are not attached to the PR.
4. **Label:** create `sentinel:review`. Maintainers apply it to fork PRs to opt them into AI
   review (rules always run).
5. **Workflow names:** `sentinel-review.yml` triggers on the checks workflow by name
   (`PR Sentinel / Checks`). Keep them in sync if you rename either.

Note: `workflow_run` workflows only run from the default branch. The review stage starts working
once both workflow files are merged into `main`.

### Configuration reference

`.github/pr-sentinel.yml` (read from the default branch by the review job):

| Key | Default | Meaning |
| --- | --- | --- |
| `checks[].kind` | `command` | `command`, `gitleaks`, or `osv` |
| `checks[].run` | — | argv list or string (split with `shlex`; never run through a shell) |
| `checks[].timeout_seconds` | 600 | per-check timeout |
| `review.ai.enabled` | true | turn AI review off entirely |
| `review.ai.provider` | `anthropic` (this repo: `gemini`) | `gemini`, `anthropic`, or `fake` |
| `review.ai.model` | per provider: `gemini-flash-latest` / `claude-opus-5-5` | model name |
| `review.ai.effort` | `high` | reasoning effort (Anthropic only) |
| `review.ai.min_confidence` | 0.7 | drop AI findings below this |
| `review.ai.max_findings` | 15 | cap after ranking |
| `review.ai.refusal_fallback` | true | server-side fallback if the model declines a chunk |
| `review.limits.max_files` | 150 | files considered per PR |
| `review.limits.max_chunk_chars` / `max_chunks` | 120000 / 4 | AI budget per push |
| `review.inline_min_severity` | `medium` | lower severities go to the summary only |
| `review.forks` | `require-label` | `always`, `require-label`, `never` (AI only; rules always run) |
| `review.exclude` | `[]` | extra globs to skip (on top of lockfiles, vendored, minified, binaries) |
| `review.disabled_rules` | `[]` | rule IDs to turn off |

Unknown keys are rejected, so a typo cannot silently fall back to a default.

## Operations

- **Cost:** at most `max_chunks` model calls per push, about 30k input tokens each at the default
  chunk size. Lower `effort` or switch `model` for cheaper runs.
- **Timeouts:** checks job 20 min, review job 15 min, model requests 240 s with 3 SDK retries,
  GitHub calls 30 s with up to 4 retries and rate-limit waits capped at 60 s.
- **Debugging:** each review job writes the rendered summary to the job's step summary. Run
  `pr-sentinel review --dry-run` with the same event payload to reproduce it without posting.
