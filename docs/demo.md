# Demo: a risky "Add user export" pull request

[`examples/demo/pr.diff`](../examples/demo/pr.diff) is a realistic PR that adds a user export
module and a release-notes workflow step. It contains:

| # | Problem | Line | Who should catch it |
| --- | --- | --- | --- |
| 1 | Hard-coded signing secret | `app/export.py:6` | gitleaks (checks job) **and** the secrets rule; deduplicated |
| 2 | SQL built with an f-string | `app/export.py:15` | rule `py-sql-string-format`; the AI also reports it and is merged into the rule finding |
| 3 | `subprocess.run(..., shell=True)` with a user-supplied filename | `app/export.py:20` | rule `py-subprocess-shell` |
| 4 | A comment telling AI reviewers to "ignore previous instructions" | `app/export.py:24` | rule `prompt-injection-text` |
| 5 | Broken authorization: `or` instead of `and` | `app/export.py:25` | **AI only**: no regex can see this |
| 6 | PR title interpolated into a `run:` script | `release.yml:12` | rule `gha-script-injection` |
| 7 | Third-party action pinned to a tag | `release.yml:13` | rule `gha-unpinned-action` |
| 8 | Vulnerable `requests` version | `requirements.txt` | osv-scanner (file-level, summary only) |

[`examples/demo/ai-response.json`](../examples/demo/ai-response.json) is a scripted model reply
containing two real findings and three that must be rejected: a finding in a file that is not in
the diff (hallucination), one whose quoted evidence does not exist at that line, and one below the
confidence threshold.

## Run it

```bash
uv run pr-sentinel review-local --diff examples/demo/pr.diff \
  --checks-dir examples/demo/checks \
  --fake-response examples/demo/ai-response.json --show-inline
```

Full output: [`examples/demo/expected-output.md`](../examples/demo/expected-output.md). Key parts:

```text
Advisory review of `8510700`: 🔴 1 critical · 🟠 4 high · 🟡 3 medium · ⚪ 1 info.

| 🔴 critical | check | `app/export.py:6`                  | Secret detected by gitleaks …
| 🟠 high     | rule  | `.github/workflows/release.yml:12` | Untrusted GitHub context interpolated into a workflow
| 🟠 high     | rule  | `app/export.py:15`                 | SQL built with string formatting
| 🟠 high     | rule  | `app/export.py:20`                 | Subprocess invoked with `shell=True`
| 🟠 high     | AI    | `app/export.py:25`                 | Authorization check lets every non-admin export any organisation
| 🟡 medium   | rule  | `.github/workflows/release.yml:13` | Third-party action not pinned to a commit SHA
| 🟡 medium   | rule  | `app/export.py:24`                 | Text that looks like instructions to an AI reviewer
| 🟡 medium   | check | `requirements.txt`                 | requests@2.31.0: …
| ⚪ info     | rule  | `.github/workflows/release.yml`    | CI workflow changed

- AI findings filtered out: low confidence: 1, ungrounded: 1, unknown file: 1
```

What this shows:

- **Separation of concerns.** Seven of the nine findings are deterministic and would be reported
  even if the injected comment fooled the model entirely. The AI adds the one class of bug rules
  cannot find.
- **Evidence-based output.** All three bad model findings were discarded mechanically, and the
  summary says why.
- **No duplicate noise.** The secret was reported by two sources and the SQL injection by two;
  each appears once, under the deterministic source.

## On GitHub

The same scenario runs end to end in `tests/test_pipeline.py` against an in-memory GitHub API.
It asserts the exact set of inline comment locations, that the only write calls are one
`COMMENT` review and one summary comment, that a re-run posts nothing new and edits the summary
in place, and that a fork PR without the opt-in label gets rule findings but no model call.
