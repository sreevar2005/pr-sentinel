# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **Report a vulnerability** button
(Security → Advisories) rather than in a public issue. Include a reproduction (a PR diff or
event payload) and the impact. Expect an acknowledgement within 5 working days.

In scope: any way for pull request content to execute code in, or obtain the token or secrets of,
the review workflow; to make PR Sentinel take a write action other than posting its own comments;
to read secrets through model output, logs or artifacts; or to suppress deterministic findings.

Out of scope: the AI reviewer missing a bug or reporting a false positive (please open a normal
issue with the diff), and anything that requires write access to the default branch.

## Design

See [docs/architecture.md](docs/architecture.md#threat-model) for the threat model and the
invariants enforced by `tests/test_workflows.py`.
