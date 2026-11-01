"""Deterministic diff rules.

These run in the trusted review job against *added lines only*, without executing any PR
code. They are intentionally few and high-signal. They are independent of the model, so
a prompt-injection that silences the AI reviewer cannot silence them.

Repository content is attacker-controlled for fork PRs, so there is deliberately no inline
"ignore this line" marker. Suppression is only possible through `review.disabled_rules`
and `review.exclude` in the base-branch config.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from fnmatch import fnmatchcase as fnmatch

from pr_sentinel.diff import FileDiff
from pr_sentinel.models import Category, Finding, Severity, Source
from pr_sentinel.redact import find_secrets, redact

MAX_EVIDENCE = 200


def _evidence(text: str) -> str:
    return redact(text.strip())[:MAX_EVIDENCE]


@dataclass(frozen=True)
class LineRule:
    rule_id: str
    category: Category
    severity: Severity
    title: str
    pattern: re.Pattern[str]
    recommendation: str
    explanation: str
    globs: tuple[str, ...] = ("*",)
    unless: re.Pattern[str] | None = None

    def applies_to(self, path: str) -> bool:
        return any(fnmatch(path, g) for g in self.globs)


_PY = ("*.py",)
_JS = ("*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs")
_WORKFLOWS = (
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    "action.yml",
    "action.yaml",
    "*/action.yml",
    "*/action.yaml",
)
_SHELLISH = ("*.sh", "*.bash", "Dockerfile", "*/Dockerfile", "*.dockerfile", "Makefile", *_WORKFLOWS)

# Untrusted GitHub contexts that must never be interpolated into scripts.
_UNTRUSTED_CTX = (
    r"github\.event\.(?:pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.(?:description|homepage))"
    r"|issue\.(?:title|body)|comment\.body|review\.body|review_comment\.body"
    r"|pages\.[^}]*\.page_name|commits\.[^}]*\.(?:message|author\.(?:email|name))"
    r"|head_commit\.(?:message|author\.(?:email|name))|workflow_run\.head_branch)"
    r"|github\.head_ref"
)

LINE_RULES: tuple[LineRule, ...] = (
    LineRule(
        "py-yaml-unsafe-load",
        Category.SECURITY,
        Severity.HIGH,
        "`yaml.load` without a safe loader",
        re.compile(r"\byaml\.(?:load|load_all)\s*\("),
        "Use `yaml.safe_load()` or pass `Loader=yaml.SafeLoader`.",
        "PyYAML's full loader can construct arbitrary Python objects from untrusted input.",
        _PY,
        unless=re.compile(r"SafeLoader|CSafeLoader|safe_load"),
    ),
    LineRule(
        "py-subprocess-shell",
        Category.SECURITY,
        Severity.HIGH,
        "Subprocess invoked with `shell=True`",
        re.compile(r"\bsubprocess\.\w+\(.*shell\s*=\s*True"),
        "Pass an argv list with `shell=False`; if a shell is unavoidable, quote inputs with `shlex.quote`.",
        "With `shell=True`, any interpolated input can inject additional shell commands.",
        _PY,
    ),
    LineRule(
        "py-os-system",
        Category.SECURITY,
        Severity.MEDIUM,
        "`os.system` / `os.popen` call",
        re.compile(r"\bos\.(?:system|popen)\s*\("),
        "Use `subprocess.run([...], check=True)` with an argv list.",
        "These run through a shell, so any dynamic input is a command-injection vector.",
        _PY,
    ),
    LineRule(
        "py-pickle-load",
        Category.SECURITY,
        Severity.HIGH,
        "Deserialising with `pickle`",
        re.compile(r"\b(?:pickle|cPickle|dill|joblib)\.loads?\s*\("),
        "Never unpickle data that could be attacker-influenced; use JSON or a schema-validated format.",
        "Unpickling executes arbitrary code embedded in the payload.",
        _PY,
    ),
    LineRule(
        "py-eval-exec",
        Category.SECURITY,
        Severity.MEDIUM,
        "Dynamic code execution with `eval`/`exec`",
        re.compile(r"(?<![\w.])(?:eval|exec)\s*\((?!\s*['\"][^'\"]*['\"]\s*\))"),
        "Replace with explicit parsing (e.g. `ast.literal_eval`, a dispatch table).",
        "Evaluating non-literal input allows arbitrary code execution.",
        _PY,
    ),
    LineRule(
        "py-sql-string-format",
        Category.SECURITY,
        Severity.HIGH,
        "SQL built with string formatting",
        re.compile(
            r"\.execute(?:many)?\s*\(\s*(?:f['\"]|['\"].*['\"]\s*%\s*|['\"].*['\"]\s*\.format\(|['\"].*['\"]\s*\+)",
            re.IGNORECASE,
        ),
        'Use parameterised queries: `cursor.execute("... WHERE id = %s", (user_id,))`.',
        "Interpolating values into SQL text enables SQL injection.",
        _PY,
    ),
    LineRule(
        "tls-verify-disabled",
        Category.SECURITY,
        Severity.HIGH,
        "TLS certificate verification disabled",
        re.compile(
            r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"
            r"|InsecureSkipVerify\s*:\s*true|curl\s.*(?:-k\b|--insecure)"
        ),
        "Keep verification on; for private CAs, configure the CA bundle instead.",
        "Disabling verification allows man-in-the-middle interception of the connection.",
    ),
    LineRule(
        "js-eval",
        Category.SECURITY,
        Severity.MEDIUM,
        "Dynamic code execution (`eval` / `new Function`)",
        re.compile(r"(?<![\w.])eval\s*\(|new\s+Function\s*\("),
        "Avoid evaluating strings as code; parse data explicitly.",
        "Evaluating strings built from input allows arbitrary script execution.",
        _JS,
    ),
    LineRule(
        "js-inner-html",
        Category.SECURITY,
        Severity.MEDIUM,
        "Raw HTML injection sink",
        re.compile(r"\.(?:innerHTML|outerHTML)\s*=(?!=)|dangerouslySetInnerHTML|document\.write\s*\("),
        "Use `textContent`, or sanitise with a vetted library (e.g. DOMPurify) before inserting HTML.",
        "Assigning unsanitised strings to HTML sinks leads to cross-site scripting.",
        _JS,
    ),
    LineRule(
        "js-child-process-exec",
        Category.SECURITY,
        Severity.HIGH,
        "`child_process.exec` with an interpolated command",
        re.compile(r"\bexec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+)"),
        "Use `execFile`/`spawn` with an argument array.",
        "`exec` runs through a shell, so interpolated values can inject commands.",
        _JS,
    ),
    LineRule(
        "shell-pipe-to-shell",
        Category.SECURITY,
        Severity.MEDIUM,
        "Remote script piped directly into a shell",
        re.compile(r"(?:curl|wget)\s[^|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"),
        "Download to a file, verify a pinned checksum, then execute.",
        "A compromised or MITM'd endpoint gets arbitrary code execution in this environment.",
        _SHELLISH,
    ),
    LineRule(
        "world-writable-permissions",
        Category.SECURITY,
        Severity.MEDIUM,
        "World-writable file permissions",
        re.compile(r"chmod\s+(?:-R\s+)?0?777\b|os\.chmod\([^)]*0o?777"),
        "Grant the minimum permissions needed (e.g. 0o755 for executables, 0o644 for files).",
        "Any local user or process can modify the file.",
    ),
    LineRule(
        "gha-script-injection",
        Category.CI_SECURITY,
        Severity.HIGH,
        "Untrusted GitHub context interpolated into a workflow",
        re.compile(r"\$\{\{\s*(?:" + _UNTRUSTED_CTX + r")"),
        'Pass the value through `env:` and reference it as a quoted shell variable ("$TITLE").',
        "Expressions are expanded before the script runs, so a crafted PR title, branch name or "
        "comment can inject shell commands with the job's token and secrets.",
        _WORKFLOWS,
        unless=re.compile(r"^\s*(?:if:|[A-Z_][A-Z0-9_]*:)"),  # `if:` conditions and env-var assignments are safe
    ),
    LineRule(
        "gha-write-all",
        Category.CI_SECURITY,
        Severity.HIGH,
        "Workflow grants `write-all` permissions",
        re.compile(r"^\s*permissions\s*:\s*write-all\b"),
        "Declare only the scopes the job needs, e.g. `permissions: { contents: read }`.",
        "A compromised step gets full write access to the repository.",
        _WORKFLOWS,
    ),
    LineRule(
        "gha-unpinned-action",
        Category.CI_SECURITY,
        Severity.MEDIUM,
        "Third-party action not pinned to a commit SHA",
        re.compile(r"^\s*-?\s*uses\s*:\s*['\"]?(?!\./|docker://)[\w.\-]+/[\w.\-/]+@(?![0-9a-f]{40}\b)\S+"),
        "Pin to a full commit SHA and keep the tag as a comment: `uses: org/action@FULL_SHA # v1.2.3`.",
        "Tags are mutable; a compromised upstream can retag and run code with this job's permissions.",
        _WORKFLOWS,
        unless=re.compile(r"uses\s*:\s*['\"]?(?:actions|github)/"),  # GitHub-owned actions: lower risk
    ),
)

_INJECTION_PHRASES = re.compile(
    r"(?i)\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|system)\b"
    r"[^.\n]{0,20}\b(?:instructions?|prompts?|rules)\b"
    r"|\b(?:you are now|act as)\b[^.\n]{0,30}\b(?:assistant|reviewer|ai|model|llm)\b"
    r"|\b(?:ai|llm|bot|automated)[ -]?review(?:er)?s?\b[^.\n]{0,60}\b(?:approve|no issues|lgtm|do not (?:report|flag))"
    r"|</?(?:system|untrusted[_-]\w*)>"
)

_SENSITIVE_PATHS = (
    (".github/workflows/*", "CI workflow changed"),
    (".github/pr-sentinel.yml", "PR Sentinel configuration changed"),
    ("CODEOWNERS", "Code ownership rules changed"),
    (".github/CODEOWNERS", "Code ownership rules changed"),
    ("docs/CODEOWNERS", "Code ownership rules changed"),
)


def _secret_findings(fd: FileDiff) -> Iterator[Finding]:
    for lineno, text in fd.added.items():
        for match in find_secrets(text):
            value = text[match.start : match.end]
            if "EXAMPLE" in value:  # documented sample credentials, e.g. AWS docs keys
                continue
            yield Finding(
                source=Source.RULE,
                rule_id=f"secret-{match.rule_id}",
                category=Category.SECRET,
                severity=Severity.CRITICAL if match.rule_id != "generic-secret" else Severity.HIGH,
                title=f"Possible secret committed: {match.description}",
                path=fd.path,
                line=lineno,
                evidence=_evidence(text),
                explanation="Anything pushed to a branch should be treated as leaked, even if the "
                "commit is later removed from the PR.",
                recommendation="Revoke and rotate the credential now, then load it from a secret "
                "manager or environment variable.",
            )


def _line_rule_findings(fd: FileDiff) -> Iterator[Finding]:
    rules = [r for r in LINE_RULES if r.applies_to(fd.path)]
    if not rules:
        return
    for lineno, text in fd.added.items():
        for rule in rules:
            if not rule.pattern.search(text):
                continue
            if rule.unless is not None and rule.unless.search(text):
                continue
            yield Finding(
                source=Source.RULE,
                rule_id=rule.rule_id,
                category=rule.category,
                severity=rule.severity,
                title=rule.title,
                path=fd.path,
                line=lineno,
                evidence=_evidence(text),
                explanation=rule.explanation,
                recommendation=rule.recommendation,
            )


def _pull_request_target_checkout(fd: FileDiff) -> Iterator[Finding]:
    """`pull_request_target`/`workflow_run` + checkout of the PR head = classic "pwn request"."""
    if not any(fnmatch(fd.path, g) for g in _WORKFLOWS):
        return
    visible = "\n".join(fd.right_side.values())
    if not re.search(r"\b(?:pull_request_target|workflow_run)\b", visible):
        return
    head_ref = re.compile(
        r"ref\s*:\s*\$\{\{\s*github\.event\.(?:pull_request\.head\.(?:sha|ref)|workflow_run\.head_(?:sha|branch))"
        r"|refs/pull/"
    )
    for lineno, text in fd.added.items():
        if head_ref.search(text):
            yield Finding(
                source=Source.RULE,
                rule_id="gha-privileged-checkout",
                category=Category.CI_SECURITY,
                severity=Severity.CRITICAL,
                title="Privileged workflow checks out untrusted PR code",
                path=fd.path,
                line=lineno,
                evidence=_evidence(text),
                explanation="`pull_request_target` and `workflow_run` run with repository secrets and a "
                "write token. Building or running PR code here hands both to the PR author.",
                recommendation="Run untrusted code in a `pull_request` workflow with no secrets, and pass "
                "results to the privileged workflow as data (artifacts) only.",
            )


def _prompt_injection(fd: FileDiff) -> Iterator[Finding]:
    for lineno, text in fd.added.items():
        if _INJECTION_PHRASES.search(text):
            yield Finding(
                source=Source.RULE,
                rule_id="prompt-injection-text",
                category=Category.PROMPT_INJECTION,
                severity=Severity.MEDIUM,
                title="Text that looks like instructions to an AI reviewer",
                path=fd.path,
                line=lineno,
                evidence=_evidence(text),
                explanation="Instruction-like text aimed at automated reviewers is a common way to "
                "suppress findings. PR Sentinel treats it as data, but a human should confirm intent.",
                recommendation="Remove the text, or confirm it is legitimate (e.g. test data for an LLM feature).",
            )


def _sensitive_paths(fd: FileDiff) -> Iterator[Finding]:
    for glob, title in _SENSITIVE_PATHS:
        if fnmatch(fd.path, glob):
            yield Finding(
                source=Source.RULE,
                rule_id="sensitive-path-changed",
                category=Category.RISKY_CHANGE,
                severity=Severity.INFO,
                title=title,
                path=fd.path,
                explanation="Changes here affect how code is built, reviewed or owned.",
                recommendation="Request review from a maintainer who owns CI and repository policy.",
            )
            return


RuleFn = Callable[[FileDiff], Iterator[Finding]]
RULE_FUNCTIONS: tuple[RuleFn, ...] = (
    _secret_findings,
    _line_rule_findings,
    _pull_request_target_checkout,
    _prompt_injection,
    _sensitive_paths,
)


def run_rules(files: list[FileDiff], disabled: list[str] | None = None) -> list[Finding]:
    disabled_set = set(disabled or [])
    findings: list[Finding] = []
    for fd in files:
        for fn in RULE_FUNCTIONS:
            findings.extend(f for f in fn(fd) if f.rule_id not in disabled_set)
    return findings
