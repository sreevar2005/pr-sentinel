"""Secret detection and redaction.

Used for three things:
1. The `secrets` rule (deterministic findings on added lines).
2. Redacting the diff *before* it is sent to a third-party model provider.
3. Scrubbing any text we post or log (check output tails, model output).

Patterns favour precision: a noisy secret rule trains people to ignore the bot.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    rule_id: str
    description: str
    regex: re.Pattern[str]
    group: int = 0  # which group holds the secret value


_P = re.compile

SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("aws-access-key-id", "AWS access key ID", _P(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 1),
    SecretPattern(
        "github-token",
        "GitHub token",
        _P(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
        1,
    ),
    SecretPattern("anthropic-api-key", "Anthropic API key", _P(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})"), 1),
    SecretPattern("openai-api-key", "OpenAI-style API key", _P(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})"), 1),
    SecretPattern("slack-token", "Slack token", _P(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})"), 1),
    SecretPattern("stripe-secret-key", "Stripe secret key", _P(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})"), 1),
    SecretPattern("google-api-key", "Google API key", _P(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 1),
    SecretPattern(
        "private-key",
        "Private key block",
        _P(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----)"),
        1,
    ),
    SecretPattern(
        "jwt",
        "JSON Web Token",
        _P(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"),
        1,
    ),
    SecretPattern(
        "url-credentials",
        "Credentials embedded in a URL",
        _P(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@'\"]+:([^\s@/'\"]{6,})@[^\s'\"]+", re.IGNORECASE),
        1,
    ),
)

# key = "value" assignments where the key name suggests a secret. Value must look random.
_GENERIC_ASSIGNMENT = _P(
    r"""(?ix)
    \b([a-z0-9_.\-]*(?:secret|passwd|password|api[_\-]?key|access[_\-]?key|auth[_\-]?token|
        private[_\-]?key|client[_\-]?secret)[a-z0-9_.\-]*)
    \s*[:=]\s*
    (['"])([^'"\s]{12,})\2
    """
)

_PLACEHOLDER = _P(
    r"(?i)^(?:x+|\*+|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|changeme|example|dummy|test|"
    r"placeholder|your[_\-].*|redacted|none|null|.*\.\.\..*)$"
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    n = len(value)
    return -sum((k / n) * math.log2(k / n) for k in counts.values())


@dataclass(frozen=True)
class SecretMatch:
    rule_id: str
    description: str
    start: int
    end: int

    def masked(self, line: str) -> str:
        value = line[self.start : self.end]
        keep = value[:4] if len(value) > 12 else ""
        return f"{keep}…[REDACTED:{self.rule_id}]"


def find_secrets(line: str) -> list[SecretMatch]:
    matches: list[SecretMatch] = []
    for pat in SECRET_PATTERNS:
        for m in pat.regex.finditer(line):
            matches.append(SecretMatch(pat.rule_id, pat.description, m.start(pat.group), m.end(pat.group)))
    for m in _GENERIC_ASSIGNMENT.finditer(line):
        value = m.group(3)
        if _PLACEHOLDER.match(value) or shannon_entropy(value) < 3.5:
            continue
        if any(s.start <= m.start(3) < s.end for s in matches):
            continue
        matches.append(SecretMatch("generic-secret", f"Hard-coded value for `{m.group(1)}`", m.start(3), m.end(3)))
    return sorted(matches, key=lambda s: s.start)


def redact(text: str) -> str:
    """Replace every detected secret in `text`. Safe to call on arbitrary multi-line text."""
    out_lines = []
    for line in text.split("\n"):
        matches = find_secrets(line)
        if not matches:
            out_lines.append(line)
            continue
        pieces: list[str] = []
        cursor = 0
        for m in matches:
            if m.start < cursor:
                continue
            pieces.append(line[cursor : m.start])
            pieces.append(f"[REDACTED:{m.rule_id}]")
            cursor = m.end
        pieces.append(line[cursor:])
        out_lines.append("".join(pieces))
    return "\n".join(out_lines)
