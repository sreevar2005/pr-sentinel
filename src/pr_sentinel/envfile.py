"""Minimal `.env` loader for local runs.

Only used by the CLI, and only for the current directory's `.env`. In GitHub Actions there is
no `.env`; keys come from repository secrets. Values already present in the environment win,
and values are never logged.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")

# Only provider keys may come from a file. Anything else (GITHUB_API_URL, proxies, ...) could
# redirect credentials, so it must be set deliberately in the real environment.
ALLOWED_KEYS = frozenset({"GEMINI_API_KEY", "ANTHROPIC_API_KEY"})


def parse_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = _LINE.match(raw)
        if not m:
            continue
        key, value = m.group(1), m.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].rstrip()  # trailing comment on an unquoted value
        values[key] = value
    return values


def load_env_file(path: Path) -> list[str]:
    """Set allowed variables from `path` that are not already set. Returns the names loaded.

    Disabled in GitHub Actions: there, keys come only from repository secrets.
    """
    if os.environ.get("GITHUB_ACTIONS") == "true" or not path.is_file():
        return []
    loaded = []
    for key, value in parse_env(path.read_text(encoding="utf-8-sig")).items():
        if key in ALLOWED_KEYS and value and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded
