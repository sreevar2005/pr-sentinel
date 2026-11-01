"""Unified diff parsing.

Two entry points:
* `FileDiff.from_patch` for per-file patches returned by GitHub's "list PR files" API.
* `parse_unified_diff` for a full `git diff` (local runs and tests).

Only RIGHT-side line numbers matter downstream: findings must point at lines that exist
in the new version of the file and appear in the diff, otherwise GitHub rejects the
review comment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class DiffParseError(ValueError):
    pass


@dataclass(frozen=True)
class DiffLine:
    kind: str  # "+", "-", " "
    text: str
    old_lineno: int | None
    new_lineno: int | None


@dataclass
class FileDiff:
    path: str
    status: str = "modified"  # added | modified | removed | renamed | copied | changed
    previous_path: str | None = None
    patch: str | None = None
    binary: bool = False
    lines: list[DiffLine] = field(default_factory=list)

    @classmethod
    def from_patch(
        cls,
        path: str,
        patch: str | None,
        status: str = "modified",
        previous_path: str | None = None,
    ) -> FileDiff:
        fd = cls(path=path, status=status, previous_path=previous_path, patch=patch)
        if patch is None:
            # GitHub omits `patch` for binary files and for very large diffs.
            fd.binary = True
            return fd
        fd.lines = parse_hunks(patch)
        return fd

    @property
    def added(self) -> dict[int, str]:
        return {ln.new_lineno: ln.text for ln in self.lines if ln.kind == "+" and ln.new_lineno is not None}

    @property
    def right_side(self) -> dict[int, str]:
        """Every new-file line visible in the diff (added + context): commentable lines."""
        return {ln.new_lineno: ln.text for ln in self.lines if ln.kind in "+ " and ln.new_lineno is not None}

    @property
    def additions(self) -> int:
        return sum(1 for ln in self.lines if ln.kind == "+")


def parse_hunks(patch: str) -> list[DiffLine]:
    lines: list[DiffLine] = []
    old_no = new_no = 0
    in_hunk = False
    for raw in patch.splitlines():
        m = _HUNK.match(raw)
        if m:
            old_no = int(m.group(1))
            new_no = int(m.group(3))
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if raw.startswith("\\"):  # "\ No newline at end of file"
            continue
        marker, text = (raw[:1], raw[1:]) if raw else (" ", "")
        if marker == "+":
            lines.append(DiffLine("+", text, None, new_no))
            new_no += 1
        elif marker == "-":
            lines.append(DiffLine("-", text, old_no, None))
            old_no += 1
        elif marker == " ":
            lines.append(DiffLine(" ", text, old_no, new_no))
            old_no += 1
            new_no += 1
        else:
            raise DiffParseError(f"unexpected diff line: {raw[:60]!r}")
    return lines


def _strip_prefix(p: str) -> str | None:
    p = p.strip()
    if p == "/dev/null":
        return None
    if p.startswith('"') and p.endswith('"'):
        p = p[1:-1]
    return p[2:] if p[:2] in ("a/", "b/") else p


def parse_unified_diff(text: str) -> list[FileDiff]:
    files: list[FileDiff] = []
    current: FileDiff | None = None
    patch_lines: list[str] = []

    def flush() -> None:
        if current is None:
            return
        if not current.binary:
            current.patch = "\n".join(patch_lines)
            current.lines = parse_hunks(current.patch)
        files.append(current)

    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            flush()
            m = re.match(r"diff --git (\S+) (\S+)$", raw)
            path = _strip_prefix(m.group(2)) if m else None
            current = FileDiff(path=path or "unknown")
            patch_lines = []
            continue
        if current is None:
            continue
        if raw.startswith("new file mode"):
            current.status = "added"
        elif raw.startswith("deleted file mode"):
            current.status = "removed"
        elif raw.startswith("rename from "):
            current.previous_path = raw[len("rename from ") :]
            current.status = "renamed"
        elif raw.startswith("rename to "):
            current.path = raw[len("rename to ") :]
        elif raw.startswith("Binary files ") or raw.startswith("GIT binary patch"):
            current.binary = True
        elif raw.startswith("--- ") and not patch_lines:
            continue
        elif raw.startswith("+++ ") and not patch_lines:
            new_path = _strip_prefix(raw[4:])
            if new_path:
                current.path = new_path
        elif raw.startswith(("index ", "similarity index", "old mode", "new mode")):
            continue
        else:
            patch_lines.append(raw)
    flush()
    return files
