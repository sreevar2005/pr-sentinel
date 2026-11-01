"""Decide which changed files are worth reviewing, and why the others were skipped."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase as fnmatch
from pathlib import PurePosixPath

from pr_sentinel.diff import FileDiff

DEFAULT_EXCLUDES = (
    # Lockfiles: reviewed by the dependency scanner, not by humans or models.
    "*.lock",
    "**/package-lock.json",
    "**/pnpm-lock.yaml",
    "**/yarn.lock",
    "**/poetry.lock",
    "**/uv.lock",
    "**/Cargo.lock",
    "**/go.sum",
    # Generated / vendored / minified.
    "**/vendor/**",
    "**/node_modules/**",
    "**/dist/**",
    "**/build/**",
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.pb.go",
    "*_pb2.py",
    "**/__snapshots__/**",
    # Binary-ish assets.
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.ico",
    "*.pdf",
    "*.zip",
    "*.woff",
    "*.woff2",
    "*.ttf",
)


@dataclass(frozen=True)
class SkippedFile:
    path: str
    reason: str


def _matches(path: str, pattern: str) -> bool:
    if fnmatch(path, pattern):
        return True
    # fnmatch's "*" already crosses "/", so "**/x/**" needs the root-level case too.
    if pattern.startswith("**/") and fnmatch(path, pattern[3:]):
        return True
    return "/" not in pattern and fnmatch(PurePosixPath(path).name, pattern)


def select_files(
    files: list[FileDiff],
    extra_excludes: list[str],
    max_files: int,
    max_file_patch_chars: int,
) -> tuple[list[FileDiff], list[SkippedFile]]:
    patterns = (*DEFAULT_EXCLUDES, *extra_excludes)
    selected: list[FileDiff] = []
    skipped: list[SkippedFile] = []
    for fd in files:
        if fd.status == "removed":
            skipped.append(SkippedFile(fd.path, "deleted"))
        elif fd.binary:
            skipped.append(SkippedFile(fd.path, "binary or diff unavailable"))
        elif any(_matches(fd.path, p) for p in patterns):
            skipped.append(SkippedFile(fd.path, "excluded (generated, vendored, or lockfile)"))
        elif not fd.added:
            skipped.append(SkippedFile(fd.path, "no added lines"))
        elif fd.patch is not None and len(fd.patch) > max_file_patch_chars:
            skipped.append(SkippedFile(fd.path, f"patch larger than {max_file_patch_chars} chars"))
        elif len(selected) >= max_files:
            skipped.append(SkippedFile(fd.path, f"over the {max_files}-file limit"))
        else:
            selected.append(fd)
    return selected, skipped
