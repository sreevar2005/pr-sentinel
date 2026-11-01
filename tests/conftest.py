from __future__ import annotations

from pathlib import Path

import pytest

from pr_sentinel.diff import FileDiff

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "demo"


def added_file(path: str, lines: list[str], start: int = 1) -> FileDiff:
    """A FileDiff where every line is newly added, starting at `start`."""
    body = "\n".join("+" + ln for ln in lines)
    patch = f"@@ -0,0 +{start},{len(lines)} @@\n{body}"
    return FileDiff.from_patch(path, patch, status="added")


# Secret-shaped strings are assembled at runtime so this repository never contains a
# literal that secret scanners (ours, gitleaks, GitHub push protection) would flag.
def fake_github_token() -> str:
    return "ghp" + "_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def fake_aws_key() -> str:
    return "AKIA" + "Q3XJ7PLM2RZ8TB4N"


@pytest.fixture
def demo_dir() -> Path:
    return DEMO
