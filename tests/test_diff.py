import pytest

from pr_sentinel.diff import DiffParseError, FileDiff, parse_hunks, parse_unified_diff

PATCH = """@@ -1,4 +1,5 @@
 import os
-import sys
+import sys, json
+import re

 def main():
@@ -20,2 +21,3 @@ def main():
     a = 1
+    b = 2
     return a
\\ No newline at end of file"""


def test_parse_hunks_tracks_both_sides() -> None:
    lines = parse_hunks(PATCH)
    added = [(ln.new_lineno, ln.text) for ln in lines if ln.kind == "+"]
    assert added == [(2, "import sys, json"), (3, "import re"), (22, "    b = 2")]
    removed = [(ln.old_lineno, ln.text) for ln in lines if ln.kind == "-"]
    assert removed == [(2, "import sys")]


def test_right_side_includes_context_but_not_removed() -> None:
    fd = FileDiff.from_patch("a.py", PATCH)
    assert fd.right_side[1] == "import os"
    assert fd.right_side[21] == "    a = 1"
    assert 2 in fd.added and 1 not in fd.added
    assert fd.additions == 3


def test_missing_patch_is_binary() -> None:
    fd = FileDiff.from_patch("logo.png", None)
    assert fd.binary and fd.added == {}


def test_garbage_inside_hunk_raises() -> None:
    with pytest.raises(DiffParseError):
        parse_hunks("@@ -1 +1 @@\n?what")


def test_parse_unified_diff_handles_new_deleted_renamed_binary() -> None:
    text = """diff --git a/new.py b/new.py
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+x = 1
+y = 2
diff --git a/old.py b/old.py
deleted file mode 100644
--- a/old.py
+++ /dev/null
@@ -1 +0,0 @@
-gone
diff --git a/a.txt b/b.txt
similarity index 90%
rename from a.txt
rename to b.txt
--- a/a.txt
+++ b/b.txt
@@ -1 +1 @@
-hello
+hello world
diff --git a/img.png b/img.png
Binary files a/img.png and b/img.png differ
"""
    files = {f.path: f for f in parse_unified_diff(text)}
    assert files["new.py"].status == "added" and files["new.py"].added == {1: "x = 1", 2: "y = 2"}
    assert files["old.py"].status == "removed"
    assert files["b.txt"].status == "renamed" and files["b.txt"].previous_path == "a.txt"
    assert files["img.png"].binary


def test_demo_diff_line_numbers(demo_dir) -> None:  # type: ignore[no-untyped-def]
    files = {f.path: f for f in parse_unified_diff((demo_dir / "pr.diff").read_text())}
    export = files["app/export.py"]
    assert export.added[25].strip().startswith("return user.org_id == org.id")
    assert export.right_side[9].startswith("def connect")
