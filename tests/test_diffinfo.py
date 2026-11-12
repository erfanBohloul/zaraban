"""Unit tests for zaraban/diffinfo.py (SPEC §9.2)."""

import shutil
import subprocess
from pathlib import Path

import pytest

from zaraban.diffinfo import (changed_functions, changed_positions, function_ranges,
                              load_hunks, parse_hunks)
from zaraban.models import ErrorCode, Hunk, Version, ZarabanError

TARGET = Path(__file__).resolve().parent.parent / "targets" / "target1_sample"

# A git diff with two files: one hunk that replaces a line and adds one, and a
# second file with two hunks.
GIT_DIFF = """\
diff --git a/src/main.c b/src/main.c
index 1111111..2222222 100644
--- a/src/main.c
+++ b/src/main.c
@@ -10,5 +10,6 @@ int handle(char *s)
     char buf[64];
-    strcpy(buf, s);
+    if (strlen(s) >= sizeof buf) return 1;
+    strcpy(buf, s);
     puts(buf);
     return 0;
 }
diff --git a/src/util.c b/src/util.c
index 3333333..4444444 100644
--- a/src/util.c
+++ b/src/util.c
@@ -1,3 +1,3 @@
 int a(void) {
-    return 1;
+    return 2;
 }
@@ -20,4 +20,3 @@ int b(void) {
 int b(void) {
-    int unused;
     return 0;
 }
"""


def test_9_2_base_and_patch_ranges_include_context():
    h = parse_hunks(GIT_DIFF, 1)[0]
    assert h.file == "src/main.c"
    assert h.header == "@@ -10,5 +10,6 @@"
    assert (h.base_start, h.base_end) == (10, 14)
    assert (h.patch_start, h.patch_end) == (10, 15)


def test_9_2_removed_lines_in_base_numbers_added_lines_in_patch_numbers():
    h = parse_hunks(GIT_DIFF, 1)[0]
    assert h.removed_lines == [11]
    assert h.added_lines == [11, 12]


def test_9_2_every_file_and_hunk_in_order():
    hunks = parse_hunks(GIT_DIFF, 1)
    assert [(h.file, h.header) for h in hunks] == [
        ("src/main.c", "@@ -10,5 +10,6 @@"),
        ("src/util.c", "@@ -1,3 +1,3 @@"),
        ("src/util.c", "@@ -20,4 +20,3 @@"),
    ]
    assert hunks[2].removed_lines == [21]
    assert hunks[2].added_lines == []


def test_9_2_context_line_is_inside_the_hunk_on_both_sides():
    h = parse_hunks(GIT_DIFF, 1)[0]
    # line 13 "return 0;" is unchanged context
    assert h.contains(Version.BASE, "src/main.c", 13)
    assert h.contains(Version.PATCH, "src/main.c", 14)
    assert not h.contains(Version.BASE, "src/main.c", 15)
    assert not h.contains(Version.PATCH, "src/main.c", 16)
    assert not h.contains(Version.PATCH, "src/util.c", 11)


def test_9_2_strip_level_is_applied_to_paths():
    diff = GIT_DIFF.replace("a/src/", "a/targets/t/src/").replace("b/src/", "b/targets/t/src/")
    assert {h.file for h in parse_hunks(diff, 3)} == {"src/main.c", "src/util.c"}


def test_9_2_plain_diff_u_without_function_names():
    diff = """\
--- old/src/main.c\t2026-11-08 18:08:52
+++ new/src/main.c\t2026-11-08 18:09:24
@@ -3 +3 @@
-    return 0;
+    return 1;
"""
    [h] = parse_hunks(diff, 1)
    assert h.file == "src/main.c"
    assert h.header == "@@ -3,1 +3,1 @@"
    assert (h.base_start, h.base_end, h.patch_start, h.patch_end) == (3, 3, 3, 3)
    assert (h.removed_lines, h.added_lines) == ([3], [3])


def test_9_2_new_file_has_an_empty_base_range():
    diff = """\
diff --git a/src/new.c b/src/new.c
new file mode 100644
--- /dev/null
+++ b/src/new.c
@@ -0,0 +1,2 @@
+int f(void);
+int g(void);
"""
    [h] = parse_hunks(diff, 1)
    assert h.file == "src/new.c"
    assert h.base_end < h.base_start
    assert not h.contains(Version.BASE, "src/new.c", 0)
    assert h.added_lines == [1, 2]


def test_9_2_deleted_file_is_named_by_its_old_path():
    diff = """\
diff --git a/src/old.c b/src/old.c
deleted file mode 100644
--- a/src/old.c
+++ /dev/null
@@ -1,2 +0,0 @@
-int f(void);
-int g(void);
"""
    [h] = parse_hunks(diff, 1)
    assert h.file == "src/old.c"
    assert h.removed_lines == [1, 2]
    assert h.patch_end < h.patch_start


def test_9_2_empty_diff_has_no_hunks():
    assert parse_hunks("", 1) == []


def test_9_2_text_that_is_not_a_diff_is_an_error():
    bad = "--- a/x\n+++ b/x\n@@ -1,3 +1,3 @@\n only one line\n"
    with pytest.raises(ZarabanError) as e:
        parse_hunks(bad, 1)
    assert e.value.code is ErrorCode.PATCH_APPLY_FAILED


def test_9_2_token_parser_incomplete_patch(tmp_path):
    """The stored incomplete patch: the strcpy is unchanged context below the
    new check, and still inside the hunk on both sides (§9.2, §9.6)."""
    # Its new name is targets/target1_sample/versions/patch_incomplete/src/main.c;
    # like git apply, the new name is used, so -p4 gives src/main.c.
    hunks = load_hunks(TARGET / "patches" / "incomplete.patch", 4)
    [h] = hunks
    assert h.file == "src/main.c"
    assert h.header == "@@ -21,14 +21,19 @@"
    assert h.contains(Version.PATCH, "src/main.c", 37)  # strcpy on patch
    assert h.contains(Version.BASE, "src/main.c", 32)  # strcpy on base
    assert 37 not in h.added_lines


# -- changed functions (§9.2) ------------------------------------------------

def _has_universal_ctags():
    if shutil.which("ctags") is None:
        return False
    out = subprocess.run(["ctags", "--version"], capture_output=True, text=True).stdout
    return "Universal Ctags" in out


needs_ctags = pytest.mark.skipif(not _has_universal_ctags(),
                                 reason="universal-ctags is in the Docker image only")

# A check added to the caller ``handle``; the overflow itself is in ``copy``.
CALLER_BASE = """\
static void copy(char *d, const char *s) {
    strcpy(d, s);
}

int handle(const char *s) {
    char buf[8];
    copy(buf, s);
    return 0;
}
"""

CALLER_PATCH = """\
static void copy(char *d, const char *s) {
    strcpy(d, s);
}

int handle(const char *s) {
    char buf[8];
    if (strlen(s) >= sizeof buf) return 1;
    copy(buf, s);
    return 0;
}

int extra(void) {
    return 0;
}
"""


def _trees(tmp_path, base_text, patch_text, name="src/x.c"):
    """Base and patch trees with one file, and the git diff between them."""
    for side, text in (("base", base_text), ("patch", patch_text)):
        f = tmp_path / side / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
    diff = subprocess.run(
        ["git", "diff", "--no-index", "--", f"base/{name}", f"patch/{name}"],
        cwd=tmp_path, capture_output=True, text=True).stdout
    # git names the files a/base/src/x.c and b/patch/src/x.c: strip 2
    return tmp_path / "base", tmp_path / "patch", parse_hunks(diff, 2)


def test_9_2_insertion_gap_on_base_side():
    # "@@ -3,7 +3,8 @@": patch line 7 is new, between base lines 6 and 7
    h = Hunk("src/x.c", "@@ -3,7 +3,8 @@", 3, 9, 3, 10, removed_lines=[], added_lines=[7])
    assert changed_positions(h, Version.BASE) == ([], [(6, 7)])
    assert changed_positions(h, Version.PATCH) == ([7], [])


def test_9_2_deletion_gap_on_patch_side():
    # "@@ -20,4 +20,3 @@": base line 21 is removed, between patch lines 20 and 21
    h = Hunk("src/x.c", "@@ -20,4 +20,3 @@", 20, 23, 20, 22, removed_lines=[21], added_lines=[])
    assert changed_positions(h, Version.PATCH) == ([], [(20, 21)])
    assert changed_positions(h, Version.BASE) == ([21], [])


def test_9_2_replacement_has_lines_on_both_sides():
    h = parse_hunks(GIT_DIFF, 1)[0]  # -11 / +11 +12
    lines, gaps = changed_positions(h, Version.BASE)
    assert lines == [11] and gaps == [(10, 12)]
    lines, gaps = changed_positions(h, Version.PATCH)
    assert lines == [11, 12] and gaps == [(10, 13)]


def test_9_2_zero_context_insertion_sits_after_start_line():
    # diff -U0: "@@ -6,0 +7 @@" inserts one line after base line 6
    h = Hunk("src/x.c", "@@ -6,0 +7,1 @@", 6, 5, 7, 7, removed_lines=[], added_lines=[7])
    assert changed_positions(h, Version.BASE) == ([], [(6, 7)])


@needs_ctags
def test_9_2_function_ranges_from_ctags(tmp_path):
    base, _, _ = _trees(tmp_path, CALLER_BASE, CALLER_PATCH)
    assert function_ranges(base, "src/x.c") == [("copy", 1, 3), ("handle", 5, 9)]


@needs_ctags
def test_9_2_missing_or_non_c_file_has_no_functions(tmp_path):
    (tmp_path / "Makefile").write_text("all:\n\techo hi\n", encoding="utf-8")
    assert function_ranges(tmp_path, "Makefile") == []
    assert function_ranges(tmp_path, "src/gone.c") == []


@needs_ctags
def test_9_2_check_added_to_caller_changes_the_caller_on_both_sides(tmp_path):
    base, patch, hunks = _trees(tmp_path, CALLER_BASE, CALLER_PATCH)
    # Nothing was removed, but the new check sits inside handle() on base too.
    assert changed_functions(base, hunks, Version.BASE) == {("src/x.c", "handle")}
    # copy() is not changed: being next to a change is not a change (§9.1).
    assert changed_functions(patch, hunks, Version.PATCH) == {
        ("src/x.c", "handle"), ("src/x.c", "extra")}


@needs_ctags
def test_9_2_new_function_after_the_last_one_does_not_change_it(tmp_path):
    base_text = "int a(void) {\n    return 0;\n}\n"
    patch_text = base_text + "\nint b(void) {\n    return 1;\n}\n"
    base, patch, hunks = _trees(tmp_path, base_text, patch_text)
    assert changed_functions(base, hunks, Version.BASE) == set()
    assert changed_functions(patch, hunks, Version.PATCH) == {("src/x.c", "b")}


@needs_ctags
def test_9_2_removed_line_changes_the_function_on_base(tmp_path):
    base_text = "int a(void) {\n    int unused;\n    return 0;\n}\n"
    patch_text = "int a(void) {\n    return 0;\n}\n"
    base, patch, hunks = _trees(tmp_path, base_text, patch_text)
    assert changed_functions(base, hunks, Version.BASE) == {("src/x.c", "a")}
    assert changed_functions(patch, hunks, Version.PATCH) == {("src/x.c", "a")}


@needs_ctags
def test_9_2_token_parser_incomplete_patch_changes_handle_set_command(tmp_path):
    for side, src in (("base", TARGET / "src" / "main.c"),
                      ("patch", TARGET / "versions" / "patch_incomplete" / "src" / "main.c")):
        (tmp_path / side / "src").mkdir(parents=True)
        shutil.copyfile(src, tmp_path / side / "src" / "main.c")
    hunks = load_hunks(TARGET / "patches" / "incomplete.patch", 4)
    want = {("src/main.c", "handle_set_command")}
    assert changed_functions(tmp_path / "base", hunks, Version.BASE) == want
    assert changed_functions(tmp_path / "patch", hunks, Version.PATCH) == want


def test_9_2_missing_ctags_is_a_tool_error(tmp_path, monkeypatch):
    (tmp_path / "x.c").write_text("int a(void) { return 0; }\n", encoding="utf-8")
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    with pytest.raises(ZarabanError) as e:
        function_ranges(tmp_path, "x.c")
    assert e.value.code is ErrorCode.TOOL_INTERNAL
