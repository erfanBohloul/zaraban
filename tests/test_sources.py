"""Unit tests for zaraban/sources.py (SPEC §3.2, §3.3)."""

import subprocess
from pathlib import Path

import pytest

from zaraban.models import ErrorCode, ZarabanError
from zaraban.sources import prepare


# -- fixtures ----------------------------------------------------------------

def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True)


def make_base(tmp_path, name="base"):
    """A small base tree with two files, committed to git."""
    d = tmp_path / name
    (d / "src").mkdir(parents=True)
    (d / "src" / "main.c").write_text(
        "int main(void) {\n    return 0;\n}\n", encoding="utf-8")
    (d / "README").write_text("hello\n", encoding="utf-8")
    _git(d, "init", "-q")
    _git(d, "config", "user.email", "t@t.t")
    _git(d, "config", "user.name", "t")
    _git(d, "add", "-A")
    _git(d, "commit", "-q", "-m", "base")
    return d


def make_patch_dir(tmp_path):
    """A copy of the base with one line changed in main.c."""
    d = tmp_path / "patched"
    (d / "src").mkdir(parents=True)
    (d / "src" / "main.c").write_text(
        "int main(void) {\n    return 1;\n}\n", encoding="utf-8")
    (d / "README").write_text("hello\n", encoding="utf-8")
    return d


# -- directory form (§3.3) ---------------------------------------------------

def test_3_3_directory_form_produces_diff(tmp_path):
    base = make_base(tmp_path)
    patch = make_patch_dir(tmp_path)
    s = prepare(base, patch, tmp_path / "work")

    assert s.base_tree.is_dir() and s.patch_tree.is_dir()
    assert s.patch.form == "directory"
    assert s.patch.strip_level is None
    # The derived diff mentions the one changed file and has at least one hunk.
    assert s.diff.hunks == 1
    # Paths are relative to the tree, not to the work directory (§9.2).
    assert s.diff.files == ["src/main.c"]
    text = s.diff_path.read_text(encoding="utf-8")
    assert "--- a/src/main.c\n+++ b/src/main.c\n" in text
    assert str(s.base_tree) not in text


def test_3_3_clean_tree_excludes_git_and_out(tmp_path):
    base = make_base(tmp_path)
    (base / "out").mkdir()
    (base / "out" / "junk.o").write_text("x", encoding="utf-8")
    patch = make_patch_dir(tmp_path)
    s = prepare(base, patch, tmp_path / "work")
    assert not (s.base_tree / ".git").exists()
    assert not (s.base_tree / "out").exists()


# -- diff-file form (§3.2) ---------------------------------------------------

def test_3_2_diff_file_applies_and_reports_strip_level(tmp_path):
    base = make_base(tmp_path)
    patch = make_patch_dir(tmp_path)
    # Build a real unified diff with a/ b/ prefixes -> applies at -p1.
    diff = subprocess.run(
        ["git", "diff", "--no-index", "--",
         "base/src/main.c", "patched/src/main.c"],
        cwd=tmp_path, capture_output=True, text=True,
    ).stdout
    # Rewrite paths so the diff is rooted at the tree (a/src, b/src).
    diff = diff.replace("base/src/main.c", "src/main.c").replace(
        "patched/src/main.c", "src/main.c")
    diff_file = tmp_path / "change.diff"
    diff_file.write_text(diff, encoding="utf-8")

    s = prepare(base, diff_file, tmp_path / "work")
    assert s.patch.form == "diff"
    assert s.patch.strip_level == 1
    # The patch tree really has the applied change.
    assert "return 1" in (s.patch_tree / "src" / "main.c").read_text()
    # The diff file is copied verbatim into the work dir.
    assert s.diff_path.read_text(encoding="utf-8") == diff


def test_3_2_non_applying_diff_raises_patch_apply_failed(tmp_path):
    base = make_base(tmp_path)
    bad = tmp_path / "bad.diff"
    bad.write_text(
        "--- a/src/main.c\n+++ b/src/main.c\n"
        "@@ -1,1 +1,1 @@\n-this line is not in the file\n+something else\n",
        encoding="utf-8")
    with pytest.raises(ZarabanError) as e:
        prepare(base, bad, tmp_path / "work")
    assert e.value.code is ErrorCode.PATCH_APPLY_FAILED


def test_3_2_diff_file_with_timestamps_lists_stripped_paths(tmp_path):
    """The delivered token_parser patches are `diff -u` output: a tab plus a
    timestamp after each file name, and different old and new paths
    (``targets/target1_sample/src/main.c`` and
    ``targets/target1_sample/versions/patch_correct/src/main.c``). git apply
    takes the new path, which becomes ``src/main.c`` only at -p4."""
    target = Path(__file__).resolve().parent.parent / "targets" / "target1_sample"
    s = prepare(target, target / "patches" / "correct.patch", tmp_path / "work")
    assert s.patch.strip_level == 4
    assert "CORRECT PATCH" in (s.patch_tree / "src" / "main.c").read_text()
    assert s.diff.files == ["src/main.c"]
    assert s.diff.hunks == 1


def test_12_4_deleted_file_listed_by_old_path(tmp_path):
    base = make_base(tmp_path)
    patch = make_patch_dir(tmp_path)
    (patch / "README").unlink()
    s = prepare(base, patch, tmp_path / "work")
    assert sorted(s.diff.files) == ["README", "src/main.c"]


def test_3_3_hunk_content_that_looks_like_a_path_is_untouched(tmp_path):
    base = make_base(tmp_path)
    patch = make_patch_dir(tmp_path)
    (patch / "src" / "main.c").write_text(
        "int main(void) {\n    return 1;\n}\n/* a/base/x b/patch/y */\n", encoding="utf-8")
    s = prepare(base, patch, tmp_path / "work")
    assert "+/* a/base/x b/patch/y */" in s.diff_path.read_text(encoding="utf-8")


# -- error handling (§3.2) ---------------------------------------------------

def test_3_2_base_must_be_a_directory(tmp_path):
    f = tmp_path / "notadir"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(ZarabanError) as e:
        prepare(f, tmp_path / "whatever", tmp_path / "work")
    assert e.value.code is ErrorCode.SOURCE_NOT_FOUND


def test_3_2_patch_neither_file_nor_dir(tmp_path):
    base = make_base(tmp_path)
    with pytest.raises(ZarabanError) as e:
        prepare(base, tmp_path / "ghost", tmp_path / "work")
    assert e.value.code is ErrorCode.SOURCE_NOT_FOUND


# -- metadata (§12.4) --------------------------------------------------------

def test_12_4_version_and_diff_metadata(tmp_path):
    base = make_base(tmp_path)
    patch = make_patch_dir(tmp_path)
    s = prepare(base, patch, tmp_path / "work")

    assert s.base.form == "directory"
    assert s.base.git_commit is not None  # base is a git repo
    assert len(s.base.tree_sha256) == 64  # sha256 hex
    assert len(s.patch.tree_sha256) == 64
    # Base and patch differ, so their tree hashes differ.
    assert s.base.tree_sha256 != s.patch.tree_sha256
    assert len(s.diff.sha256) == 64
    assert s.diff.path == str(s.diff_path)


# -- strip levels (§3.2) -----------------------------------------------------

def write_diff(tmp_path, text, name="change.diff"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_3_2_diff_without_prefix_applies_at_p0(tmp_path):
    base = make_base(tmp_path)
    diff = write_diff(tmp_path, "--- src/main.c\n+++ src/main.c\n@@ -1,3 +1,3 @@\n"
                                " int main(void) {\n-    return 0;\n+    return 2;\n }\n")
    s = prepare(base, diff, tmp_path / "work")
    assert s.patch.strip_level == 0
    assert "return 2" in (s.patch_tree / "src" / "main.c").read_text()


def test_3_2_git_diff_that_only_adds_a_file_uses_p1(tmp_path):
    # Nothing in the base anchors the level; -p0 and -p2 would also "apply"
    # (creating b/src/new.c or new.c), but a git-style diff means -p1.
    base = make_base(tmp_path)
    diff = write_diff(tmp_path, "diff --git a/src/new.c b/src/new.c\nnew file mode 100644\n"
                                "--- /dev/null\n+++ b/src/new.c\n@@ -0,0 +1 @@\n+int x;\n")
    s = prepare(base, diff, tmp_path / "work")
    assert s.patch.strip_level == 1
    assert (s.patch_tree / "src" / "new.c").read_text() == "int x;\n"
    assert not (s.patch_tree / "b").exists()
    assert s.diff.files == ["src/new.c"]


def test_3_2_ambiguous_strip_level_is_an_error(tmp_path):
    # x/src/main.c and src/main.c have the same content, so the diff applies
    # at -p0 (to x/src/main.c) and at -p1 (to src/main.c). Guessing could
    # patch the wrong file, so the run must stop.
    base = make_base(tmp_path)
    (base / "x" / "src").mkdir(parents=True)
    (base / "x" / "src" / "main.c").write_text((base / "src" / "main.c").read_text())
    diff = write_diff(tmp_path, "--- x/src/main.c\n+++ x/src/main.c\n@@ -1,3 +1,3 @@\n"
                                " int main(void) {\n-    return 0;\n+    return 2;\n }\n")
    with pytest.raises(ZarabanError) as e:
        prepare(base, diff, tmp_path / "work")
    assert e.value.code is ErrorCode.PATCH_APPLY_FAILED
    assert "more than one strip level" in e.value.message
    assert any("-p0" in p and "x/src/main.c" in p for p in e.value.details["problems"])


def test_3_2_apply_failure_explains_why(tmp_path):
    base = make_base(tmp_path)
    bad = write_diff(tmp_path, "--- a/src/main.c\n+++ b/src/main.c\n"
                               "@@ -1,1 +1,1 @@\n-not in the file\n+x\n", "bad.diff")
    with pytest.raises(ZarabanError) as e:
        prepare(base, bad, tmp_path / "work")
    problems = e.value.details["problems"]
    assert len(problems) == 5  # one line per strip level, -p0 .. -p4
    assert any(p.startswith("-p1:") and "patch" in p for p in problems)


# -- clean copies (§3.3, §6.2) -----------------------------------------------

def test_3_3_out_is_skipped_only_at_the_root(tmp_path):
    base = make_base(tmp_path)
    (base / "out").mkdir()
    (base / "src" / "out").mkdir()
    (base / "src" / "out" / "gen.c").write_text("int g;\n")
    (base / "src" / "__pycache__").mkdir()
    s = prepare(base, make_patch_dir(tmp_path), tmp_path / "work")
    assert not (s.base_tree / "out").exists()
    assert (s.base_tree / "src" / "out" / "gen.c").is_file()  # part of the program
    assert not (s.base_tree / "src" / "__pycache__").exists()


def test_3_3_symlinks_are_kept_as_links(tmp_path):
    base = make_base(tmp_path)
    (base / "link.c").symlink_to("src/main.c")
    s = prepare(base, make_patch_dir(tmp_path), tmp_path / "work")
    assert (s.base_tree / "link.c").is_symlink()


def test_3_3_identical_trees_give_an_empty_diff(tmp_path):
    base = make_base(tmp_path)
    same = tmp_path / "same"
    (same / "src").mkdir(parents=True)
    (same / "src" / "main.c").write_text((base / "src" / "main.c").read_text())
    (same / "README").write_text("hello\n")
    s = prepare(base, same, tmp_path / "work")
    assert s.diff.files == [] and s.diff.hunks == 0
    assert s.base.tree_sha256 == s.patch.tree_sha256


def test_3_3_prepare_twice_in_the_same_work_dir(tmp_path):
    base = make_base(tmp_path)
    work = tmp_path / "work"
    patch = make_patch_dir(tmp_path)
    prepare(base, patch, work)
    (work / "patch" / "leftover.o").write_text("x")  # e.g. from an earlier run
    s = prepare(base, patch, work)
    assert not (s.patch_tree / "leftover.o").exists()


def test_12_4_base_outside_git_has_no_commit(tmp_path):
    plain = tmp_path / "plain"
    (plain / "src").mkdir(parents=True)
    (plain / "src" / "main.c").write_text("int main(void) {\n    return 0;\n}\n")
    s = prepare(plain, make_patch_dir(tmp_path), tmp_path / "work")
    assert s.base.git_commit is None
