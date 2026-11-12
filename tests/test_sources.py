"""Unit tests for zaraban/sources.py (SPEC §3.2, §3.3)."""

import subprocess

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
    assert s.diff.hunks >= 1
    assert any("main.c" in f for f in s.diff.files)
    assert s.diff_path.read_text(encoding="utf-8").strip() != ""


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
