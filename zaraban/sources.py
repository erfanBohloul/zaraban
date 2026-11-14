"""Source preparation: make the base and patch trees, and derive the diff.

This runs before anything is built. It:

- resolves ``--base`` (a directory) and ``--patch`` (a diff file or a
  directory);
- produces two clean source trees under the work directory, so nothing is
  ever built inside the repository;
- obtains the unified diff between them:
    * a diff file is used as given, applied to the base copy with ``git apply``
      at the strip level ``-p0``..``-p4`` that applies cleanly; if two
      levels would patch different existing files, the run stops instead of
      guessing;
    * two directories are compared with ``git diff --no-index`` between the
      clean trees, before any build, and the result is written with
      the usual ``a/`` ``b/`` prefixes rooted at the tree (``a/src/main.c``),
      so it reads like any ``-p1`` diff.

It records the version and diff metadata the report needs. It does not
build or run anything, and it does not parse the diff into hunks; that is
``diffinfo.py``.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from unidiff import PatchSet
from unidiff.errors import UnidiffParseError

from .models import DiffInfo, ErrorCode, VersionInfo, ZarabanError

_MAX_STRIP = 4
DIR_DIFF_STRIP = 1  # the diff of two directories is written rooted at a/ b/


@dataclass
class Sources:
    """The prepared inputs of one run."""

    base_tree: Path
    patch_tree: Path
    diff_path: Path
    base: VersionInfo
    patch: VersionInfo
    diff: DiffInfo


def prepare(
    base_arg: str | Path,
    patch_arg: str | Path,
    work_dir: str | Path,
) -> Sources:
    """Prepare the base and patch trees and the diff.

    ``base_arg`` must be a directory. ``patch_arg`` is a diff file or a
    directory. Raises :class:`ZarabanError` (exit 30) on a missing
    source or a diff that does not apply.
    """
    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)

    base_dir = Path(base_arg)
    if not base_dir.is_dir():
        raise ZarabanError(ErrorCode.SOURCE_NOT_FOUND,
                           f"the base version {base_arg} is not a directory; give the "
                           "base sources with --base or base_dir in the config",
                           {"base": str(base_arg)})

    patch_path = Path(patch_arg)
    base_tree = work / "base"
    patch_tree = work / "patch"
    diff_path = work / "patch.diff"
    copy_tree(base_dir, base_tree)

    if patch_path.is_file():
        form = "diff"
        strip = _apply_diff(patch_path, base_tree, patch_tree)
        shutil.copyfile(patch_path, diff_path)
        patch_commit = None
    elif patch_path.is_dir():
        form = "directory"
        strip = None  # recorded only for the diff form
        copy_tree(patch_path, patch_tree)
        _diff_trees(base_tree, patch_tree, diff_path)
        patch_commit = _git_commit(patch_path)
    else:
        raise ZarabanError(ErrorCode.SOURCE_NOT_FOUND,
                           f"--patch {patch_arg} does not exist; give a diff file or a "
                           "directory with the patched sources",
                           {"patch": str(patch_arg)})

    base_info = VersionInfo(
        form="directory", ref=str(base_arg), git_commit=_git_commit(base_dir),
        tree_sha256=_tree_sha256(base_tree),
    )
    patch_info = VersionInfo(
        form=form, ref=str(patch_arg), git_commit=patch_commit,
        tree_sha256=_tree_sha256(patch_tree), strip_level=strip,
    )
    diff_info = _diff_info(diff_path, strip if strip is not None else DIR_DIFF_STRIP)
    return Sources(base_tree, patch_tree, diff_path, base_info, patch_info, diff_info)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def copy_tree(src: Path, dest: Path) -> None:
    """Replace ``dest`` with a clean copy of ``src`` (no git data or run outputs).
    Also used by the builder for its per-build copies."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, ignore=_ignore_for(Path(src)), symlinks=True)


def _ignore_for(root: Path) -> Callable[[str, list[str]], set[str]]:
    """What copy_tree leaves out: git data and Python caches at any depth, and
    the run output directory ``out`` only at the root of the tree. A source
    directory called ``out`` deeper down (``src/out/``) is part of the program."""
    def ignore(dirpath: str, names: list[str]) -> set[str]:
        skip = {n for n in names if n in (".git", "__pycache__") or n.endswith(".pyc")}
        if Path(dirpath) == root and "out" in names:
            skip.add("out")
        return skip
    return ignore


def _apply_diff(diff_file: Path, base_tree: Path, patch_tree: Path) -> int:
    """Copy the base tree and apply the diff; return the strip level used.

    Every level ``-p0``..``-p4`` is checked first. Each level that applies is
    "anchored" when it changes or deletes a file that exists in the base. One
    anchored level is used. Several anchored levels would patch different
    files, so the diff is ambiguous and the run stops. A diff that only adds
    files has no anchor: it uses ``-p1`` for a git-style diff (``b/...``
    paths), otherwise the lowest level that applies.
    """
    copy_tree(base_tree, patch_tree)
    diff = str(diff_file.resolve())
    touched: dict[int, list[str]] = {}  # level -> paths it would patch
    failures: dict[int, str] = {}
    for level in range(_MAX_STRIP + 1):
        check = _git_apply(patch_tree, level, diff, "--check")
        if check.returncode == 0:
            touched[level] = _numstat_paths(_git_apply(patch_tree, level, diff, "--numstat").stdout)
        else:
            failures[level] = check.stderr.strip()

    if not touched:
        raise ZarabanError(
            ErrorCode.PATCH_APPLY_FAILED,
            f"the patch {diff_file} does not apply to the base version (tried with "
            f"-p0 to -p{_MAX_STRIP} leading path parts removed); check that it was made "
            "against this base",
            {"diff": str(diff_file),
             "problems": [f"-p{lvl}: {_first_line(err)}" for lvl, err in failures.items()]},
        )

    level = _choose_level(touched, base_tree, diff_file)
    applied = _git_apply(patch_tree, level, diff)
    if applied.returncode != 0:
        raise ZarabanError(ErrorCode.PATCH_APPLY_FAILED,
                           f"the patch {diff_file} passed 'git apply --check' at "
                           f"-p{level} but then did not apply",
                           {"diff": str(diff_file), "problems": [_first_line(applied.stderr)]})
    return level


def _choose_level(touched: dict[int, list[str]], base_tree: Path, diff_file: Path) -> int:
    anchored = [lvl for lvl, paths in touched.items()
                if any((base_tree / p).is_file() for p in paths)]
    if len(anchored) == 1:
        return anchored[0]
    if len(anchored) > 1:
        raise ZarabanError(
            ErrorCode.PATCH_APPLY_FAILED,
            f"the patch {diff_file} applies to different files depending on how many "
            "leading path parts are removed, so it is ambiguous; make it with "
            "'git diff' or 'diff -ru base patched' from the target directory",
            {"diff": str(diff_file),
             "problems": [f"-p{lvl} would patch: {', '.join(touched[lvl])}" for lvl in anchored]},
        )
    # Only new files: nothing in the base shows which level is right.
    git_style = 0 in touched and all(p.startswith(("a/", "b/")) for p in touched[0])
    return 1 if git_style and 1 in touched else min(touched)


def _git_apply(tree: Path, level: int, diff: str, *flags: str) -> subprocess.CompletedProcess:
    """``git apply`` in ``tree``, which has no ``.git`` of its own (copy_tree).

    git must not find a repository above ``tree``: inside one (for example a
    run directory under ``out/`` of a checkout), ``git apply`` takes paths as
    relative to that repository's root, silently skips every file outside
    ``tree`` and still exits 0, so the patch tree would stay the base.
    ``GIT_CEILING_DIRECTORIES`` stops the search at ``tree``.
    """
    env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(Path(tree).resolve().parent)}
    return subprocess.run(["git", "apply", *flags, f"-p{level}", diff],
                          cwd=tree, env=env, capture_output=True, text=True)


def _numstat_paths(numstat: str) -> list[str]:
    """Paths from ``git apply --numstat`` output (``added<TAB>deleted<TAB>path``)."""
    return [line.split("\t", 2)[2] for line in numstat.splitlines() if line.count("\t") >= 2]


def _first_line(text: str) -> str:
    text = text.strip()
    return text.splitlines()[0] if text else "(no message)"


def _diff_trees(base_tree: Path, patch_tree: Path, out: Path) -> None:
    """Write the unified diff between two trees. Build outputs are not present,
    because the diff is taken from the clean copies before any build.

    Both trees live in the same work directory. git is run there with the two
    tree names, so its paths are ``a/base/src/main.c`` and
    ``b/patch/src/main.c``; :func:`_root_paths` turns them into
    ``a/src/main.c`` and ``b/src/main.c``.
    """
    result = subprocess.run(
        ["git", "diff", "--no-index", "--no-renames", "--",
         base_tree.name, patch_tree.name],
        cwd=base_tree.parent, capture_output=True, text=True,
    )
    # git diff --no-index exits 1 when the trees differ; >1 is a real error.
    # Both trees were just made by the tool, so this is not a user error.
    if result.returncode > 1:
        raise ZarabanError(ErrorCode.TOOL_INTERNAL,
                           "could not diff the base and patch directories",
                           {"stderr": result.stderr.strip()})
    out.write_text(_root_paths(result.stdout, base_tree.name, patch_tree.name),
                   encoding="utf-8")


def _root_paths(diff: str, base_name: str, patch_name: str) -> str:
    """Drop the tree names from the file paths in the diff's file headers.

    Only header lines (from ``diff --git`` up to the first ``@@``) are changed,
    so hunk content that happens to contain such a path is left alone.
    """
    a, b = f"a/{base_name}/", f"b/{patch_name}/"
    lines: list[str] = []
    in_header = False
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git "):
            in_header = True
        elif line.startswith("@@"):
            in_header = False
        if in_header:
            line = line.replace(a, "a/", 1).replace(b, "b/", 1)
        lines.append(line)
    return "".join(lines)


def _git_commit(path: Path) -> Optional[str]:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--short", "HEAD"],
        capture_output=True, text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _tree_sha256(tree: Path) -> str:
    """A stable hash of a tree: every file's relative path and contents, sorted."""
    h = hashlib.sha256()
    for f in sorted(p for p in tree.rglob("*") if p.is_file()):
        h.update(str(f.relative_to(tree)).encode("utf-8"))
        h.update(b"\0")
        h.update(f.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def _diff_info(diff_path: Path, strip: int) -> DiffInfo:
    """Changed files and hunk count of the diff, for the report.

    File paths are given after removing ``strip`` leading components, so they
    match the tree (``src/main.c``), like the paths in stack frames. A deleted
    file is listed by its old path. The per-hunk parsing used for linking is
    in diffinfo.py.
    """
    raw = diff_path.read_bytes()
    try:
        patch_set = PatchSet(raw.decode("utf-8", errors="replace"))
    except UnidiffParseError as exc:
        raise ZarabanError(ErrorCode.PATCH_APPLY_FAILED,
                           f"the patch {diff_path} is not a valid unified diff: {exc}",
                           {"diff": str(diff_path)})
    files: list[str] = []
    for f in patch_set:
        name = strip_path(f.source_file if f.is_removed_file else f.target_file, strip)
        if name not in files:
            files.append(name)
    hunks = sum(len(f) for f in patch_set)
    sha = hashlib.sha256(raw).hexdigest()
    return DiffInfo(path=str(diff_path), sha256=sha, files=files, hunks=hunks)


def strip_path(path: str, strip: int) -> str:
    """Remove ``strip`` leading path components, as ``git apply -p<strip>`` does."""
    parts = path.split("/")
    return "/".join(parts[strip:]) if len(parts) > strip else path
