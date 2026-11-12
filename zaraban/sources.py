"""Source preparation: make the base and patch trees, and derive the diff.

This runs before anything is built (SPEC §2 step 2, §3.2, §3.3). It:

- resolves ``--base`` (a directory) and ``--patch`` (a diff file or a
  directory), as §3.2 defines;
- produces two clean source trees under the work directory, so nothing is
  ever built inside the repository (§3.3, §6.2);
- obtains the unified diff between them:
    * a diff file is used as given, applied to the base copy with ``git apply``
      at the first strip level ``-p0``..``-p4`` that applies cleanly (§3.2);
    * two directories are compared with ``git diff --no-index`` between the
      clean trees, before any build (§3.3), and the result is written with
      the usual ``a/`` ``b/`` prefixes rooted at the tree (``a/src/main.c``),
      so it reads like any ``-p1`` diff.

It records the version and diff metadata the report needs (§12.4). It does not
build or run anything, and it does not parse the diff into hunks; that is
``diffinfo.py`` (Member C, §9.2).
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from unidiff import PatchSet
from unidiff.errors import UnidiffParseError

from .models import DiffInfo, ErrorCode, VersionInfo, ZarabanError

# Never copied into a work tree: the repo's git data and run outputs (§6.2).
_IGNORE = shutil.ignore_patterns(".git", "out", "__pycache__", "*.pyc")
_MAX_STRIP = 4
_DIR_DIFF_STRIP = 1  # the diff of two directories is written rooted at a/ b/


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
    directory (§3.2). Raises :class:`ZarabanError` (exit 30) on a missing
    source or a diff that does not apply.
    """
    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)

    base_dir = Path(base_arg)
    if not base_dir.is_dir():
        raise ZarabanError(ErrorCode.SOURCE_NOT_FOUND,
                           f"--base must be an existing directory: {base_arg}",
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
        strip = None  # recorded only for the diff form (§12.4)
        copy_tree(patch_path, patch_tree)
        _diff_trees(base_tree, patch_tree, diff_path)
        patch_commit = _git_commit(patch_path)
    else:
        raise ZarabanError(ErrorCode.SOURCE_NOT_FOUND,
                           f"--patch is neither a file nor a directory: {patch_arg}",
                           {"patch": str(patch_arg)})

    base_info = VersionInfo(
        form="directory", ref=str(base_arg), git_commit=_git_commit(base_dir),
        tree_sha256=_tree_sha256(base_tree),
    )
    patch_info = VersionInfo(
        form=form, ref=str(patch_arg), git_commit=patch_commit,
        tree_sha256=_tree_sha256(patch_tree), strip_level=strip,
    )
    diff_info = _diff_info(diff_path, strip if strip is not None else _DIR_DIFF_STRIP)
    return Sources(base_tree, patch_tree, diff_path, base_info, patch_info, diff_info)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def copy_tree(src: Path, dest: Path) -> None:
    """Replace ``dest`` with a clean copy of ``src`` (no git data or run outputs).
    Also used by the builder for its per-build copies (§6.2)."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, ignore=_IGNORE, symlinks=True)


def _apply_diff(diff_file: Path, base_tree: Path, patch_tree: Path) -> int:
    """Copy the base tree and apply the diff; return the strip level used."""
    copy_tree(base_tree, patch_tree)
    for level in range(_MAX_STRIP + 1):
        check = subprocess.run(
            ["git", "apply", "--check", f"-p{level}", str(diff_file.resolve())],
            cwd=patch_tree, capture_output=True, text=True,
        )
        if check.returncode == 0:
            applied = subprocess.run(
                ["git", "apply", f"-p{level}", str(diff_file.resolve())],
                cwd=patch_tree, capture_output=True, text=True,
            )
            if applied.returncode == 0:
                return level
    raise ZarabanError(
        ErrorCode.PATCH_APPLY_FAILED,
        f"the diff does not apply to the base at any strip level -p0..-p{_MAX_STRIP}",
        {"diff": str(diff_file)},
    )


def _diff_trees(base_tree: Path, patch_tree: Path, out: Path) -> None:
    """Write the unified diff between two trees. Build outputs are not present,
    because the diff is taken from the clean copies before any build (§3.3).

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
    if result.returncode > 1:
        raise ZarabanError(ErrorCode.SOURCE_NOT_FOUND,
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
    """Changed files and hunk count of the diff, for the report (§12.4).

    File paths are given after removing ``strip`` leading components, so they
    match the tree (``src/main.c``), as §9.2 uses them. A deleted file is
    listed by its old path. The per-hunk parsing used for linking is
    diffinfo.py (Member C, §9.2).
    """
    raw = diff_path.read_bytes()
    try:
        patch_set = PatchSet(raw.decode("utf-8", errors="replace"))
    except UnidiffParseError as exc:
        raise ZarabanError(ErrorCode.PATCH_APPLY_FAILED,
                           f"the diff could not be parsed: {exc}",
                           {"diff": str(diff_path)})
    files: list[str] = []
    for f in patch_set:
        name = _strip_path(f.source_file if f.is_removed_file else f.target_file, strip)
        if name not in files:
            files.append(name)
    hunks = sum(len(f) for f in patch_set)
    sha = hashlib.sha256(raw).hexdigest()
    return DiffInfo(path=str(diff_path), sha256=sha, files=files, hunks=hunks)


def _strip_path(path: str, strip: int) -> str:
    """Remove ``strip`` leading path components, as ``git apply -p<strip>`` does."""
    parts = path.split("/")
    return "/".join(parts[strip:]) if len(parts) > strip else path
