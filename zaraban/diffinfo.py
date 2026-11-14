"""Reading the diff for linking findings to the patch.

The diff is parsed with ``unidiff`` into one :class:`Hunk` per hunk. For each
hunk the tool knows:

- on the **base side**: its line range and the removed lines, in base line
  numbers;
- on the **patch side**: its line range and the added lines, in patch line
  numbers.

A hunk's line range includes its unchanged context lines, so a crash on a
context line is still "inside the changed hunk".

File paths are given after removing the strip level that was used to apply the
diff, so they match the paths in stack traces (``src/main.c``). As in
``git apply``, a changed or added file is named by its new path and a deleted
file by its old path.

**Changed functions** come from the source code, not from hunk headers:
``universal-ctags`` gives the start and end line of every function in
the base or patch tree, and a function is changed on a side when a changed
line of that side falls inside it. On the base side the changed lines are the
removed lines, on the patch side the added lines. A change can also be an
insertion with nothing removed, for example a new length check: the base side
has no changed line for it, only a position between two base lines. A
function also counts as changed on a side when such a position lies inside
it. Otherwise a check added to a caller would not mark the caller as changed
on base, and the location evidence for a ``FIXED`` finding would be lost.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from unidiff import PatchSet
from unidiff.errors import UnidiffParseError

from .models import ErrorCode, Hunk, Version, ZarabanError
from .sources import DIR_DIFF_STRIP, Sources, strip_path


def parse_hunks(diff_text: str, strip: int) -> list[Hunk]:
    """Every hunk of a unified diff, in file order, with paths stripped.

    ``strip`` is the number of leading path components to remove, the same
    level ``git apply -p<strip>`` used. Binary files have no hunks and
    are skipped. Raises :class:`ZarabanError` if the text is not a diff.
    """
    try:
        patch_set = PatchSet(diff_text)
    except UnidiffParseError as exc:
        raise ZarabanError(ErrorCode.PATCH_APPLY_FAILED,
                           f"the diff could not be parsed: {exc}")
    hunks: list[Hunk] = []
    for patched_file in patch_set:
        raw_path = patched_file.source_file if patched_file.is_removed_file \
            else patched_file.target_file
        path = strip_path(raw_path, strip)
        for h in patched_file:
            hunks.append(Hunk(
                file=path,
                header=f"@@ -{h.source_start},{h.source_length} "
                       f"+{h.target_start},{h.target_length} @@",
                # A side with length 0 (a new or deleted file) gets an empty
                # range: end = start - 1, so no line falls inside it.
                base_start=h.source_start,
                base_end=h.source_start + h.source_length - 1,
                patch_start=h.target_start,
                patch_end=h.target_start + h.target_length - 1,
                removed_lines=[ln.source_line_no for ln in h if ln.is_removed],
                added_lines=[ln.target_line_no for ln in h if ln.is_added],
            ))
    return hunks


def load_hunks(diff_path: str | Path, strip: int) -> list[Hunk]:
    """:func:`parse_hunks` of a diff file, read the same way sources.py reads it."""
    raw = Path(diff_path).read_bytes()
    return parse_hunks(raw.decode("utf-8", errors="replace"), strip)


def sources_hunks(sources: Sources) -> list[Hunk]:
    """The hunks of a run's diff, as prepared by sources.py.

    A diff file is read at the strip level that applied it; the diff that
    sources.py writes for a patch directory is rooted at ``a/`` ``b/``.
    The level is taken with ``is None``, because ``-p0`` is a valid level.
    """
    level = sources.patch.strip_level
    return load_hunks(sources.diff_path, DIR_DIFF_STRIP if level is None else level)


# ---------------------------------------------------------------------------
# Changed functions
# ---------------------------------------------------------------------------

# Function definitions only; prototypes and macros are not code that runs.
_CTAGS = ["ctags", "--output-format=json", "--fields=+ne", "--languages=C,C++",
          "--kinds-C=f", "--kinds-C++=f", "-o", "-"]


def function_ranges(tree: str | Path, rel_path: str) -> list[tuple[str, int, int]]:
    """``(name, start, end)`` of every function defined in one file of a tree.

    Lines are 1-based and inclusive. A file that does not exist on this side
    (added or deleted by the patch) or is not C/C++ has no functions.
    """
    if not (Path(tree) / rel_path).is_file():
        return []
    try:
        result = subprocess.run([*_CTAGS, rel_path], cwd=tree,
                                capture_output=True, text=True)
    except FileNotFoundError:
        raise ZarabanError(ErrorCode.TOOL_INTERNAL,
                           "universal-ctags is not installed (needed to find changed functions)")
    if result.returncode != 0:
        raise ZarabanError(ErrorCode.TOOL_INTERNAL,
                           f"ctags failed on {rel_path}",
                           {"stderr": result.stderr.strip()})
    out: list[tuple[str, int, int]] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        tag = json.loads(line)
        if tag.get("_type") == "tag" and tag.get("kind") == "function":
            out.append((tag["name"], tag["line"], tag.get("end", tag["line"])))
    return out


def changed_positions(hunk: Hunk, side: Version) -> tuple[list[int], list[tuple[int, int]]]:
    """Where the patch changed this hunk, in the line numbers of ``side``.

    Returns ``(lines, gaps)``: ``lines`` are the changed lines of that side
    (removed lines on base, added lines on patch); ``gaps`` are the positions
    of changes that left nothing on that side (lines added on patch are a gap
    on base, and the reverse), each as the pair of lines around it.

    The gaps are found from the context lines alone: the context lines of the
    two sides are the same lines in the same order, so the n-th context line
    on one side is the n-th on the other.
    """
    if side is Version.BASE:
        start, end, own, other = hunk.base_start, hunk.base_end, hunk.removed_lines, hunk.added_lines
        other_start, other_end = hunk.patch_start, hunk.patch_end
    else:
        start, end, own, other = hunk.patch_start, hunk.patch_end, hunk.added_lines, hunk.removed_lines
        other_start, other_end = hunk.base_start, hunk.base_end

    if end < start:
        # Empty range: the change sits after line ``start`` (unified diff rule,
        # e.g. "@@ -5,0 +6,2 @@" inserts after base line 5).
        return list(own), ([(start, start + 1)] if other else [])

    own_set, other_set = set(own), set(other)
    ctx = [n for n in range(start, end + 1) if n not in own_set]
    other_ctx = [n for n in range(other_start, other_end + 1) if n not in other_set]
    gaps: list[tuple[int, int]] = []
    for line in other:
        k = sum(1 for n in other_ctx if n < line)  # context lines above it
        before = ctx[k - 1] if k > 0 else start - 1
        after = ctx[k] if k < len(ctx) else end + 1
        if (before, after) not in gaps:
            gaps.append((before, after))
    return list(own), gaps


def changed_functions(tree: str | Path, hunks: list[Hunk], side: Version) -> set[tuple[str, str]]:
    """``(file, function)`` of every function the patch changed on ``side``.

    ``tree`` is the source tree of that side (base or patch). A function is
    changed when a changed line of that side is inside it, or a change that
    left nothing on that side sits between two of its lines (see the module
    docstring).
    """
    by_file: dict[str, list[Hunk]] = {}
    for h in hunks:
        by_file.setdefault(h.file, []).append(h)

    changed: set[tuple[str, str]] = set()
    for rel_path, file_hunks in by_file.items():
        ranges = function_ranges(tree, rel_path)
        if not ranges:
            continue
        for h in file_hunks:
            lines, gaps = changed_positions(h, side)
            for name, lo, hi in ranges:
                if any(lo <= n <= hi for n in lines) \
                        or any(lo <= a and b <= hi for a, b in gaps):
                    changed.add((rel_path, name))
    return changed


def changed_lines_by_file(hunks: list[Hunk], side: Version) -> dict[str, set[int]]:
    """The changed line numbers of ``side``, per file: added lines on the
    patch side, removed lines on the base side. Insertions that leave nothing on
    ``side`` have no line there and are omitted."""
    out: dict[str, set[int]] = {}
    for h in hunks:
        lines, _gaps = changed_positions(h, side)
        if lines:
            out.setdefault(h.file, set()).update(lines)
    return out
