"""Reading the diff for linking findings to the patch (SPEC §9.2).

The diff is parsed with ``unidiff`` into one :class:`Hunk` per hunk. For each
hunk the tool knows:

- on the **base side**: its line range and the removed lines, in base line
  numbers;
- on the **patch side**: its line range and the added lines, in patch line
  numbers.

A hunk's line range includes its unchanged context lines, so a crash on a
context line is still "inside the changed hunk" (§9.2).

File paths are given after removing the strip level that was used to apply the
diff (§3.2), so they match the paths in stack traces (``src/main.c``). As in
``git apply``, a changed or added file is named by its new path and a deleted
file by its old path.

Section numbers such as §9.2 refer to docs/SPEC.md.
"""

from __future__ import annotations

from pathlib import Path

from unidiff import PatchSet
from unidiff.errors import UnidiffParseError

from zaraban.models import ErrorCode, Hunk, ZarabanError
from zaraban.sources import _strip_path


def parse_hunks(diff_text: str, strip: int) -> list[Hunk]:
    """Every hunk of a unified diff, in file order, with paths stripped.

    ``strip`` is the number of leading path components to remove, the same
    level ``git apply -p<strip>`` used (§3.2). Binary files have no hunks and
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
        path = _strip_path(raw_path, strip)
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
