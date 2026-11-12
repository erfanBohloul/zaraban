"""Linking findings to the patch (SPEC §9).

A link is reported only with **location evidence** from an actual execution
(§9.3) together with **comparative evidence** from running both versions on
the same input (§9.5). Being close to a changed line is never enough: when the
evidence is missing, the link is ``UNDETERMINED`` (§9.1).

This module never changes a finding's category or the exit code (§9.6).

Section numbers such as §9.3 refer to docs/SPEC.md.
"""

from __future__ import annotations

import posixpath
from typing import Optional

from zaraban.findings import stable_key
from zaraban.models import (
    BuildName,
    Category,
    CombinedResult,
    Finding,
    Frame,
    Hunk,
    Link,
    LinkLevel,
    OnPatch,
    Results,
    Version,
)

ChangedFunctions = set[tuple[str, str]]  # (file, function), from diffinfo.changed_functions

# ---------------------------------------------------------------------------
# Location evidence (§9.3)
# ---------------------------------------------------------------------------


def locate(frames: list[Frame], hunks: list[Hunk], changed: ChangedFunctions,
           side: Version, executed_lines: Optional[list[int]] = None) -> Link:
    """The strongest location evidence of one stack trace on one side of the diff.

    Every frame that is not a runtime frame is checked, not only the top one,
    and the strongest level found in any frame is reported (§9.3):

    - ``IN_CHANGED_HUNK``: a frame's file and line are inside a hunk's range
      on ``side`` (context lines included, §9.2);
    - ``IN_CHANGED_FUNCTION``: the crashing frame (the first non-runtime frame
      with a name) is inside a function the patch changed on ``side``;
    - ``CHANGED_FUNCTION_IN_STACK``: a changed function appears lower in the
      stack, as a caller of the crashing code;
    - ``CHANGED_CODE_EXECUTED``: no frame matches, but the execution trace
      (§9.4) shows that changed lines of ``side`` ran (``executed_lines``);
    - ``UNDETERMINED``: none of these. A crash in a changed file but outside
      every changed hunk and function is only closeness, so it stays here.

    Within one level the frame nearest the top of the stack is reported.
    """
    app = [f for f in frames if not f.runtime]

    for f in app:
        if f.file and f.line is not None:
            path = _norm(f.file)
            for h in hunks:
                if h.contains(side, path, f.line):
                    return _frame_link(LinkLevel.IN_CHANGED_HUNK, side, f, h)

    named = [f for f in app if f.function]
    if named and _is_changed(named[0], changed):
        return _frame_link(LinkLevel.IN_CHANGED_FUNCTION, side, named[0])
    for f in named[1:]:
        if _is_changed(f, changed):
            return _frame_link(LinkLevel.CHANGED_FUNCTION_IN_STACK, side, f)

    if executed_lines:
        return Link(level=LinkLevel.CHANGED_CODE_EXECUTED, side=side,
                    executed_changed_lines=sorted(executed_lines))
    return Link(level=LinkLevel.UNDETERMINED, side=side,
                executed_changed_lines=[] if executed_lines is not None else None)


def _frame_link(level: LinkLevel, side: Version, f: Frame, h: Optional[Hunk] = None) -> Link:
    return Link(level=level, side=side, file=_norm(f.file) if f.file else None,
                function=f.function, line=f.line, frame=f.index,
                hunk=h.header if h else None)


def _is_changed(f: Frame, changed: ChangedFunctions) -> bool:
    """Whether a frame's function is one the patch changed.

    The file must match too, because two files may define a static function
    with the same name. A frame without a file (no debug information) matches
    by name only when exactly one changed function has that name.
    """
    if f.file:
        return (_norm(f.file), f.function) in changed
    return sum(1 for _, fn in changed if fn == f.function) == 1


def _norm(path: str) -> str:
    """``./src/main.c`` -> ``src/main.c``, to compare with diff paths."""
    return posixpath.normpath(path)


# ---------------------------------------------------------------------------
# Which side and which crash a finding is linked through (§9.3, §9.4)
# ---------------------------------------------------------------------------

# FIXED: the error is gone on patch, so its crash is on base, matched against
# the base side of the diff. INCOMPLETE_FIX and NEW_ISSUE: the crash on patch,
# against the patch side. FUNCTIONAL_REGRESSION: no crash, only the execution
# trace on patch (§9.4). INCONCLUSIVE: no side; the link stays UNDETERMINED.
_SIDE = {
    Category.FIXED: Version.BASE,
    Category.INCOMPLETE_FIX: Version.PATCH,
    Category.NEW_ISSUE: Version.PATCH,
    Category.FUNCTIONAL_REGRESSION: Version.PATCH,
}


def link_side(finding: Finding) -> Optional[Version]:
    """The side of the diff a finding is checked against, or None."""
    return _SIDE.get(finding.category)


def link_crash(finding: Finding, results: Results) -> Optional[CombinedResult]:
    """The crash whose stack trace is checked against the diff (§9.3).

    ``FIXED``: a crash on ``base-sanitized``; ``INCOMPLETE_FIX`` and
    ``NEW_ISSUE``: a crash on ``patch-sanitized`` of a test that still
    reaches the error. A crash with the finding's own signature is preferred;
    otherwise (call paths differ, §8.2) the first crash of the same bug.
    Tests are tried in the finding's order. None for findings without a
    crash, or whose crash has no stack trace (§8.3).
    """
    side = link_side(finding)
    if side is None or finding.category is Category.FUNCTIONAL_REGRESSION:
        return None
    build = BuildName.BASE_SANITIZED if side is Version.BASE else BuildName.PATCH_SANITIZED

    candidates: list[CombinedResult] = []
    for t in finding.tests:
        if side is Version.PATCH and t.on_patch is not OnPatch.REACHES:
            continue
        r = results[t.test].get(build)
        if r is not None and r.stable_crash:
            candidates.append(r)
    if finding.signature is None:  # §8.3: one test, no stack trace to compare
        return candidates[0] if candidates else None
    keyed = [r for r in candidates if stable_key(r) is not None]
    for r in keyed:
        if r.signature == finding.signature:
            return r
    return keyed[0] if keyed else None
