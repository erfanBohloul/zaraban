"""Linking findings to the patch (SPEC §9).

:func:`link_findings` is the entry point: it sets ``finding.link`` on every
finding that :func:`zaraban.findings.build_findings` made.

A link is reported only with **location evidence** from an actual execution
(§9.3) together with **comparative evidence** from running both versions on
the same input (§9.5). Being close to a changed line is never enough: when the
evidence is missing, the link is ``UNDETERMINED`` (§9.1).

This module never changes a finding's category or the exit code (§9.6).

Section numbers such as §9.3 refer to docs/SPEC.md.
"""

from __future__ import annotations

import posixpath
from pathlib import Path
from typing import Optional

from .diffinfo import changed_functions
from .findings import oracle_mismatches, stable_key
from .models import (
    BuildName,
    Category,
    CombinedResult,
    Finding,
    Frame,
    Hunk,
    Link,
    LinkLevel,
    OnPatch,
    Outcome,
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


# ---------------------------------------------------------------------------
# Comparative evidence (§9.5)
# ---------------------------------------------------------------------------


def comparative_tests(finding: Finding, results: Results) -> list[str]:
    """The tests that show, by running both versions on the same input, that
    the versions differ in the way the category claims (§9.5).

    - ``FIXED``: crash on base, no crash on patch (``blocked``).
    - ``INCOMPLETE_FIX``: crash on both versions (``reaches`` and a crash on
      base too), plus the tests the patch blocks: a blocked test shows that
      the patch acts on this error, a still-crashing one that it does not act
      enough.
    - ``NEW_ISSUE``: no crash on base, crash on patch.
    - ``FUNCTIONAL_REGRESSION``: matches its oracle on base and not on patch.
    - ``INCONCLUSIVE``: none; the category itself says the evidence is not
      enough.
    """
    out: list[str] = []
    for t in finding.tests:
        per_build = results[t.test]
        base = per_build.get(BuildName.BASE_SANITIZED)
        base_crash = base is not None and base.outcome is Outcome.CRASH
        if finding.category is Category.FIXED:
            ok = t.on_patch is OnPatch.BLOCKED
        elif finding.category is Category.INCOMPLETE_FIX:
            ok = t.on_patch is OnPatch.BLOCKED or (t.on_patch is OnPatch.REACHES and base_crash)
        elif finding.category is Category.NEW_ISSUE:
            ok = t.on_patch is OnPatch.REACHES and not base_crash
        elif finding.category is Category.FUNCTIONAL_REGRESSION:
            ok = not oracle_mismatches(per_build, Version.BASE) \
                and bool(oracle_mismatches(per_build, Version.PATCH))
        else:
            ok = False
        if ok:
            out.append(t.test)
    return out


# ---------------------------------------------------------------------------
# Explanation and the entry point (§9.6)
# ---------------------------------------------------------------------------


def explain(finding: Finding, link: Link, crash: Optional[CombinedResult]) -> str:
    """One or two sentences built only from the recorded facts (§9.6): where
    the evidence lies in the diff, then what the comparison of the versions
    shows, or why it shows nothing.

    ``link`` is the location evidence of :func:`locate` with its comparative
    tests already set, before :func:`link_findings` applies §9.1.
    """
    return f"{_location_sentence(finding, link, crash)} {_comparison_sentence(finding, link)}".strip()


def _location_sentence(finding: Finding, link: Link, crash: Optional[CombinedResult]) -> str:
    side = link.side.value if link.side else None
    where = f"frame #{link.frame} {link.function} ({link.file}:{link.line})"
    if link.level is LinkLevel.IN_CHANGED_HUNK:
        return f"{where[0].upper()}{where[1:]} of the crash on {side} lies inside hunk {link.hunk}."
    if link.level is LinkLevel.IN_CHANGED_FUNCTION:
        return (f"The crash on {side} happens in {where}, a function the patch changed, "
                f"outside its hunks.")
    if link.level is LinkLevel.CHANGED_FUNCTION_IN_STACK:
        return f"The crash on {side} is reached through {where}, a function the patch changed."
    test = crash.test if crash else (finding.tests[0].test if finding.tests else "the test")
    if link.level is LinkLevel.CHANGED_CODE_EXECUTED:
        lines = link.executed_changed_lines or []
        what = f"changed line{'s' if len(lines) > 1 else ''} {', '.join(map(str, lines))}"
        lead = "No frame of the crash lies in changed code, but the" if crash else "The"
        return f"{lead} execution trace shows {test} running {what} of the {side} side."
    # UNDETERMINED
    if finding.category is Category.INCONCLUSIVE:
        return "The evidence is not enough to link this finding to the diff."
    if crash is not None and any(not f.runtime and f.function for f in crash.first.analysis.frames):
        why = f"No frame of the crash on {side} lies in a changed hunk or function"
    elif crash is not None:
        why = f"The crash on {side} has no stack trace with function names"
    else:
        why = "There is no crash stack"
    if link.executed_changed_lines == []:
        return f"{why}, and the execution trace runs no changed line of the {side} side, " \
               f"so the link is undetermined."
    return f"{why}, and no execution trace was made, so the link is undetermined."


def _comparison_sentence(finding: Finding, link: Link) -> str:
    on = {t.test: t.on_patch for t in finding.tests}
    reaches = [t for t, o in on.items() if o is OnPatch.REACHES]
    blocked = [t for t, o in on.items() if o is OnPatch.BLOCKED]
    tests = link.comparative_tests
    if not tests and finding.category in _NEEDED:
        return _missing_sentence(finding, link)
    if finding.category is Category.FIXED and tests:
        return f"{_and(tests)} {_verb(tests, 'crashes', 'crash')} on base and not on patch."
    if finding.category is Category.INCOMPLETE_FIX:
        if blocked:
            return (f"The patch blocks {_and(blocked)} but {_and(reaches)} still "
                    f"{_verb(reaches, 'reaches', 'reach')} the same error.")
        return f"{_and(reaches)} still {_verb(reaches, 'reaches', 'reach')} the same error on patch."
    if finding.category is Category.NEW_ISSUE and tests:
        return f"{_and(tests)} {_verb(tests, 'crashes', 'crash')} on patch and not on base."
    if finding.category is Category.FUNCTIONAL_REGRESSION and tests:
        return f"{_and(tests)} {_verb(tests, 'matches', 'match')} its oracle on base and not on patch."
    return ""


# What the comparison must show for each category (§9.5), in words.
_NEEDED = {
    Category.FIXED: "crashes on base and not on patch",
    Category.INCOMPLETE_FIX: "reaches this error on both versions or is blocked by the patch",
    Category.NEW_ISSUE: "crashes on patch and not on base",
    Category.FUNCTIONAL_REGRESSION: "matches its oracle on base and not on patch",
}


def _missing_sentence(finding: Finding, link: Link) -> str:
    """Why no test gives comparative evidence: what each test did instead."""
    why = []
    for t in finding.tests:
        if t.on_patch is OnPatch.OTHER_ERROR:
            why.append(f"{t.test} crashes with another error on patch")
        elif t.on_patch is None and finding.category is not Category.FUNCTIONAL_REGRESSION:
            why.append(f"the patch result of {t.test} is flaky")
        elif t.on_patch is OnPatch.REACHES and finding.category is Category.NEW_ISSUE:
            why.append(f"{t.test} also crashes on base")
        elif t.on_patch is OnPatch.REACHES and finding.category is Category.INCOMPLETE_FIX:
            why.append(f"{t.test} crashes only on patch")
    detail = f" ({'; '.join(why)})" if why else ""
    text = f"no test {_NEEDED[finding.category]}{detail}"
    if link.level is LinkLevel.UNDETERMINED:  # the first sentence already says so
        return text[0].upper() + text[1:] + "."
    return f"But {text}, so the link is undetermined."


def _and(names: list[str]) -> str:
    """``a``, ``a and b``, ``a, b and c``."""
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def _verb(names: list[str], one: str, many: str) -> str:
    return one if len(names) == 1 else many


def link_findings(findings: list[Finding], results: Results, hunks: list[Hunk],
                  base_tree: str | Path, patch_tree: str | Path,
                  traces: Optional[dict[str, list[int]]] = None) -> list[Finding]:
    """Set ``finding.link`` on every finding (§9.6) and return the findings.

    ``hunks`` come from :func:`zaraban.diffinfo.load_hunks`; the trees are the
    clean base and patch source copies, for the changed functions (§9.2).
    ``traces`` maps a finding id to the changed lines its test executed on the
    finding's side (§9.4); a finding without an entry had no trace made.
    Changed functions are computed once per side, and only when a stack trace
    needs them.

    A link needs both kinds of evidence (§9.1): when no test gives
    comparative evidence (§9.5), the level is ``UNDETERMINED`` even if a frame
    matched the diff. This happens, for example, when the only test of a
    ``FIXED`` finding crashes earlier on patch with another error, which may
    only hide the base error.
    """
    trees = {Version.BASE: base_tree, Version.PATCH: patch_tree}
    changed: dict[Version, set[tuple[str, str]]] = {}
    for f in findings:
        side = link_side(f)
        crash = link_crash(f, results)
        if side is None:
            link = Link(level=LinkLevel.UNDETERMINED)
        else:
            frames = crash.first.analysis.frames if crash else []
            if frames and side not in changed:
                changed[side] = changed_functions(trees[side], hunks, side)
            link = locate(frames, hunks, changed.get(side, set()), side,
                          (traces or {}).get(f.id))
        link.comparative_tests = comparative_tests(f, results)
        link.explanation = explain(f, link, crash)
        # §9.1: location evidence counts only together with comparative
        # evidence. Without it the link is UNDETERMINED; the matched frame and
        # hunk stay recorded as facts, and the explanation says what is missing.
        if not link.comparative_tests:
            link.level = LinkLevel.UNDETERMINED
        f.link = link
    return findings
