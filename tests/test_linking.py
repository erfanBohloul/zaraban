"""Unit tests for zaraban/linking.py (SPEC §9), built from fake results."""

from pathlib import Path

from results_fakes import crash, frames, normal, results

from zaraban.diffinfo import load_hunks
from zaraban.findings import build_findings
from zaraban.models import (BuildName, Category, Frame, Hunk, LinkLevel, Version)
from zaraban.linking import link_crash, link_side, locate

TARGET = Path(__file__).resolve().parent.parent / "targets" / "target1_sample"
TOKEN_STACK = frames(("handle_set_command", "src/main.c", 37),
                     ("process_input", "src/main.c", 60),
                     ("main", "src/main.c", 80))
TOKEN_CHANGED = {("src/main.c", "handle_set_command")}

# A synthetic diff: one hunk at lines 20-30 of src/main.c on both sides.
HUNK = Hunk("src/main.c", "@@ -20,11 +20,11 @@", 20, 30, 20, 30, [25], [25])


def _incomplete_hunks():
    return load_hunks(TARGET / "patches" / "incomplete.patch", 4)


# -- location evidence (§9.3) ------------------------------------------------

def test_9_6_token_parser_incomplete_crash_is_in_the_changed_hunk():
    """The example of §9.6: frame #1 handle_set_command (src/main.c:37) of the
    crash on patch lies inside hunk @@ -21,14 +21,19 @@."""
    link = locate(TOKEN_STACK, _incomplete_hunks(), TOKEN_CHANGED, Version.PATCH)
    assert link.level is LinkLevel.IN_CHANGED_HUNK
    assert (link.side, link.file, link.function, link.line, link.frame, link.hunk) == (
        Version.PATCH, "src/main.c", "handle_set_command", 37, 1, "@@ -21,14 +21,19 @@")
    assert link.executed_changed_lines is None


def test_9_3_fixed_is_matched_on_the_base_side():
    base_stack = frames(("handle_set_command", "src/main.c", 32),
                        ("process_input", "src/main.c", 55))
    link = locate(base_stack, _incomplete_hunks(), TOKEN_CHANGED, Version.BASE)
    assert (link.level, link.side, link.line) == (LinkLevel.IN_CHANGED_HUNK, Version.BASE, 32)


def test_9_3_side_matters():
    # line 37 is in the patch range (21-39) but not in the base range (21-34)
    link = locate(TOKEN_STACK, _incomplete_hunks(), set(), Version.BASE)
    assert link.level is LinkLevel.UNDETERMINED


def test_9_3_crash_in_changed_function_outside_the_hunk():
    stack = frames(("parse", "src/main.c", 45), ("main", "src/main.c", 90))
    link = locate(stack, [HUNK], {("src/main.c", "parse")}, Version.PATCH)
    assert (link.level, link.function, link.line, link.frame, link.hunk) == (
        LinkLevel.IN_CHANGED_FUNCTION, "parse", 45, 1, None)


def test_9_3_check_in_a_calling_function():
    """The spec's example: a changed check in a caller affects an error in
    another function."""
    stack = frames(("copy", "src/util.c", 5), ("handle", "src/main.c", 50),
                   ("main", "src/main.c", 90))
    link = locate(stack, [HUNK], {("src/main.c", "handle")}, Version.BASE)
    assert (link.level, link.function, link.frame) == (
        LinkLevel.CHANGED_FUNCTION_IN_STACK, "handle", 2)


def test_9_3_strongest_level_in_any_frame():
    # frame 1 only in a changed function, frame 2 inside the hunk: the hunk wins
    stack = frames(("parse", "src/main.c", 45), ("handle", "src/main.c", 27))
    link = locate(stack, [HUNK], {("src/main.c", "parse")}, Version.PATCH)
    assert (link.level, link.function, link.frame) == (LinkLevel.IN_CHANGED_HUNK, "handle", 2)


def test_9_3_nearest_frame_wins_within_a_level():
    stack = frames(("a", "src/main.c", 21), ("b", "src/main.c", 22))
    assert locate(stack, [HUNK], set(), Version.PATCH).function == "a"


def test_9_3_closeness_in_a_changed_file_is_undetermined():
    """In a file the patch changed, but outside its hunks and functions, and no
    changed function in the stack: only closeness (§9.1)."""
    stack = frames(("other", "src/main.c", 31), ("main", "src/main.c", 90))
    link = locate(stack, [HUNK], {("src/main.c", "handle")}, Version.PATCH)
    assert link.level is LinkLevel.UNDETERMINED
    assert (link.file, link.function, link.line, link.frame) == (None, None, None, None)


def test_9_3_no_file_line_or_function_is_undetermined():
    assert locate([], [HUNK], {("src/main.c", "handle")}, Version.PATCH).level \
        is LinkLevel.UNDETERMINED
    unnamed = [Frame(0, None, None, None, False)]
    assert locate(unnamed, [HUNK], {("src/main.c", "handle")}, Version.PATCH).level \
        is LinkLevel.UNDETERMINED


def test_9_3_runtime_frames_are_not_checked():
    stack = [Frame(0, "__asan_memcpy", "src/main.c", 25, True),
             Frame(1, "main", "src/main.c", 90, False)]
    assert locate(stack, [HUNK], {("src/main.c", "__asan_memcpy")}, Version.PATCH).level \
        is LinkLevel.UNDETERMINED


def test_9_3_function_must_match_its_file():
    stack = frames(("parse", "src/other.c", 5))
    assert locate(stack, [HUNK], {("src/main.c", "parse")}, Version.PATCH).level \
        is LinkLevel.UNDETERMINED


def test_9_3_frame_without_file_matches_a_unique_function_name():
    stack = [Frame(0, "parse", None, None, False)]
    assert locate(stack, [], {("src/main.c", "parse")}, Version.PATCH).level \
        is LinkLevel.IN_CHANGED_FUNCTION
    ambiguous = {("src/a.c", "parse"), ("src/b.c", "parse")}
    assert locate(stack, [], ambiguous, Version.PATCH).level is LinkLevel.UNDETERMINED


def test_9_2_paths_are_normalized():
    stack = frames(("a", "./src/main.c", 21))
    link = locate(stack, [HUNK], set(), Version.PATCH)
    assert (link.level, link.file) == (LinkLevel.IN_CHANGED_HUNK, "src/main.c")


def test_9_4_executed_changed_lines_when_no_frame_matches():
    link = locate([], [HUNK], set(), Version.PATCH, executed_lines=[27, 25])
    assert (link.level, link.side, link.executed_changed_lines) == (
        LinkLevel.CHANGED_CODE_EXECUTED, Version.PATCH, [25, 27])


def test_9_4_trace_that_ran_no_changed_line_is_undetermined():
    link = locate([], [HUNK], set(), Version.PATCH, executed_lines=[])
    assert (link.level, link.executed_changed_lines) == (LinkLevel.UNDETERMINED, [])


def test_9_3_frame_evidence_is_stronger_than_the_trace():
    link = locate(TOKEN_STACK, _incomplete_hunks(), TOKEN_CHANGED, Version.PATCH,
                  executed_lines=[24])
    assert link.level is LinkLevel.IN_CHANGED_HUNK


# -- which side and which crash (§9.3) ---------------------------------------

def _findings(table):
    return build_findings(results(table)), results(table)


def test_9_3_side_by_category():
    found, _ = _findings({
        "valid_a": {"base-release": normal(0, oracle=True), "base-sanitized": normal(0, oracle=True),
                    "patch-release": normal(1, oracle=False), "patch-sanitized": normal(0, oracle=True)},
        "exploit_x": {"base-sanitized": crash()},
        "exploit_y": {"base-sanitized": crash(stack=(("f", "src/f.c", 1),)),
                      "patch-sanitized": crash(stack=(("f", "src/f.c", 1),))},
        "valid_b": {"patch-sanitized": crash("NULL_DEREF", (("g", "src/g.c", 2),))},
        "valid_c": {"patch-release": crash(stack=())},
    })
    assert [(f.category, link_side(f)) for f in found] == [
        (Category.FUNCTIONAL_REGRESSION, Version.PATCH),
        (Category.FIXED, Version.BASE),
        (Category.INCOMPLETE_FIX, Version.PATCH),
        (Category.NEW_ISSUE, Version.PATCH),
        (Category.INCONCLUSIVE, None),
    ]


def test_9_3_fixed_uses_the_base_crash():
    found, r = _findings({"exploit_primary": {"base-sanitized": crash(), "patch-sanitized": normal(1)}})
    chosen = link_crash(found[0], r)
    assert (chosen.test, chosen.build) == ("exploit_primary", BuildName.BASE_SANITIZED)


def test_9_3_incomplete_fix_uses_a_patch_crash_that_still_reaches():
    found, r = _findings({
        "exploit_primary": {"base-sanitized": crash(), "patch-sanitized": normal(1)},
        "exploit_secondary": {"base-sanitized": crash(), "patch-sanitized": crash()},
    })
    chosen = link_crash(found[0], r)
    assert (chosen.test, chosen.build) == ("exploit_secondary", BuildName.PATCH_SANITIZED)


def test_9_3_prefers_the_finding_signature_when_call_paths_differ():
    via_a = crash(stack=(("copy", "src/u.c", 5), ("caller_a", "src/main.c", 10)))
    via_b = crash(stack=(("copy", "src/u.c", 5), ("caller_b", "src/main.c", 20)))
    found, r = _findings({
        "exploit_a": {"base-sanitized": via_a, "patch-sanitized": via_b},
        "exploit_b": {"base-sanitized": via_a, "patch-sanitized": via_a},
    })
    [f] = found
    assert f.signature.endswith("caller_a")
    # exploit_a reaches on patch, but through caller_b; exploit_b keeps caller_a
    assert link_crash(f, r).test == "exploit_b"


def test_9_3_other_call_path_is_used_when_the_signature_is_not_on_patch():
    via_a = crash(stack=(("copy", "src/u.c", 5), ("caller_a", "src/main.c", 10)))
    via_b = crash(stack=(("copy", "src/u.c", 5), ("caller_b", "src/main.c", 20)))
    found, r = _findings({"exploit_a": {"base-sanitized": via_a, "patch-sanitized": via_b}})
    chosen = link_crash(found[0], r)
    assert chosen.signature.endswith("caller_b")


def test_9_3_findings_without_a_crash_have_none():
    found, r = _findings({"valid_a": {"patch-release": normal(1, oracle=False),
                                      "base-release": normal(0, oracle=True)}})
    assert found[0].category is Category.FUNCTIONAL_REGRESSION
    assert link_crash(found[0], r) is None


def test_9_3_unsigned_crash_has_no_frames_to_match():
    unsigned = crash("SEGV", stack=(), detection="SIGNAL", signal="SIGSEGV")
    found, r = _findings({"exploit_x": {"base-sanitized": unsigned, "patch-sanitized": normal(1)}})
    chosen = link_crash(found[0], r)
    assert chosen.test == "exploit_x"
    assert locate(chosen.first.analysis.frames, [HUNK], set(), Version.BASE).level \
        is LinkLevel.UNDETERMINED
