"""Unit tests for zaraban/linking.py (SPEC §9), built from fake results."""

import shutil
import subprocess
from pathlib import Path

import pytest
from results_fakes import crash, frames, normal, results, timeout

from zaraban import linking
from zaraban.diffinfo import load_hunks
from zaraban.findings import build_findings
from zaraban.models import (BUILD_ORDER, BuildName, Category, Frame, Hunk, LinkLevel,
                            Version)
from zaraban.linking import (comparative_tests, link_crash, link_findings, link_side,
                             locate)

TARGET = Path(__file__).resolve().parent.parent / "targets" / "test_token_parser"
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


# -- comparative evidence (§9.5) ---------------------------------------------

OK = normal(0, oracle=True)
REJECTED = normal(1, oracle=False, reasons=["exit code 1, expected 0"])


def _all(spec):
    return {b.value: spec for b in BUILD_ORDER}


def test_9_5_fixed_tests_crash_on_base_not_on_patch():
    k2 = crash("USE_AFTER_FREE", (("cleanup", "src/p.c", 50),))
    found, r = _findings({
        "exploit_a": {"base-sanitized": crash(), "patch-sanitized": normal(1)},
        "exploit_b": {"base-sanitized": crash(), "patch-sanitized": k2},     # other error
    })
    fixed = found[0]
    assert fixed.category is Category.FIXED
    assert comparative_tests(fixed, r) == ["exploit_a"]


def test_9_5_incomplete_fix_has_both_reaching_and_blocked_tests():
    found, r = _findings({
        "exploit_primary": {"base-sanitized": crash(), "patch-sanitized": normal(1)},
        "exploit_secondary": {"base-sanitized": crash(), "patch-sanitized": crash()},
        "exploit_bypass": {"patch-sanitized": crash()},   # crashes only on patch
    })
    [f] = found
    assert comparative_tests(f, r) == ["exploit_primary", "exploit_secondary"]


def test_9_5_new_issue_tests_do_not_crash_on_base():
    found, r = _findings({"valid_echo": {"patch-sanitized": crash("NULL_DEREF", (("g", "src/g.c", 2),))}})
    assert comparative_tests(found[0], r) == ["valid_echo"]


def test_9_5_functional_regression_and_inconclusive():
    found, r = _findings({
        "valid_set": {**_all(OK), "patch-release": REJECTED},
        "valid_bad": {**_all(OK), "base-release": REJECTED},
    })
    assert [(f.category, comparative_tests(f, r)) for f in found] == [
        (Category.FUNCTIONAL_REGRESSION, ["valid_set"]),
        (Category.INCONCLUSIVE, []),
    ]


def test_9_5_functional_regression_ignores_crashed_builds_like_8_4():
    """§8.4 judges only builds that did not crash; the comparative evidence
    must use the same builds, or the finding would have no evidence."""
    found, r = _findings({"valid_set": {**_all(OK), "base-sanitized": crash(),
                                        "patch-release": REJECTED}})
    regression = [f for f in found if f.category is Category.FUNCTIONAL_REGRESSION]
    assert [comparative_tests(f, r) for f in regression] == [["valid_set"]]


# -- explanation and link_findings (§9.6) ------------------------------------

def _fake_changed(monkeypatch, changed):
    """Replace ctags with a fixed set of changed functions; count the calls."""
    calls = []

    def fake(tree, hunks, side):
        calls.append(side)
        return changed
    monkeypatch.setattr(linking, "changed_functions", fake)
    return calls


def _incomplete_results():
    return results({
        "exploit_primary": {"base-sanitized": crash(), "patch-sanitized": normal(1)},
        "exploit_secondary": {"base-sanitized": crash(), "patch-sanitized": crash()},
    })


def test_9_6_token_parser_incomplete_link(monkeypatch):
    _fake_changed(monkeypatch, TOKEN_CHANGED)
    r = _incomplete_results()
    [f] = link_findings(build_findings(r), r, _incomplete_hunks(), "base", "patch")
    link = f.link
    assert link.level is LinkLevel.IN_CHANGED_HUNK
    assert link.comparative_tests == ["exploit_primary", "exploit_secondary"]
    assert link.explanation == (
        "Frame #1 handle_set_command (src/main.c:37) of the crash on patch lies inside "
        "hunk @@ -21,14 +21,19 @@. The patch blocks exploit_primary but exploit_secondary "
        "still reaches the same error.")


def test_9_6_fixed_link_on_base(monkeypatch):
    _fake_changed(monkeypatch, TOKEN_CHANGED)
    base_crash = crash(stack=(("handle_set_command", "src/main.c", 32),
                              ("process_input", "src/main.c", 55)))
    r = results({"exploit_primary": {"base-sanitized": base_crash, "patch-sanitized": normal(1)},
                 "exploit_secondary": {"base-sanitized": base_crash, "patch-sanitized": normal(1)}})
    [f] = link_findings(build_findings(r), r, _incomplete_hunks(), "base", "patch")
    assert (f.link.level, f.link.side, f.link.line) == (LinkLevel.IN_CHANGED_HUNK, Version.BASE, 32)
    assert f.link.explanation.endswith(
        "exploit_primary and exploit_secondary crash on base and not on patch.")


def test_9_6_changed_function_and_caller_explanations(monkeypatch):
    _fake_changed(monkeypatch, {("src/main.c", "handle")})
    in_fn = crash(stack=(("handle", "src/main.c", 90),))
    in_caller = crash("USE_AFTER_FREE", (("copy", "src/u.c", 5), ("handle", "src/main.c", 95)))
    r = results({"valid_a": {"patch-sanitized": in_fn}, "valid_b": {"patch-sanitized": in_caller}})
    a, b = link_findings(build_findings(r), r, [HUNK], "base", "patch")
    assert a.link.level is LinkLevel.IN_CHANGED_FUNCTION
    assert a.link.explanation == (
        "The crash on patch happens in frame #1 handle (src/main.c:90), a function the patch "
        "changed, outside its hunks. valid_a crashes on patch and not on base.")
    assert b.link.level is LinkLevel.CHANGED_FUNCTION_IN_STACK
    assert b.link.explanation.startswith(
        "The crash on patch is reached through frame #2 handle (src/main.c:95)")


def test_9_6_undetermined_link_says_why(monkeypatch):
    _fake_changed(monkeypatch, set())
    far = crash(stack=(("other", "src/main.c", 300),))
    r = results({"valid_a": {"patch-sanitized": far}})
    [f] = link_findings(build_findings(r), r, [HUNK], "base", "patch")
    assert f.link.level is LinkLevel.UNDETERMINED
    assert f.category is Category.NEW_ISSUE      # the link never changes the category
    assert f.link.explanation == (
        "No frame of the crash on patch lies in a changed hunk or function, and no execution "
        "trace was made, so the link is undetermined. valid_a crashes on patch and not on base.")


def test_9_4_functional_regression_needs_the_trace(monkeypatch):
    calls = _fake_changed(monkeypatch, set())
    r = results({"valid_set": {**_all(OK), "patch-release": REJECTED}})
    found = build_findings(r)
    [f] = link_findings(found, r, [HUNK], "base", "patch")
    assert f.link.level is LinkLevel.UNDETERMINED and f.link.side is Version.PATCH
    assert f.link.explanation.startswith("There is no crash stack, and no execution trace")
    assert calls == []   # no stack trace, so ctags is not needed

    [f] = link_findings(found, r, [HUNK], "base", "patch", traces={"F-001": [25]})
    assert (f.link.level, f.link.executed_changed_lines) == (LinkLevel.CHANGED_CODE_EXECUTED, [25])
    assert f.link.explanation == ("The execution trace shows valid_set running changed line 25 "
                                  "of the patch side. valid_set matches its oracle on base and "
                                  "not on patch.")


def test_9_4_trace_for_a_crash_without_frame_evidence(monkeypatch):
    _fake_changed(monkeypatch, set())
    r = results({"valid_a": {"patch-sanitized": crash(stack=(("other", "src/main.c", 300),))}})
    [f] = link_findings(build_findings(r), r, [HUNK], "base", "patch", traces={"F-001": [27, 25]})
    assert f.link.explanation.startswith(
        "No frame of the crash lies in changed code, but the execution trace shows valid_a "
        "running changed lines 25, 27 of the patch side.")


def test_9_6_inconclusive_is_undetermined_without_side(monkeypatch):
    _fake_changed(monkeypatch, set())
    r = results({"exploit_x": {"base-sanitized": crash(), "patch-sanitized": timeout()}})
    found = link_findings(build_findings(r), r, [HUNK], "base", "patch")
    inconclusive = [f for f in found if f.category is Category.INCONCLUSIVE]
    assert inconclusive
    for f in inconclusive:
        assert (f.link.level, f.link.side, f.link.comparative_tests) == (
            LinkLevel.UNDETERMINED, None, [])
        assert f.link.explanation == "The evidence is not enough to link this finding to the diff."


def test_9_6_changed_functions_once_per_side(monkeypatch):
    calls = _fake_changed(monkeypatch, set())
    r = results({"exploit_a": {"base-sanitized": crash()},
                 "exploit_b": {"base-sanitized": crash("USE_AFTER_FREE", (("x", "src/x.c", 1),))},
                 "valid_c": {"patch-sanitized": crash("NULL_DEREF", (("y", "src/y.c", 1),))}})
    link_findings(build_findings(r), r, [HUNK], "base", "patch")
    assert calls == [Version.BASE, Version.PATCH]


def _has_universal_ctags():
    if shutil.which("ctags") is None:
        return False
    out = subprocess.run(["ctags", "--version"], capture_output=True, text=True).stdout
    return "Universal Ctags" in out


@pytest.mark.skipif(not _has_universal_ctags(), reason="universal-ctags is in the Docker image only")
def test_9_6_token_parser_incomplete_end_to_end(tmp_path):
    """Real trees, real diff, real ctags: the example of §9.6."""
    for side, src in (("base", TARGET / "src" / "main.c"),
                      ("patch", TARGET / "versions" / "patch_incomplete" / "src" / "main.c")):
        (tmp_path / side / "src").mkdir(parents=True)
        shutil.copyfile(src, tmp_path / side / "src" / "main.c")
    r = _incomplete_results()
    [f] = link_findings(build_findings(r), r, _incomplete_hunks(),
                        tmp_path / "base", tmp_path / "patch")
    assert f.link.explanation.startswith(
        "Frame #1 handle_set_command (src/main.c:37) of the crash on patch lies inside hunk "
        "@@ -21,14 +21,19 @@.")


# -- both kinds of evidence (§9.1) -------------------------------------------

def test_9_1_location_without_comparative_evidence_is_undetermined(monkeypatch):
    """On patch the test crashes earlier with another error, so nothing shows
    that the base overflow is gone: it may only be masked. The frame lies in
    the hunk, but without comparative evidence the link is UNDETERMINED."""
    _fake_changed(monkeypatch, set())
    k1 = crash("STACK_BUFFER_OVERFLOW", (("parse", "src/main.c", 25),))
    k2 = crash("USE_AFTER_FREE", (("init", "src/other.c", 3),))
    r = results({"exploit_x": {"base-sanitized": k1, "patch-sanitized": k2}})
    fixed, new = link_findings(build_findings(r), r, [HUNK], "base", "patch")
    assert fixed.category is Category.FIXED          # the link never changes it (§9.6)
    link = fixed.link
    assert (link.level, link.comparative_tests) == (LinkLevel.UNDETERMINED, [])
    # the matched frame is still recorded, as a fact
    assert (link.file, link.function, link.line, link.hunk) == (
        "src/main.c", "parse", 25, "@@ -20,11 +20,11 @@")
    assert link.explanation == (
        "Frame #1 parse (src/main.c:25) of the crash on base lies inside hunk "
        "@@ -20,11 +20,11 @@. But no test crashes on base and not on patch "
        "(exploit_x crashes with another error on patch), so the link is undetermined.")
    assert new.link.explanation.endswith(
        "No test crashes on patch and not on base (exploit_x also crashes on base).")


def test_9_1_flaky_patch_result_gives_no_comparative_evidence(monkeypatch):
    _fake_changed(monkeypatch, set())
    r = results({"exploit_x": {"base-sanitized": crash(stack=(("parse", "src/main.c", 25),)),
                               "patch-sanitized": [crash(stack=(("parse", "src/main.c", 25),)),
                                                   normal(1), normal(1)]}})
    fixed = [f for f in link_findings(build_findings(r), r, [HUNK], "base", "patch")
             if f.category is Category.FIXED][0]
    assert fixed.link.level is LinkLevel.UNDETERMINED
    assert "(the patch result of exploit_x is flaky)" in fixed.link.explanation


def test_9_1_incomplete_fix_with_only_a_patch_only_crash(monkeypatch):
    """B has only a test that now fails with another error; P has only a test
    that does not crash on base: neither compares the same error on both."""
    _fake_changed(monkeypatch, set())
    other = crash("USE_AFTER_FREE", (("init", "src/other.c", 3),))
    r = results({"exploit_a": {"base-sanitized": crash(stack=(("parse", "src/main.c", 25),)),
                               "patch-sanitized": other},
                 "exploit_b": {"patch-sanitized": crash(stack=(("parse", "src/main.c", 25),))}})
    f = [f for f in link_findings(build_findings(r), r, [HUNK], "base", "patch")
         if f.category is Category.INCOMPLETE_FIX][0]
    assert f.link.level is LinkLevel.UNDETERMINED
    assert f.link.explanation.endswith(
        "But no test reaches this error on both versions or is blocked by the patch "
        "(exploit_a crashes with another error on patch; exploit_b crashes only on patch), "
        "so the link is undetermined.")
