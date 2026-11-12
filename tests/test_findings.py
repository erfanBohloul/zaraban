"""Unit tests for zaraban/findings.py (SPEC §8), built from fake results."""

from results_fakes import TOKEN_FRAMES, crash, normal, resource_limit, results, timeout

from zaraban.findings import (BugKey, bug_key, build_text, crash_frame, describe,
                              finding_test, profile_summary)
from zaraban.models import (BUILD_ORDER, Analysis, BuildName, ErrorType, Frame, OnPatch,
                            Outcome, Profile, TestKind)

BS = BuildName.BASE_SANITIZED
PS = BuildName.PATCH_SANITIZED
BR = BuildName.BASE_RELEASE
PR = BuildName.PATCH_RELEASE


def _analysis(spec):
    r = results({"t": {"base-sanitized": spec}})
    return r["t"][BS].first.analysis


# -- bug key (§1, §8.2) ------------------------------------------------------

def test_1_bug_key_is_error_type_and_crashing_function_and_file():
    key = bug_key(_analysis(crash()))
    assert key == BugKey(ErrorType.STACK_BUFFER_OVERFLOW, "handle_set_command", "src/main.c")
    assert str(key) == "STACK_BUFFER_OVERFLOW @ handle_set_command (src/main.c)"


def test_1_bug_key_skips_runtime_frames():
    # frame #0 is __interceptor_strcpy, a runtime frame (§7.4)
    a = _analysis(crash())
    assert a.frames[0].runtime
    assert crash_frame(a).function == "handle_set_command"


def test_8_2_different_callers_same_bug_key():
    via_a = crash(stack=(("copy", "src/u.c", 5), ("caller_a", "src/main.c", 10)))
    via_b = crash(stack=(("copy", "src/u.c", 5), ("caller_b", "src/main.c", 20)))
    a, b = _analysis(via_a), _analysis(via_b)
    assert a.signature != b.signature
    assert bug_key(a) == bug_key(b)


def test_8_2_same_function_other_error_type_is_another_bug():
    a = _analysis(crash("STACK_BUFFER_OVERFLOW"))
    b = _analysis(crash("USE_AFTER_FREE"))
    assert bug_key(a) != bug_key(b)


def test_8_2_same_function_name_in_another_file_is_another_bug():
    a = _analysis(crash(stack=(("parse", "src/a.c", 1),)))
    b = _analysis(crash(stack=(("parse", "src/b.c", 1),)))
    assert bug_key(a) != bug_key(b)


def test_8_3_crash_without_signature_has_no_bug_key():
    a = _analysis(crash(stack=()))
    assert a.signature is None and bug_key(a) is None


def test_8_2_unnamed_frames_are_skipped_like_the_signature():
    a = Analysis(Outcome.CRASH, error_type=ErrorType.SEGV, signature="SEGV @ f", frames=[
        Frame(0, None, None, None, False),
        Frame(1, "f", "src/x.c", 3, False),
    ])
    assert bug_key(a) == BugKey(ErrorType.SEGV, "f", "src/x.c")


def test_8_2_frame_without_file_still_has_a_key():
    a = _analysis(crash(stack=(("f", None, None),)))
    assert bug_key(a) == BugKey(ErrorType.STACK_BUFFER_OVERFLOW, "f", None)
    assert str(bug_key(a)) == "STACK_BUFFER_OVERFLOW @ f"


def test_8_2_non_crash_has_no_bug_key():
    assert bug_key(_analysis(normal(1))) is None
    assert bug_key(_analysis(timeout())) is None


# -- what one test did on each build (§8.8, §12.4) ---------------------------

def test_8_8_finding_test_lists_all_four_builds_in_order():
    r = results({"exploit_primary": {
        "base-release": crash(detection="STACK_CANARY", stack=()),
        "base-sanitized": crash(),
        "patch-release": normal(1),
        "patch-sanitized": normal(1),
    }})
    ft = finding_test(r["exploit_primary"], OnPatch.BLOCKED)
    assert ft.test == "exploit_primary" and ft.kind is TestKind.SECURITY
    assert list(ft.results) == list(BUILD_ORDER)
    assert ft.on_patch is OnPatch.BLOCKED
    bs = ft.results[BS]
    assert (bs.outcome, bs.detection.value, bs.signal) == (Outcome.CRASH, "ASAN", "SIGABRT")
    assert bs.signature == "STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main"
    assert ft.results[BR].detection.value == "STACK_CANARY"
    assert (ft.results[PS].outcome, ft.results[PS].exit_code) == (Outcome.NORMAL, 1)


def test_8_8_finding_test_keeps_oracle_and_flaky():
    r = results({"valid_set": {"patch-release": normal(1, oracle=False),
                               "patch-sanitized": [normal(0, oracle=True), normal(1, oracle=False)]}})
    ft = finding_test(r["valid_set"])
    assert ft.on_patch is None
    assert ft.results[PR].oracle_passed is False
    assert ft.results[PS].flaky is True
    assert ft.results[BR].flaky is False


def test_8_8_describe_each_outcome():
    r = results({"t": {
        "base-release": crash(detection="FORTIFY", stack=()),
        "base-sanitized": crash(signal=None, exit_code=1),   # ASan exit without abort
        "patch-release": timeout(),
        "patch-sanitized": resource_limit("memory"),
    }, "u": {"base-release": normal(1)}})
    t = r["t"]
    assert describe(t[BR]) == "CRASH FORTIFY SIGABRT"
    assert describe(t[BS]) == "CRASH ASAN exit 1"
    assert describe(t[PR]) == "TIMEOUT"
    assert describe(t[PS]) == "RESOURCE_LIMIT memory"
    assert describe(r["u"][BR]) == "NORMAL exit 1"


def test_8_8_describe_marks_flaky():
    r = results({"t": {"base-sanitized": [crash(), normal(0)]}})
    assert describe(r["t"][BS]) == "CRASH ASAN SIGABRT (flaky)"


def test_8_8_same_result_for_every_test_is_one_text():
    r = results({"exploit_primary": {"base-sanitized": crash()},
                 "exploit_secondary": {"base-sanitized": crash()}})
    assert build_text([r["exploit_primary"][BS], r["exploit_secondary"][BS]]) == "CRASH ASAN SIGABRT"


def test_8_8_different_results_are_listed_worst_first_with_tests():
    r = results({"exploit_primary": {"patch-sanitized": normal(1)},
                 "exploit_secondary": {"patch-sanitized": crash()}})
    text = build_text([r["exploit_primary"][PS], r["exploit_secondary"][PS]])
    assert text == "CRASH ASAN SIGABRT (exploit_secondary); NORMAL exit 1 (exploit_primary)"


def test_8_2_release_and_sanitized_summaries_are_separate():
    """§8.2: release results are reported next to the sanitized ones, never merged."""
    r = results({
        "exploit_primary": {"base-release": crash(detection="STACK_CANARY", stack=()),
                            "base-sanitized": crash(),
                            "patch-release": normal(1), "patch-sanitized": normal(1)},
        "exploit_secondary": {"base-release": crash(detection="STACK_CANARY", stack=()),
                              "base-sanitized": crash(),
                              "patch-release": crash(detection="STACK_CANARY", stack=()),
                              "patch-sanitized": crash()},
    })
    per_test = [r["exploit_primary"], r["exploit_secondary"]]
    assert profile_summary(per_test, Profile.RELEASE) == {
        "base": "CRASH STACK_CANARY SIGABRT",
        "patch": "CRASH STACK_CANARY SIGABRT (exploit_secondary); NORMAL exit 1 (exploit_primary)",
    }
    assert profile_summary(per_test, Profile.SANITIZED) == {
        "base": "CRASH ASAN SIGABRT",
        "patch": "CRASH ASAN SIGABRT (exploit_secondary); NORMAL exit 1 (exploit_primary)",
    }


def test_fakes_token_parser_signature():
    """The fake helper builds signatures the way §7.4 defines them."""
    a = _analysis(crash())
    assert a.signature == "STACK_BUFFER_OVERFLOW @ " + " < ".join(f for f, _, _ in TOKEN_FRAMES)
