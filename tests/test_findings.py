"""Unit tests for zaraban/findings.py (SPEC §8), built from fake results."""

from results_fakes import TOKEN_FRAMES, crash, normal, resource_limit, results, timeout

from zaraban.findings import (BugKey, bug_key, build_text, crash_findings, crash_frame,
                              describe, finding_test, functional_findings, matches_oracle,
                              profile_summary, release_only_findings, unsigned_crash_findings)
from zaraban.models import (BUILD_ORDER, Analysis, BuildName, Category, ErrorType, Frame,
                            OnPatch, Outcome, Profile, TestKind)

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


# -- crash findings (§8.2) ---------------------------------------------------

SIG = "STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main"


def _on_patch(f):
    return {t.test: t.on_patch for t in f.tests}


def test_8_9_correct_patch_is_one_fixed_finding():
    r = results({
        "valid_set": {},
        "exploit_primary": {"base-sanitized": crash(), "patch-sanitized": normal(1)},
        "exploit_secondary": {"base-sanitized": crash(), "patch-sanitized": normal(1)},
    })
    [f] = crash_findings(r)
    assert f.category is Category.FIXED
    assert f.signature == SIG and f.error_type is ErrorType.STACK_BUFFER_OVERFLOW
    assert _on_patch(f) == {"exploit_primary": OnPatch.BLOCKED,
                            "exploit_secondary": OnPatch.BLOCKED}
    assert f.evidence == ["runs/exploit_primary/", "runs/exploit_secondary/"]
    assert f.sanitized == {"base": "CRASH ASAN SIGABRT", "patch": "NORMAL exit 1"}
    assert f.notes == ("STACK_BUFFER_OVERFLOW @ handle_set_command (src/main.c) occurs on "
                       "base with exploit_primary, exploit_secondary and on patch with none of them.")


def test_8_9_incomplete_patch_is_one_incomplete_fix():
    r = results({
        "exploit_primary": {"base-sanitized": crash(), "patch-sanitized": normal(1)},
        "exploit_secondary": {"base-sanitized": crash(), "patch-sanitized": crash()},
    })
    [f] = crash_findings(r)
    assert f.category is Category.INCOMPLETE_FIX
    assert _on_patch(f) == {"exploit_primary": OnPatch.BLOCKED,
                            "exploit_secondary": OnPatch.REACHES}
    assert f.notes.endswith("still occurs on patch with exploit_secondary; "
                            "the patch blocks exploit_primary.")


def test_8_2_worst_case_decides():
    blocked = {"base-sanitized": crash(), "patch-sanitized": normal(1)}
    r = results({"exploit_a": blocked, "exploit_b": blocked,
                 "exploit_c": {"base-sanitized": crash(), "patch-sanitized": crash()}})
    [f] = crash_findings(r)
    assert f.category is Category.INCOMPLETE_FIX
    assert [t.test for t in f.tests] == ["exploit_a", "exploit_b", "exploit_c"]


def test_8_2_crash_only_on_patch_is_new_issue():
    r = results({
        "valid_echo": {"patch-sanitized": crash("HEAP_BUFFER_OVERFLOW", (("echo", "src/main.c", 40),))},
    })
    [f] = crash_findings(r)
    assert f.category is Category.NEW_ISSUE
    assert _on_patch(f) == {"valid_echo": OnPatch.REACHES}
    assert f.tests[0].kind is TestKind.VALID


def test_8_2_different_call_path_is_still_the_same_bug():
    """The patch blocks the input through caller_a; another input reaches the
    same crash through caller_b: one INCOMPLETE_FIX, not FIXED + NEW_ISSUE."""
    via_a = crash(stack=(("copy", "src/u.c", 5), ("caller_a", "src/main.c", 10)))
    via_b = crash(stack=(("copy", "src/u.c", 5), ("caller_b", "src/main.c", 20)))
    r = results({
        "exploit_primary": {"base-sanitized": via_a, "patch-sanitized": normal(1)},
        "exploit_bypass": {"patch-sanitized": via_b},
    })
    [f] = crash_findings(r)
    assert f.category is Category.INCOMPLETE_FIX
    assert f.signature == "STACK_BUFFER_OVERFLOW @ copy < caller_a"
    assert "Call paths differ: STACK_BUFFER_OVERFLOW @ copy < caller_a | " \
           "STACK_BUFFER_OVERFLOW @ copy < caller_b." in f.notes


def test_8_2_a_test_can_be_in_two_findings():
    k1 = crash("STACK_BUFFER_OVERFLOW", (("parse", "src/p.c", 3),))
    k2 = crash("USE_AFTER_FREE", (("cleanup", "src/p.c", 50),))
    r = results({"exploit_primary": {"base-sanitized": k1, "patch-sanitized": k2}})
    first, second = crash_findings(r)
    assert first.category is Category.FIXED
    assert _on_patch(first) == {"exploit_primary": OnPatch.OTHER_ERROR}
    assert second.category is Category.NEW_ISSUE
    assert second.error_type is ErrorType.USE_AFTER_FREE
    assert _on_patch(second) == {"exploit_primary": OnPatch.REACHES}


def test_8_2_same_signal_and_detection_is_not_enough():
    """Comparison is by bug key, not by "both crashed" (§8.2)."""
    r = results({"exploit_primary": {
        "base-sanitized": crash(stack=(("parse", "src/p.c", 3),)),
        "patch-sanitized": crash(stack=(("render", "src/r.c", 9),)),
    }})
    cats = [f.category for f in crash_findings(r)]
    assert cats == [Category.FIXED, Category.NEW_ISSUE]


def test_8_2_findings_in_first_seen_run_order():
    r = results({
        "valid_a": {"patch-sanitized": crash("NULL_DEREF", (("a", "src/a.c", 1),))},
        "exploit_primary": {"base-sanitized": crash()},
    })
    assert [f.category for f in crash_findings(r)] == [Category.NEW_ISSUE, Category.FIXED]
    # an explicit run order wins over the order of the dict
    r_order = crash_findings(r, ["exploit_primary", "valid_a"])
    assert [f.category for f in r_order] == [Category.FIXED, Category.NEW_ISSUE]


def test_8_2_release_crashes_do_not_make_crash_findings():
    r = results({"exploit_primary": {"base-release": crash(detection="STACK_CANARY", stack=())}})
    assert crash_findings(r) == []


def test_8_2_release_results_are_listed_next_to_sanitized():
    r = results({"exploit_primary": {
        "base-release": crash(detection="STACK_CANARY", stack=()),
        "base-sanitized": crash(),
        "patch-release": normal(1), "patch-sanitized": normal(1),
    }})
    [f] = crash_findings(r)
    assert f.release == {"base": "CRASH STACK_CANARY SIGABRT", "patch": "NORMAL exit 1"}
    assert f.tests[0].results[BR].detection.value == "STACK_CANARY"


def test_8_3_crash_without_signature_is_not_grouped():
    r = results({"exploit_primary": {"base-sanitized": crash(stack=())}})
    assert crash_findings(r) == []


def test_8_5_flaky_crash_does_not_make_a_crash_finding():
    r = results({"exploit_primary": {"base-sanitized": [crash(), crash(), normal(1)]}})
    assert crash_findings(r) == []


def test_8_5_flaky_patch_result_is_not_counted_as_blocked():
    r = results({"exploit_primary": {"base-sanitized": crash(),
                                      "patch-sanitized": [crash(), normal(1), normal(1)]}})
    [f] = crash_findings(r)
    assert f.category is Category.FIXED   # the stable evidence only (§8.2, §8.5)
    assert _on_patch(f) == {"exploit_primary": None}
    assert "exploit_primary is flaky" in f.notes


# -- crashes without a signature (§8.3) --------------------------------------

UNSIGNED_SEGV = crash("SEGV", stack=(), detection="SIGNAL", signal="SIGSEGV")


def _one(findings):
    [f] = findings
    return f


def test_8_3_unsigned_base_crash_gone_on_patch_is_fixed():
    r = results({"exploit_primary": {"base-sanitized": UNSIGNED_SEGV,
                                      "patch-sanitized": normal(1)}})
    f = _one(unsigned_crash_findings(r))
    assert f.category is Category.FIXED
    assert f.signature is None and f.error_type is ErrorType.SEGV
    assert _on_patch(f) == {"exploit_primary": OnPatch.BLOCKED}
    assert f.evidence == ["runs/exploit_primary/"]


def test_8_3_unsigned_patch_crash_with_known_type_is_new_issue():
    r = results({"valid_echo": {"patch-sanitized": UNSIGNED_SEGV}})
    f = _one(unsigned_crash_findings(r))
    assert f.category is Category.NEW_ISSUE
    assert _on_patch(f) == {"valid_echo": OnPatch.REACHES}


def test_8_3_unsigned_patch_abort_or_unknown_is_inconclusive():
    for etype in ("ABORT", "UNKNOWN"):
        r = results({"valid_echo": {"patch-sanitized": crash(etype, stack=(), detection="SIGNAL")}})
        f = _one(unsigned_crash_findings(r))
        assert f.category is Category.INCONCLUSIVE
        assert "unclassified stop" in f.notes


def test_8_3_unsigned_base_crash_and_any_patch_crash_is_inconclusive():
    for patch_run in (UNSIGNED_SEGV, crash()):
        r = results({"exploit_primary": {"base-sanitized": UNSIGNED_SEGV,
                                          "patch-sanitized": patch_run}})
        f = _one(unsigned_crash_findings(r))
        assert f.category is Category.INCONCLUSIVE
        assert "cannot be told whether it is the same error" in f.notes


def test_8_3_signed_base_crash_and_unsigned_patch_crash_is_inconclusive():
    """Not in the table of §8.3: without this the §8.2 finding would say FIXED
    while the patch still crashes."""
    r = results({"exploit_primary": {"base-sanitized": crash(),
                                      "patch-sanitized": UNSIGNED_SEGV}})
    [fixed] = crash_findings(r)
    assert _on_patch(fixed) == {"exploit_primary": OnPatch.OTHER_ERROR}
    f = _one(unsigned_crash_findings(r))
    assert f.category is Category.INCONCLUSIVE
    assert f.error_type is ErrorType.SEGV
    assert f.notes.startswith("Base crashes with " + SIG)


def test_8_3_signed_crashes_are_left_to_8_2():
    r = results({"exploit_primary": {"base-sanitized": crash(), "patch-sanitized": crash()},
                 "valid_set": {}})
    assert unsigned_crash_findings(r) == []


def test_8_3_flaky_unsigned_crash_is_left_to_8_5():
    r = results({"exploit_primary": {"base-sanitized": [UNSIGNED_SEGV, normal(1)]}})
    assert unsigned_crash_findings(r) == []


def test_8_3_release_only_crash_is_inconclusive_side_by_side():
    r = results({"valid_set": {"patch-release": crash("BUFFER_OVERFLOW", stack=(),
                                                     detection="FORTIFY")}})
    f = _one(release_only_findings(r))
    assert f.category is Category.INCONCLUSIVE
    assert f.error_type is ErrorType.BUFFER_OVERFLOW
    assert f.release == {"base": "NORMAL exit 0", "patch": "CRASH FORTIFY SIGABRT"}
    assert f.sanitized == {"base": "NORMAL exit 0", "patch": "NORMAL exit 0"}
    assert f.notes == ("On patch the release build crashes (CRASH FORTIFY SIGABRT) but the "
                       "sanitized build does not (NORMAL exit 0). Without a sanitizer report "
                       "the crash cannot be classified.")


def test_8_3_release_only_on_both_versions_is_one_finding():
    canary = crash("STACK_BUFFER_OVERFLOW", stack=(), detection="STACK_CANARY")
    r = results({"exploit_primary": {"base-release": canary, "patch-release": canary}})
    f = _one(release_only_findings(r))
    assert "on base the release build crashes" in f.notes.lower()
    assert "on patch the release build crashes" in f.notes


def test_8_3_release_and_sanitized_both_crashing_is_not_release_only():
    r = results({"exploit_primary": {
        "base-release": crash(detection="STACK_CANARY", stack=()),
        "base-sanitized": crash()}})
    assert release_only_findings(r) == []


def test_8_3_flaky_release_crash_is_left_to_8_5():
    r = results({"valid_set": {"patch-release": [crash(stack=()), normal(0)]}})
    assert release_only_findings(r) == []


# -- functional findings (§8.4) ----------------------------------------------

OK = normal(0, oracle=True)
REJECTED = normal(1, oracle=False, reasons=["exit code 1, expected 0"])


def _all(spec):
    return {b.value: spec for b in BUILD_ORDER}


def test_5_4_matches_oracle():
    r = results({"t": {"base-release": OK, "base-sanitized": normal(1),   # no oracle
                       "patch-release": REJECTED, "patch-sanitized": timeout()}})["t"]
    assert matches_oracle(r[BR]) and matches_oracle(r[BS])
    assert not matches_oracle(r[PR]) and not matches_oracle(r[PS])


def test_8_9_regression_patch_rejects_valid_set():
    r = results({"valid_set": {"base-release": OK, "base-sanitized": OK,
                               "patch-release": REJECTED, "patch-sanitized": REJECTED}})
    f = _one(functional_findings(r))
    assert f.category is Category.FUNCTIONAL_REGRESSION
    assert f.signature is None and f.error_type is None
    assert f.tests[0].on_patch is None
    assert f.notes == ("valid_set matches its oracle on base but not on patch "
                       "(patch-release: exit code 1, expected 0; "
                       "patch-sanitized: exit code 1, expected 0).")


def test_8_4_one_patch_build_is_enough():
    r = results({"valid_set": {"base-release": OK, "base-sanitized": OK,
                               "patch-release": OK, "patch-sanitized": REJECTED}})
    assert _one(functional_findings(r)).category is Category.FUNCTIONAL_REGRESSION


def test_8_4_boundary_and_invalid_are_judged_like_valid():
    r = results({"boundary_max": {**_all(OK), "patch-release": REJECTED},
                 "invalid_bad": {**_all(OK), "patch-sanitized": REJECTED}},
                kinds={"boundary_max": "boundary", "invalid_bad": "invalid"})
    assert [f.category for f in functional_findings(r)] == [Category.FUNCTIONAL_REGRESSION] * 2


def test_8_4_hang_on_patch_is_a_functional_regression_not_a_crash():
    r = results({"valid_set": {**_all(OK), "patch-release": timeout()}})
    f = _one(functional_findings(r))
    assert f.category is Category.FUNCTIONAL_REGRESSION
    assert f.tests[0].results[PR].outcome is Outcome.TIMEOUT
    assert "patch-release: TIMEOUT" in f.notes


def test_8_4_resource_limit_counts_as_mismatch():
    r = results({"valid_set": {**_all(OK), "patch-sanitized": resource_limit("memory")}})
    assert _one(functional_findings(r)).category is Category.FUNCTIONAL_REGRESSION


def test_8_4_mismatch_on_base_is_inconclusive():
    for patch in (OK, REJECTED):
        r = results({"valid_set": {**_all(patch), "base-release": REJECTED}})
        f = _one(functional_findings(r))
        assert f.category is Category.INCONCLUSIVE
        assert "the test or its oracle is wrong" in f.notes


def test_8_4_matching_everywhere_is_not_a_finding():
    r = results({"valid_set": _all(OK), "valid_echo": {}})  # valid_echo has no oracle
    assert functional_findings(r) == []


def test_8_4_crash_on_valid_input_is_left_to_crash_findings():
    r = results({"valid_set": {**_all(OK), "patch-sanitized": crash()}})
    assert functional_findings(r) == []
    assert crash_findings(r)[0].category is Category.NEW_ISSUE


def test_8_4_security_test_rejected_as_expected_is_not_a_finding():
    reject = normal(1, oracle=True)
    r = results({"exploit_primary": {"base-release": crash(stack=()), "base-sanitized": crash(),
                                      "patch-release": reject, "patch-sanitized": reject}})
    assert functional_findings(r) == []


def test_8_4_security_test_no_crash_but_wrong_behavior_is_inconclusive():
    wrong = normal(0, oracle=False, reasons=["exit code 0, expected 1"])
    r = results({"exploit_primary": {"base-sanitized": crash(),
                                      "patch-release": wrong, "patch-sanitized": wrong}})
    f = _one(functional_findings(r))
    assert f.category is Category.INCONCLUSIVE
    assert "does not crash on patch but does not behave as expected" in f.notes


def test_8_4_security_base_is_not_judged_by_the_oracle():
    r = results({"exploit_primary": {"base-release": normal(0, oracle=False),
                                      "base-sanitized": crash(),
                                      "patch-release": normal(1, oracle=True),
                                      "patch-sanitized": normal(1, oracle=True)}})
    assert functional_findings(r) == []


def test_8_4_timeout_on_patch_for_security_or_regression_is_inconclusive():
    r = results({"exploit_primary": {"base-sanitized": crash(), "patch-sanitized": timeout()},
                 "reg-exploit-1a2b": {"base-sanitized": crash(), "patch-release": resource_limit()}})
    found = functional_findings(r)
    assert [f.category for f in found] == [Category.INCONCLUSIVE] * 2
    assert all("not every stop is an exploitable vulnerability" in f.notes for f in found)
    assert found[1].tests[0].kind is TestKind.REGRESSION


def test_8_4_flaky_results_are_left_to_8_5():
    r = results({"valid_set": {**_all(OK), "patch-release": [OK, REJECTED]}})
    assert functional_findings(r) == []
