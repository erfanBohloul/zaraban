"""Unit tests for the completeness check (SPEC §8.7, Task 2.4)."""

import copy

import pytest

from zaraban.completeness import check, crash_counts, unreferenced
from zaraban.findings import build_findings
from zaraban.models import (
    BUILD_ORDER,
    Analysis,
    BuildName,
    CombinedResult,
    Detection,
    ErrorCode,
    ErrorType,
    Frame,
    InputInfo,
    InputMethod,
    OracleResult,
    Outcome,
    RunRecord,
    StreamInfo,
    TestKind,
    ZarabanError,
)

BR, BS, PR, PS = BUILD_ORDER


def _run(test, kind, build, state, repeat=1):
    """state: "ok", "fail" (oracle mismatch), "timeout", "crash", "crash:<func>",
    "unsigned" (crash without frames); "crash@<file>" puts the frames in <file>."""
    crashed = state.startswith("crash") or state == "unsigned"
    state, _, file = state.partition("@")
    file = file or "src/main.c"
    func = state.split(":", 1)[1] if ":" in state else "handle_set_command"
    frames = [Frame(0, func, file, 37, False), Frame(1, "main", file, 90, False)] \
        if crashed and state != "unsigned" else []
    outcome = Outcome.CRASH if crashed else Outcome.TIMEOUT if state == "timeout" else Outcome.NORMAL
    a = Analysis(outcome,
                 detection=Detection.ASAN if crashed else None,
                 error_type=ErrorType.STACK_BUFFER_OVERFLOW if crashed else None,
                 frames=frames,
                 signature=f"STACK_BUFFER_OVERFLOW @ {func} < main" if frames else None)
    return RunRecord(
        test=test, kind=kind, build=build, repeat=repeat, cmd=[], env={}, cwd="",
        input=InputInfo(InputMethod.FILE, "input.txt", 1, "0" * 64),
        exit_code=None if crashed else (1 if state == "fail" else 0),
        signal="SIGABRT" if crashed else None, timed_out=state == "timeout", limit_hit=None,
        duration_s=0.0, stdout=StreamInfo("1.stdout", 0, "a" * 64),
        stderr=StreamInfo("1.stderr", 0, "b" * 64), analysis=a,
        oracle=OracleResult(True, state == "ok") if outcome is Outcome.NORMAL
        else OracleResult(True, False))


def _combined(test, kind, build, state):
    if state == "flaky":
        runs = [_run(test, kind, build, "crash", 1), _run(test, kind, build, "ok", 2)]
        return CombinedResult(test, kind, build, runs, flaky=True)
    return CombinedResult(test, kind, build, [_run(test, kind, build, state, r) for r in (1, 2)],
                          flaky=False)


def results_of(spec):
    """{test: (kind, (br, bs, pr, ps))} -> Results."""
    return {t: {b: _combined(t, kind, b, s) for b, s in zip(BUILD_ORDER, states)}
            for t, (kind, states) in spec.items()}


V, S, R = TestKind.VALID, TestKind.SECURITY, TestKind.REGRESSION
CORRECT = {
    "valid_ping": (V, ("ok", "ok", "ok", "ok")),
    "valid_set": (V, ("ok", "ok", "ok", "ok")),
    "exploit_primary": (S, ("crash", "crash", "ok", "ok")),
    "exploit_secondary": (S, ("crash", "crash", "ok", "ok")),
}


def _passes(spec):
    results = results_of(spec)
    findings = build_findings(results, list(spec))
    check(results, findings)  # must not raise
    return results, findings


def _fails(results, findings):
    with pytest.raises(ZarabanError) as e:
        check(results, findings)
    assert e.value.code is ErrorCode.TOOL_INTERNAL
    return e.value.details["problems"]


# -- real runs pass ----------------------------------------------------------

@pytest.mark.parametrize("change", [
    {},                                                                    # correct patch
    {"exploit_secondary": (S, ("crash", "crash", "crash", "crash"))},      # incomplete fix
    {"valid_set": (V, ("ok", "ok", "fail", "fail"))},                      # functional regression
    {"valid_ping": (V, ("flaky", "ok", "ok", "ok"))},                      # flaky
    {"valid_set": (V, ("ok", "ok", "crash:parse_value", "crash:parse_value"))},  # new issue
    {"valid_set": (V, ("ok", "ok", "timeout", "timeout"))},                # timeout on patch
    {"valid_set": (V, ("fail", "fail", "fail", "fail"))},                  # wrong oracle
    {"exploit_primary": (S, ("crash", "unsigned", "ok", "ok"))},           # crash without signature
    {"exploit_primary": (S, ("crash", "ok", "ok", "ok"))},                 # release-only crash
    {"exploit_primary": (S, ("crash", "crash", "crash:other", "crash:other"))},  # other error on patch
])
def test_8_7_every_finding_rule_passes_the_check(change):
    _passes({**CORRECT, **change})


def test_8_7_same_signature_text_with_two_bug_keys_is_two_findings_each_counted_once():
    # Same functions but another file on patch: two bug keys with the same
    # signature text, so FIXED (base key) and NEW_ISSUE (patch key). Each
    # crash is in exactly the finding of its own key (seen on token_parser).
    results, findings = _passes({**CORRECT, "exploit_secondary": (
        S, ("crash", "crash", "crash@patch/src/main.c", "crash@patch/src/main.c"))})
    assert sorted(f.category.value for f in findings) == ["FIXED", "NEW_ISSUE"]
    assert findings[0].signature == findings[1].signature


def test_8_7_security_test_not_reproduced_on_base_is_a_status_condition_not_a_loss():
    # Base does not crash: no finding, condition base_not_reproduced (exit 40).
    _passes({**CORRECT, "exploit_primary": (S, ("ok", "ok", "ok", "ok")),
             "exploit_secondary": (S, ("timeout", "timeout", "ok", "ok"))})


def test_8_7_regression_test_clean_or_stopped_on_base_is_a_warning_not_a_loss():
    _passes({**CORRECT,
             "reg-a": (R, ("ok", "ok", "ok", "ok")),
             "reg-b": (R, ("timeout", "timeout", "ok", "ok")),
             "reg-c": (R, ("crash", "crash", "ok", "ok"))})


def test_8_7_no_results_is_nothing_to_check():
    check(None, [])
    check({}, [])


# -- lost results fail -------------------------------------------------------

def test_8_7_dropped_finding_is_tool_internal():
    results, findings = _passes({**CORRECT, "valid_set": (V, ("ok", "ok", "fail", "fail"))})
    kept = [f for f in findings if f.category.value != "FUNCTIONAL_REGRESSION"]
    problems = _fails(results, kept)
    assert problems == ["valid_set on patch-release: an oracle mismatch is in no finding",
                        "valid_set on patch-sanitized: an oracle mismatch is in no finding"]


def test_8_7_dropped_crash_finding_fails_both_rules():
    results, findings = _passes(CORRECT)
    problems = _fails(results, [])
    assert "exploit_primary on base-release: CRASH is in no finding" in problems
    assert any("exploit_primary on base-sanitized: crash" in p and "no crash finding" in p
               for p in problems)


def test_8_7_lost_timeout_and_flaky_results_are_named():
    results, findings = _passes({**CORRECT, "valid_ping": (V, ("flaky", "ok", "ok", "ok")),
                                 "valid_set": (V, ("timeout", "timeout", "timeout", "timeout"))})
    problems = unreferenced(results, [])
    assert "valid_ping on base-release: a flaky result is in no finding" in problems
    assert "valid_set on base-sanitized: TIMEOUT is in no finding" in problems


def test_8_7_crash_in_two_crash_findings_fails():
    results, findings = _passes(CORRECT)
    [fixed] = findings
    twin = copy.deepcopy(fixed)
    twin.id = "F-002"
    problems = _fails(results, [fixed, twin])
    assert any("exploit_primary on base-sanitized" in p and "2 crash findings (F-001, F-002)" in p
               for p in problems)


def test_8_7_crash_finding_whose_category_does_not_fit_its_tests_fails():
    # Base crashes, patch does not: that is FIXED, never NEW_ISSUE.
    from zaraban.models import Category
    results, findings = _passes(CORRECT)
    findings[0].category = Category.NEW_ISSUE
    problems = crash_counts(results, findings)
    assert any(p.startswith("F-001: NEW_ISSUE with signature") for p in problems)
    assert any("exploit_primary on base-sanitized" in p and "no crash finding" in p
               for p in problems)


def test_8_7_all_problems_are_reported_together():
    results, _ = _passes({**CORRECT, "valid_set": (V, ("ok", "ok", "fail", "fail"))})
    problems = _fails(results, [])
    tests = {p.split(" ")[0] for p in problems}
    assert tests == {"exploit_primary", "exploit_secondary", "valid_set"}
