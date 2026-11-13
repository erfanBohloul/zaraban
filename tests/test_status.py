"""Unit tests for the status/exit-code logic (SPEC §13).

These build Finding and Checks objects by hand (the frozen models.py types),
so Member D can test the verdict logic without Member B or C finished.
"""

from zaraban.models import (
    Category,
    Checks,
    ConditionName,
    ErrorCode,
    ExitCode,
    Finding,
    FindingTest,
    Issue,
    OnPatch,
    TestKind,
)
from zaraban.status import compute_status


# -- fixtures ----------------------------------------------------------------

def all_ok() -> Checks:
    """Every required check passed."""
    return Checks(*([True] * 7))


def finding(fid: str, category: Category, *test_names: str) -> Finding:
    tests = [FindingTest(test=n, kind=TestKind.SECURITY, results={}) for n in test_names]
    return Finding(id=fid, category=category, tests=list(tests))


def fixed() -> Finding:
    return finding("F-009", Category.FIXED, "exploit_primary")


# -- PASS needs a FIXED finding (§13.3) --------------------------------------

def test_13_3_fixed_finding_and_all_checks_is_pass():
    s = compute_status([fixed()], all_ok())
    assert s.exit_code is ExitCode.PASS
    assert s.exit_name == "PASS"
    assert [c.name for c in s.conditions] == [ConditionName.PASS]
    assert s.conditions[0].findings == ["F-009"]


def test_13_3_no_conditions_and_no_fixed_finding_is_inconclusive():
    s = compute_status([], all_ok())
    assert s.exit_code == 40
    assert s.exit_name == "INCONCLUSIVE"
    assert "no FIXED finding" in s.conditions[0].reason


# -- one finding each (§13.3) ------------------------------------------------

def test_13_3_incomplete_fix_is_vuln_remains_10():
    s = compute_status([finding("F-001", Category.INCOMPLETE_FIX, "exploit_primary")], all_ok())
    assert s.exit_code == 10
    assert s.exit_name == "VULN_REMAINS"
    cond = s.conditions[0]
    assert cond.findings == ["F-001"]
    assert cond.tests == ["exploit_primary"]


def test_13_3_vuln_remains_names_the_tests_that_still_reach_the_error():
    f = Finding(id="F-001", category=Category.INCOMPLETE_FIX, tests=[
        FindingTest("exploit_primary", TestKind.SECURITY, {}, on_patch=OnPatch.BLOCKED),
        FindingTest("exploit_secondary", TestKind.SECURITY, {}, on_patch=OnPatch.REACHES),
    ])
    s = compute_status([f], all_ok())
    assert s.conditions[0].tests == ["exploit_secondary"]
    assert "exploit_secondary" in s.conditions[0].reason


def test_13_3_new_issue_shares_code_10_but_keeps_its_name():
    s = compute_status([finding("F-002", Category.NEW_ISSUE, "valid_ping")], all_ok())
    assert s.exit_code == 10
    assert s.exit_name == "NEW_ISSUE"


def test_13_3_functional_regression_is_20():
    s = compute_status([finding("F-003", Category.FUNCTIONAL_REGRESSION, "valid_set")], all_ok())
    assert s.exit_code == 20
    assert s.exit_name == "FUNC_REGRESSION"


def test_13_3_inconclusive_finding_is_40():
    s = compute_status([finding("F-004", Category.INCONCLUSIVE, "boundary_empty")], all_ok())
    assert s.exit_code == 40
    assert s.exit_name == "INCONCLUSIVE"


def test_13_3_an_error_is_build_or_config_error_30():
    err = Issue(ErrorCode.BUILD_FAILED.value, "patch-sanitized did not build")
    s = compute_status([fixed()], all_ok(), errors=[err])
    assert s.exit_code == 30
    assert s.exit_name == "BUILD_OR_CONFIG_ERROR"
    assert "BUILD_FAILED" in s.conditions[0].reason


# -- priority when several conditions hold (§13.1) ---------------------------

def test_13_1_10_beats_20():
    s = compute_status([
        finding("F-001", Category.INCOMPLETE_FIX, "exploit_primary"),
        finding("F-002", Category.FUNCTIONAL_REGRESSION, "valid_set"),
    ], all_ok())
    assert s.exit_code == 10
    names = [c.name for c in s.conditions]
    assert names[0] is ConditionName.VULN_REMAINS
    assert ConditionName.FUNC_REGRESSION in names  # kept, though it did not decide


def test_13_1_20_beats_40():
    s = compute_status([
        finding("F-001", Category.INCONCLUSIVE, "boundary_empty"),
        finding("F-002", Category.FUNCTIONAL_REGRESSION, "valid_set"),
    ], all_ok())
    assert s.exit_code == 20
    assert [c.code for c in s.conditions] == [20, 40]


def test_13_1_30_beats_10():
    checks = all_ok()
    checks.builds_ok = False
    s = compute_status([finding("F-001", Category.INCOMPLETE_FIX, "exploit_primary")], checks)
    assert s.exit_code == 30
    assert s.exit_name == "BUILD_OR_CONFIG_ERROR"


def test_13_1_40_beats_pass():
    s = compute_status([fixed(), finding("F-002", Category.INCONCLUSIVE, "boundary_empty")],
                       all_ok())
    assert s.exit_code == 40
    assert ConditionName.PASS not in [c.name for c in s.conditions]


def test_13_4_new_issue_and_vuln_remains_tie_breaks_to_vuln_remains():
    s = compute_status([
        finding("F-002", Category.NEW_ISSUE, "v"),
        finding("F-001", Category.INCOMPLETE_FIX, "s"),
    ], all_ok())
    assert s.exit_code == 10
    assert s.exit_name == "VULN_REMAINS"
    assert s.reason == ("VULN_REMAINS (F-001) has the highest priority among: "
                        "VULN_REMAINS, NEW_ISSUE.")


# -- required checks (§13.2) -------------------------------------------------

def test_13_2_runs_not_completed_is_30_not_40():
    checks = all_ok()
    checks.all_runs_completed = False
    s = compute_status([fixed()], checks)
    assert s.exit_code == 30


def test_13_2_hardening_not_checked_is_30_not_40():
    checks = all_ok()
    checks.hardening_checked = False
    s = compute_status([fixed()], checks)
    assert s.exit_code == 30


def test_13_2_base_not_reproduced_is_inconclusive_naming_the_tests():
    checks = all_ok()
    checks.base_reproduced = False
    s = compute_status([], checks, base_not_reproduced=["exploit_primary"])
    assert s.exit_code == 40
    assert s.exit_name == "INCONCLUSIVE"
    assert s.conditions[0].tests == ["exploit_primary"]
    assert "exploit_primary" in s.conditions[0].reason


def test_13_2_failed_check_merges_with_inconclusive_finding():
    checks = all_ok()
    checks.results_stable = False
    s = compute_status([finding("F-001", Category.INCONCLUSIVE, "boundary_empty")], checks)
    inconclusive = [c for c in s.conditions if c.name is ConditionName.INCONCLUSIVE]
    assert len(inconclusive) == 1
    assert inconclusive[0].findings == ["F-001"]
    assert "flaky" in inconclusive[0].reason


def test_13_2_a_failed_check_never_passes():
    for attr in ("builds_ok", "profiles_verified", "all_runs_completed", "base_reproduced",
                 "results_stable", "bundles_replayed", "hardening_checked"):
        checks = all_ok()
        setattr(checks, attr, False)
        assert compute_status([fixed()], checks).exit_code != 0, attr


def test_13_2_all_checks_failed_records_both_conditions_30_wins():
    s = compute_status([], Checks())  # every check False
    assert s.exit_code == 30
    names = {c.name for c in s.conditions}
    assert names == {ConditionName.BUILD_OR_CONFIG_ERROR, ConditionName.INCONCLUSIVE}


# -- shape of the result -----------------------------------------------------

def test_13_status_carries_the_checks_object():
    checks = all_ok()
    s = compute_status([fixed()], checks)
    assert s.checks is checks
    assert s.checks.all_ok
