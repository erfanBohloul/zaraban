"""Unit tests for the status/exit-code logic (SPEC §13).

These build Finding and Checks objects by hand (the frozen models.py types),
so Member D can test the verdict logic without Member B or C finished.
"""

from zaraban.models import (
    Category,
    Checks,
    ConditionName,
    ExitCode,
    Finding,
    FindingTest,
    TestKind,
)
from zaraban.status import compute_status


# -- fixtures ----------------------------------------------------------------

def all_ok() -> Checks:
    """Every required check passed (the only state that can PASS)."""
    return Checks(*([True] * 7))


def finding(fid: str, category: Category, *test_names: str) -> Finding:
    tests = [FindingTest(test=n, kind=TestKind.SECURITY, results={}) for n in test_names]
    return Finding(id=fid, category=category, tests=list(tests))


# -- clean PASS (§13.2) ------------------------------------------------------

def test_13_2_pass_needs_all_checks_and_no_findings():
    s = compute_status([], all_ok())
    assert s.exit_code is ExitCode.PASS
    assert s.exit_name == "PASS"
    assert [c.name for c in s.conditions] == [ConditionName.PASS]


def test_13_2_fixed_findings_still_pass():
    # A FIXED finding is the good outcome; it raises no condition.
    s = compute_status([finding("F-001", Category.FIXED, "exploit_primary")], all_ok())
    assert s.exit_code is ExitCode.PASS


# -- one finding each (§13.3) ------------------------------------------------

def test_13_3_incomplete_fix_is_vuln_remains_10():
    s = compute_status([finding("F-001", Category.INCOMPLETE_FIX, "exploit_primary")], all_ok())
    assert s.exit_code == 10
    assert s.exit_name == "VULN_REMAINS"
    cond = s.conditions[0]
    assert cond.findings == ["F-001"]
    assert cond.tests == ["exploit_primary"]


def test_13_3_new_issue_shares_code_10_but_keeps_its_name():
    s = compute_status([finding("F-002", Category.NEW_ISSUE, "valid_ping")], all_ok())
    assert s.exit_code == 10
    assert s.exit_name == "NEW_ISSUE"  # distinct from VULN_REMAINS


def test_13_3_functional_regression_is_20():
    s = compute_status([finding("F-003", Category.FUNCTIONAL_REGRESSION, "valid_set")], all_ok())
    assert s.exit_code == 20
    assert s.exit_name == "FUNC_REGRESSION"


def test_13_3_inconclusive_finding_is_40():
    s = compute_status([finding("F-004", Category.INCONCLUSIVE, "boundary_empty")], all_ok())
    assert s.exit_code == 40
    assert s.exit_name == "INCONCLUSIVE"


# -- priority when several conditions hold (§13.1) ---------------------------

def test_13_1_vuln_remains_beats_functional_regression():
    # 10 wins over 20.
    s = compute_status([
        finding("F-001", Category.INCOMPLETE_FIX, "exploit_primary"),
        finding("F-002", Category.FUNCTIONAL_REGRESSION, "valid_set"),
    ], all_ok())
    assert s.exit_code == 10
    # Both conditions are recorded, most-severe first.
    names = [c.name for c in s.conditions]
    assert names[0] is ConditionName.VULN_REMAINS
    assert ConditionName.FUNC_REGRESSION in names


def test_13_1_build_error_beats_everything():
    # A failed build check is 30, which outranks a code-10 finding.
    checks = Checks(*([True] * 7))
    checks.builds_ok = False
    s = compute_status([finding("F-001", Category.INCOMPLETE_FIX, "exploit_primary")], checks)
    assert s.exit_code == 30
    assert s.exit_name == "BUILD_OR_CONFIG_ERROR"


def test_13_1_new_issue_and_vuln_remains_tie_breaks_to_vuln_remains():
    # Both are code 10; VULN_REMAINS names the status.
    s = compute_status([
        finding("F-002", Category.NEW_ISSUE, "v"),
        finding("F-001", Category.INCOMPLETE_FIX, "s"),
    ], all_ok())
    assert s.exit_code == 10
    assert s.exit_name == "VULN_REMAINS"


# -- required checks (§13.2) -------------------------------------------------

def test_13_2_failed_soundness_check_is_inconclusive_40():
    checks = Checks(*([True] * 7))
    checks.base_reproduced = False
    s = compute_status([], checks)
    assert s.exit_code == 40
    assert s.exit_name == "INCONCLUSIVE"
    assert "did not reproduce" in s.conditions[0].reason


def test_13_2_soundness_failure_merges_with_inconclusive_finding():
    checks = Checks(*([True] * 7))
    checks.results_stable = False
    s = compute_status([finding("F-001", Category.INCONCLUSIVE, "boundary_empty")], checks)
    # One INCONCLUSIVE condition carrying both the finding and the flaky-check reason.
    inconclusive = [c for c in s.conditions if c.name is ConditionName.INCONCLUSIVE]
    assert len(inconclusive) == 1
    assert inconclusive[0].findings == ["F-001"]
    assert "flaky" in inconclusive[0].reason


def test_13_2_build_and_soundness_failures_both_recorded_build_wins():
    checks = Checks()  # every check False
    s = compute_status([], checks)
    assert s.exit_code == 30  # build error outranks the inconclusive soundness failure
    names = {c.name for c in s.conditions}
    assert ConditionName.BUILD_OR_CONFIG_ERROR in names
    assert ConditionName.INCONCLUSIVE in names


# -- shape of the result -----------------------------------------------------

def test_13_status_carries_the_checks_object():
    checks = all_ok()
    s = compute_status([], checks)
    assert s.checks is checks
    assert s.checks.all_ok
