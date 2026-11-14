"""Decide the run's outcome: conditions and the final exit code.

This is the tool's verdict. It takes the findings, the errors of the run and
the required checks (gathered by the pipeline) and produces a :class:`~zaraban.models.Status`: the list of
:class:`Condition` reasons, the single :class:`ExitCode`, and a one-line
reason.

Conditions:

* ``BUILD_OR_CONFIG_ERROR`` (30): there is at least one error. A failed
  ``builds_ok``, ``profiles_verified``, ``all_runs_completed`` or
  ``hardening_checked`` check is an error too, so it raises this
  condition even if the pipeline forgot to record the error.
* ``VULN_REMAINS`` / ``NEW_ISSUE`` (10), ``FUNC_REGRESSION`` (20),
  ``INCONCLUSIVE`` (40): one per finding category; ``FIXED`` raises nothing.
* ``INCONCLUSIVE`` (40) also when ``base_reproduced`` failed, naming the
  security tests that did not crash on base.
* ``PASS`` (0): none of the above **and at least one FIXED finding**. With no
  condition and no FIXED finding the result is ``INCONCLUSIVE``: nothing shows
  that the original error was reproduced and then removed.

When several conditions hold, the first code in ``EXIT_PRIORITY`` wins
(30 > 10 > 20 > 40 > 0); between ``VULN_REMAINS`` and ``NEW_ISSUE``
the name is ``VULN_REMAINS``. Every condition stays in the report.
"""

from __future__ import annotations

from typing import Optional

from .models import (
    EXIT_PRIORITY,
    Category,
    Checks,
    Condition,
    ConditionName,
    Finding,
    Issue,
    OnPatch,
    Status,
)
from .util import unique

# A finding of this category raises this condition. FIXED raises nothing.
_CATEGORY_CONDITION: dict[Category, ConditionName] = {
    Category.INCOMPLETE_FIX: ConditionName.VULN_REMAINS,
    Category.NEW_ISSUE: ConditionName.NEW_ISSUE,
    Category.FUNCTIONAL_REGRESSION: ConditionName.FUNC_REGRESSION,
    Category.INCONCLUSIVE: ConditionName.INCONCLUSIVE,
}

# Required checks whose failure is an error, code 30.
_ERROR_CHECKS: tuple[tuple[str, str], ...] = (
    ("builds_ok", "a build failed"),
    ("profiles_verified", "a binary failed profile verification"),
    ("all_runs_completed", "not every test ran on every build"),
    ("hardening_checked", "the release binaries were not inspected for hardening"),
)

# Required checks whose failure means INCONCLUSIVE, code 40.
# ``results_stable`` and ``bundles_replayed`` are normally covered by the
# INCONCLUSIVE findings for flaky results and for bundles that do not replay;
# they are checked here as well so a failed check can never end in PASS.
_INCONCLUSIVE_CHECKS: tuple[tuple[str, str], ...] = (
    ("base_reproduced", "a security test did not crash on base-sanitized"),
    ("results_stable", "a result was flaky"),
    ("bundles_replayed", "a reproducer bundle did not replay stably"),
)

# Tie-break among conditions with the same code: VULN_REMAINS names a 10.
_NAME_RANK: dict[ConditionName, int] = {
    ConditionName.BUILD_OR_CONFIG_ERROR: 0,
    ConditionName.VULN_REMAINS: 1,
    ConditionName.NEW_ISSUE: 2,
    ConditionName.FUNC_REGRESSION: 3,
    ConditionName.INCONCLUSIVE: 4,
    ConditionName.PASS: 5,
}


def compute_status(
    findings: list[Finding],
    checks: Checks,
    errors: Optional[list[Issue]] = None,
    base_not_reproduced: Optional[list[str]] = None,
) -> Status:
    """Turn findings, errors and checks into the run's :class:`Status`.

    ``base_not_reproduced`` names the security tests that did not crash on
    ``base-sanitized``; it is used for the reason of the ``base_reproduced``
    condition. The conditions are returned most-severe first.
    """
    conditions: list[Condition] = []
    conditions.extend(_error_conditions(errors or [], checks))
    conditions.extend(_finding_conditions(findings))
    conditions.extend(_inconclusive_check_conditions(checks, base_not_reproduced or []))
    conditions = _merge_by_name(conditions)

    if not conditions:
        fixed = [f.id for f in findings if f.category is Category.FIXED]
        if fixed:
            conditions = [Condition(
                ConditionName.PASS,
                f"{', '.join(fixed)}: the error is reproduced on base and not observed "
                "on patch; all other checks passed",
                findings=fixed,
                tests=unique(t for f in findings if f.id in fixed for t in f.test_names))]
        else:
            # Cannot happen when base_reproduced succeeded.
            conditions = [Condition(
                ConditionName.INCONCLUSIVE,
                "no FIXED finding: nothing shows the error was reproduced on base "
                "and removed on patch")]

    conditions.sort(key=_priority)
    deciding = conditions[0]
    return Status(
        checks=checks,
        conditions=conditions,
        exit_code=deciding.code,
        exit_name=deciding.name.value,
        reason=_status_reason(deciding, conditions),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _error_conditions(errors: list[Issue], checks: Checks) -> list[Condition]:
    reasons = [f"{e.code}: {e.message}" for e in errors]
    reasons += [msg for attr, msg in _ERROR_CHECKS if not getattr(checks, attr)]
    if not reasons:
        return []
    return [Condition(ConditionName.BUILD_OR_CONFIG_ERROR, "; ".join(unique(reasons)))]


def _finding_conditions(findings: list[Finding]) -> list[Condition]:
    """One condition per raised category, listing the findings that raised it."""
    grouped: dict[ConditionName, list[Finding]] = {}
    for f in findings:
        name = _CATEGORY_CONDITION.get(f.category)
        if name is not None:  # FIXED raises nothing
            grouped.setdefault(name, []).append(f)

    out: list[Condition] = []
    for name, group in grouped.items():
        tests = unique(t for f in group for t in _causing_tests(f))
        out.append(Condition(name, _finding_reason(name, group),
                             findings=[f.id for f in group], tests=tests))
    return out


def _causing_tests(f: Finding) -> list[str]:
    """The tests that caused the condition. For an incomplete fix these are the
    tests that still reach the error on patch, not the ones the patch blocks."""
    if f.category is Category.INCOMPLETE_FIX:
        reaching = [t.test for t in f.tests if t.on_patch is OnPatch.REACHES]
        if reaching:
            return reaching
    return f.test_names


def _inconclusive_check_conditions(checks: Checks, not_reproduced: list[str]) -> list[Condition]:
    reasons: list[str] = []
    for attr, msg in _INCONCLUSIVE_CHECKS:
        if getattr(checks, attr):
            continue
        if attr == "base_reproduced" and not_reproduced:
            msg = f"security test(s) {', '.join(not_reproduced)} did not crash on base-sanitized"
        reasons.append(msg)
    if not reasons:
        return []
    tests = not_reproduced if not checks.base_reproduced else []
    return [Condition(ConditionName.INCONCLUSIVE, "; ".join(reasons), tests=list(tests))]


def _merge_by_name(conditions: list[Condition]) -> list[Condition]:
    """Fold conditions that share a name (e.g. an INCONCLUSIVE finding and a
    failed check) into one, keeping all findings, tests and reasons."""
    merged: dict[ConditionName, Condition] = {}
    for c in conditions:
        if c.name not in merged:
            merged[c.name] = Condition(c.name, c.reason, list(c.findings), list(c.tests))
            continue
        m = merged[c.name]
        m.findings = unique([*m.findings, *c.findings])
        m.tests = unique([*m.tests, *c.tests])
        if c.reason and c.reason not in m.reason:
            m.reason = f"{m.reason}; {c.reason}" if m.reason else c.reason
    return list(merged.values())


def _finding_reason(name: ConditionName, group: list[Finding]) -> str:
    parts = []
    for f in group:
        tests = ", ".join(_causing_tests(f)) or "no test"
        what = {
            ConditionName.VULN_REMAINS: f"the error is still reached on patch by {tests}",
            ConditionName.NEW_ISSUE: f"a security error appears on patch only, in {tests}",
            ConditionName.FUNC_REGRESSION: f"{tests} passed on base and fail on patch",
            ConditionName.INCONCLUSIVE: f"the result of {tests} could not be classified",
        }[name]
        parts.append(f"{f.id}: {what}")
    return "; ".join(parts)


def _status_reason(deciding: Condition, conditions: list[Condition]) -> str:
    """``VULN_REMAINS (F-001) has the highest priority among: VULN_REMAINS.``"""
    ids = f" ({', '.join(deciding.findings)})" if deciding.findings else ""
    names = ", ".join(c.name.value for c in conditions)
    return f"{deciding.name.value}{ids} has the highest priority among: {names}."


def _priority(c: Condition) -> tuple[int, int]:
    return (EXIT_PRIORITY.index(c.code), _NAME_RANK[c.name])
