"""Decide the run's outcome: conditions and the final exit code (SPEC §13).

This is the tool's verdict. It takes the findings (Member C, §8) and the
required checks (gathered by the pipeline, §13.2) and produces a
:class:`~zaraban.models.Status`: the list of :class:`Condition` reasons, the
single :class:`ExitCode`, and a one-line human reason.

Two things decide the exit code:

* **Findings.** Each finding category maps to a condition (§13.3). ``FIXED``
  is the good case and raises nothing; the other categories each raise their
  condition. ``NEW_ISSUE`` and ``INCOMPLETE_FIX`` both mean code 10, but keep
  their own names so the report says which it was.
* **Required checks (§13.2).** PASS is only allowed when every check passed.
  A failed *build* check (``builds_ok`` / ``profiles_verified``) is a
  ``BUILD_OR_CONFIG_ERROR`` (30); a failed *soundness* check (the run did not
  complete, the base did not reproduce the vulnerability, results were flaky,
  a reproducer did not replay, hardening was not checked) means the verdict
  cannot be trusted, which is ``INCONCLUSIVE`` (40).

When several conditions hold at once, the first code in ``EXIT_PRIORITY``
wins (30 > 10 > 20 > 40 > 0, §13.1). This module does not build, run or write
anything; the report writer (§12) puts the returned ``Status`` into
``report.json``.
"""

from __future__ import annotations

from .models import (
    EXIT_PRIORITY,
    Category,
    Checks,
    Condition,
    ConditionName,
    ExitCode,
    Finding,
    Status,
)

# A finding of this category raises this condition. FIXED raises nothing.
_CATEGORY_CONDITION: dict[Category, ConditionName] = {
    Category.INCOMPLETE_FIX: ConditionName.VULN_REMAINS,
    Category.NEW_ISSUE: ConditionName.NEW_ISSUE,
    Category.FUNCTIONAL_REGRESSION: ConditionName.FUNC_REGRESSION,
    Category.INCONCLUSIVE: ConditionName.INCONCLUSIVE,
}

# Required checks, split by what their failure means (§13.2).
#   build checks failing  -> BUILD_OR_CONFIG_ERROR (30)
#   soundness checks failing -> INCONCLUSIVE (40): no trustworthy verdict
_BUILD_CHECKS: tuple[tuple[str, str], ...] = (
    ("builds_ok", "one of the four builds failed"),
    ("profiles_verified", "a build did not match its required profile"),
)
_SOUNDNESS_CHECKS: tuple[tuple[str, str], ...] = (
    ("all_runs_completed", "not every test run completed"),
    ("base_reproduced", "the known vulnerability did not reproduce on the base version"),
    ("results_stable", "results were flaky across repeats"),
    ("bundles_replayed", "a reproducer bundle did not replay"),
    ("hardening_checked", "the hardening comparison did not run"),
)

# Tie-break order among conditions that share an exit code (e.g. VULN_REMAINS
# and NEW_ISSUE are both 10): the earlier one names the status.
_NAME_RANK: dict[ConditionName, int] = {
    ConditionName.BUILD_OR_CONFIG_ERROR: 0,
    ConditionName.VULN_REMAINS: 1,
    ConditionName.NEW_ISSUE: 2,
    ConditionName.FUNC_REGRESSION: 3,
    ConditionName.INCONCLUSIVE: 4,
    ConditionName.PASS: 5,
}


def compute_status(findings: list[Finding], checks: Checks) -> Status:
    """Turn findings and checks into the run's :class:`Status` (§13).

    The conditions are returned most-severe first, and ``exit_code`` /
    ``exit_name`` / ``reason`` describe the deciding one.
    """
    conditions: list[Condition] = []
    conditions.extend(_finding_conditions(findings))
    conditions.extend(_check_conditions(checks))
    conditions = _merge_by_name(conditions)

    if not conditions:
        # No finding raised a condition and no check failed: a clean PASS. The
        # guard is belt-and-braces; a failed check always adds a condition.
        reason = "all required checks passed and no findings were raised"
        conditions = [Condition(ConditionName.PASS, reason)]

    conditions.sort(key=_priority)
    deciding = conditions[0]
    return Status(
        checks=checks,
        conditions=conditions,
        exit_code=deciding.code,
        exit_name=deciding.name.value,
        reason=deciding.reason,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_conditions(findings: list[Finding]) -> list[Condition]:
    """One condition per raised category, listing the findings that raised it."""
    grouped: dict[ConditionName, list[Finding]] = {}
    for f in findings:
        name = _CATEGORY_CONDITION.get(f.category)
        if name is not None:  # FIXED raises nothing
            grouped.setdefault(name, []).append(f)

    out: list[Condition] = []
    for name, group in grouped.items():
        ids = [f.id for f in group]
        tests = _unique(t for f in group for t in f.test_names)
        out.append(Condition(name, _finding_reason(name, group), findings=ids, tests=tests))
    return out


def _check_conditions(checks: Checks) -> list[Condition]:
    out: list[Condition] = []
    build_fail = [msg for attr, msg in _BUILD_CHECKS if not getattr(checks, attr)]
    if build_fail:
        out.append(Condition(ConditionName.BUILD_OR_CONFIG_ERROR, "; ".join(build_fail)))
    sound_fail = [msg for attr, msg in _SOUNDNESS_CHECKS if not getattr(checks, attr)]
    if sound_fail:
        out.append(Condition(ConditionName.INCONCLUSIVE, "; ".join(sound_fail)))
    return out


def _merge_by_name(conditions: list[Condition]) -> list[Condition]:
    """Fold conditions that share a name (e.g. an INCONCLUSIVE finding and a
    failed soundness check) into one, keeping all findings, tests and reasons."""
    merged: dict[ConditionName, Condition] = {}
    for c in conditions:
        if c.name not in merged:
            merged[c.name] = Condition(c.name, c.reason, list(c.findings), list(c.tests))
            continue
        m = merged[c.name]
        m.findings = _unique([*m.findings, *c.findings])
        m.tests = _unique([*m.tests, *c.tests])
        if c.reason and c.reason not in m.reason:
            m.reason = f"{m.reason}; {c.reason}" if m.reason else c.reason
    return list(merged.values())


def _finding_reason(name: ConditionName, group: list[Finding]) -> str:
    ids = ", ".join(f.id for f in group)
    text = {
        ConditionName.VULN_REMAINS:
            "the vulnerability still occurs on the patched version",
        ConditionName.NEW_ISSUE:
            "the patch introduced a new crash not present on the base version",
        ConditionName.FUNC_REGRESSION:
            "the patch broke previously correct behavior",
        ConditionName.INCONCLUSIVE:
            "a finding could not be classified with confidence",
    }[name]
    return f"{text} ({ids})"


def _priority(c: Condition) -> tuple[int, int]:
    return (EXIT_PRIORITY.index(c.code), _NAME_RANK[c.name])


def _unique(items) -> list[str]:
    """De-duplicate while keeping first-seen order."""
    seen: dict[str, None] = {}
    for it in items:
        seen.setdefault(it, None)
    return list(seen)
