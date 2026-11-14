"""Completeness check: nothing is lost between the results and the report.

Grouping results into findings only changes how they are presented; it must
never drop one. At the end of every run this module checks that:

1. every **abnormal result** (a crash, an oracle mismatch, a timeout, a
   resource limit, or a flaky result, on any build) belongs to a test that is
   referenced by at least one finding or status condition;
2. every **stable crash with a signature** on a sanitized build is in
   **exactly one** crash finding.

A failure is a bug in the tool, never in the target: it raises
``TOOL_INTERNAL`` (exit 30, details in ``errors.log``) listing every problem
found. This module never runs anything and never changes a finding.

What is abnormal but needs no finding of its own (``expected``):

- a ``security`` or ``regression`` test that ends on a base build without a
  crash but not normally (timeout, resource limit, oracle mismatch). Base is
  not judged for these kinds by the finding rules. For ``security`` tests
  this is the status condition ``base_not_reproduced`` (exit 40); for
  ``regression`` tests the warning ``REGRESSION_BASE_CLEAN``.

A crash is never expected: on any build and for any kind of test, it is in a
crash finding, an unsigned-crash finding, or a flaky finding.
"""

from __future__ import annotations

from typing import Optional

from .findings import BugKey, bug_key
from .models import (
    BuildName,
    Category,
    CombinedResult,
    ErrorCode,
    Finding,
    Outcome,
    Results,
    TestKind,
    Version,
    ZarabanError,
)

_SANITIZED = (BuildName.BASE_SANITIZED, BuildName.PATCH_SANITIZED)
_BASE_NOT_JUDGED = (TestKind.SECURITY, TestKind.REGRESSION)
# Crash finding categories -> (key seen on base, key seen on patch).
_CRASH_CATEGORIES = {Category.FIXED: (True, False), Category.NEW_ISSUE: (False, True),
                     Category.INCOMPLETE_FIX: (True, True)}


def check(results: Optional[Results], findings: list[Finding]) -> None:
    """Raise ``TOOL_INTERNAL`` if a result is lost; return None if not."""
    if not results:
        return
    problems = unreferenced(results, findings) + crash_counts(results, findings)
    if problems:
        raise ZarabanError(
            ErrorCode.TOOL_INTERNAL,
            f"completeness check failed: {len(problems)} result(s) are not reported "
            f"correctly; this is a bug in the tool",
            {"problems": problems},
        )


# ---------------------------------------------------------------------------
# Rule 1: every abnormal result is referenced
# ---------------------------------------------------------------------------


def is_abnormal(r: CombinedResult) -> bool:
    """A crash, an oracle mismatch, a timeout, a resource limit, or flaky."""
    return r.flaky or r.outcome is not Outcome.NORMAL or r.oracle_passed is False


def expected(r: CombinedResult) -> bool:
    """An abnormal result that is reported without a finding: a stable,
    non-crash result of a ``security`` or ``regression`` test on a base build
    (module docstring)."""
    return (not r.flaky and r.outcome is not Outcome.CRASH
            and r.build.version is Version.BASE and r.kind in _BASE_NOT_JUDGED)


def unreferenced(results: Results, findings: list[Finding]) -> list[str]:
    """One problem per abnormal result whose test no finding names."""
    referenced = {name for f in findings for name in f.test_names}
    problems = []
    for test, per_build in results.items():
        if test in referenced:
            continue
        for build, r in per_build.items():
            if is_abnormal(r) and not expected(r):
                problems.append(f"{test} on {build.value}: {_describe(r)} is in no finding")
    return problems


# ---------------------------------------------------------------------------
# Rule 2: every signed sanitized crash is in exactly one crash finding
# ---------------------------------------------------------------------------


def finding_key(f: Finding, results: Results) -> Optional[BugKey]:
    """The bug key of a crash finding, or None for any other finding.

    The key is rebuilt from the finding's tests, not from its ``signature``
    text: two different bug keys can share a signature (same functions, a
    different file), so the text alone cannot tell them apart. The key is the
    one that every test of the finding has on a sanitized build and that fits
    the category: ``FIXED`` only on base, ``NEW_ISSUE`` only on patch,
    ``INCOMPLETE_FIX`` on both.
    """
    if f.signature is None or f.category not in _CRASH_CATEGORIES:
        return None
    per_test = [_sanitized_keys(results.get(name, {})) for name in f.test_names]
    if not per_test:
        return None
    common = set.intersection(*(base | patch for base, patch in per_test))
    fitting = []
    for key in common:
        on_base = any(key in base for base, _ in per_test)
        on_patch = any(key in patch for _, patch in per_test)
        if (on_base, on_patch) == _CRASH_CATEGORIES[f.category]:
            fitting.append(key)
    return fitting[0] if len(fitting) == 1 else None


def _sanitized_keys(per_build) -> tuple[set[BugKey], set[BugKey]]:
    """The bug keys of the stable crashes on base-sanitized and patch-sanitized."""
    out = []
    for build in _SANITIZED:
        r = per_build.get(build)
        key = bug_key(r.first.analysis) if r is not None and r.stable_crash else None
        out.append({key} if key is not None else set())
    return out[0], out[1]


def crash_counts(results: Results, findings: list[Finding]) -> list[str]:
    """One problem per stable signed sanitized crash that is in zero, or more
    than one, crash finding with its bug key."""
    keyed = [(f, finding_key(f, results)) for f in findings]
    problems = []
    for f, key in keyed:
        if f.signature is not None and f.category in _CRASH_CATEGORIES and key is None:
            problems.append(f"{f.id}: {f.category.value} with signature {f.signature!r}, but "
                            f"its tests share no bug key that fits the category")
    for test, per_build in results.items():
        for build in _SANITIZED:
            r = per_build.get(build)
            if r is None or not r.stable_crash:
                continue
            key = bug_key(r.first.analysis)
            if key is None:  # no signature: an unsigned crash, checked by rule 1
                continue
            ids = [f.id for f, k in keyed if k == key and test in f.test_names]
            if len(ids) != 1:
                where = "no crash finding" if not ids else f"{len(ids)} crash findings ({', '.join(ids)})"
                problems.append(f"{test} on {build.value}: crash {r.signature} is in {where}")
    return problems


def _describe(r: CombinedResult) -> str:
    if r.flaky:
        return "a flaky result"
    if r.outcome is not Outcome.NORMAL:
        return r.outcome.value
    return "an oracle mismatch"
