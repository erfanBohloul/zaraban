"""Completeness check: nothing is lost between the results and the report (SPEC §8.7).

Grouping results into findings only changes how they are presented; it must
never drop one. At the end of every run (Task 2.4) this module checks that:

1. every **abnormal result** (a crash, an oracle mismatch, a timeout, a
   resource limit, or a flaky result, on any build) belongs to a test that is
   referenced by at least one finding or status condition;
2. every **stable crash with a signature** on a sanitized build is in
   **exactly one** crash finding (§8.2).

A failure is a bug in the tool, never in the target: it raises
``TOOL_INTERNAL`` (exit 30, details in ``errors.log``) listing every problem
found. This module never runs anything and never changes a finding.

What is abnormal but needs no finding of its own (``expected``):

- a ``security`` or ``regression`` test that ends on a base build without a
  crash but not normally (timeout, resource limit, oracle mismatch). Base is
  not judged for these kinds by the finding rules (§8.4). For ``security``
  tests this is the status condition ``base_not_reproduced`` (§8.6, §13.2,
  exit 40); for ``regression`` tests the warning ``REGRESSION_BASE_CLEAN``.

A crash is never expected: on any build and for any kind of test, it is in a
crash finding (§8.2), a finding of §8.3, or a flaky finding (§8.5).
"""

from __future__ import annotations

from typing import Optional

from .findings import BugKey, bug_key
from .models import (
    BuildName,
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


def check(results: Optional[Results], findings: list[Finding]) -> None:
    """Raise ``TOOL_INTERNAL`` if a result is lost (§8.7); return None if not."""
    if not results:
        return
    problems = unreferenced(results, findings) + crash_counts(results, findings)
    if problems:
        raise ZarabanError(
            ErrorCode.TOOL_INTERNAL,
            f"completeness check failed (§8.7): {len(problems)} result(s) are not reported "
            f"correctly; this is a bug in the tool",
            {"problems": problems},
        )


# ---------------------------------------------------------------------------
# Rule 1: every abnormal result is referenced
# ---------------------------------------------------------------------------


def is_abnormal(r: CombinedResult) -> bool:
    """A crash, an oracle mismatch, a timeout, a resource limit, or flaky (§8.7)."""
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
    """The bug key of a crash finding (§8.2), or None for any other finding.

    A crash finding's ``signature`` is the first signature seen in its group,
    so one of its tests has a stable sanitized crash with exactly that
    signature; that crash's bug key is the finding's key.
    """
    if f.signature is None:
        return None
    for name in f.test_names:
        for build in _SANITIZED:
            r = results.get(name, {}).get(build)
            if r is not None and r.stable_crash and r.signature == f.signature:
                return bug_key(r.first.analysis)
    return None


def crash_counts(results: Results, findings: list[Finding]) -> list[str]:
    """One problem per stable signed sanitized crash that is in zero, or more
    than one, crash finding with its bug key."""
    keyed = [(f, finding_key(f, results)) for f in findings]
    problems = []
    for f, key in keyed:
        if f.signature is not None and key is None:
            problems.append(f"{f.id}: has signature {f.signature!r} but no stable sanitized "
                            f"crash of its tests has it")
    for test, per_build in results.items():
        for build in _SANITIZED:
            r = per_build.get(build)
            if r is None or not r.stable_crash:
                continue
            key = bug_key(r.first.analysis)
            if key is None:  # no signature: §8.3, checked by rule 1
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
