"""Oracle matching (SPEC §5.4).

Compares a run with the test's expected exit code and standard output.
Standard error is not compared; it is used only for crash analysis (§7.4).
"""

from __future__ import annotations

from typing import Optional

from .models import OracleResult, Outcome, OutputMatch, TestCase


def match(test: TestCase, outcome: Outcome, exit_code: Optional[int], stdout: bytes) -> OracleResult:
    """Judge one run against the test's oracle fields (§5.4).

    A run that did not end normally never matches. ``expected_output`` is
    compared as UTF-8 bytes: anywhere in stdout for ``contains``, byte for
    byte for ``exact``. A test with no oracle fields is not checked
    (``checked=False``, ``passed=None``), but the reasons are still listed.
    """
    reasons: list[str] = []

    if outcome is not Outcome.NORMAL:
        reasons.append(f"ended with {outcome.value}")

    if test.expected_exit_code is not None and exit_code != test.expected_exit_code:
        reasons.append(f"exit code {exit_code}, expected {test.expected_exit_code}")

    if test.expected_output is not None:
        want = test.expected_output.encode("utf-8")
        exact = test.output_match is OutputMatch.EXACT
        if not (stdout == want if exact else want in stdout):
            reasons.append(f"output does not {test.output_match.value}-match")

    checked = test.has_oracle
    return OracleResult(checked=checked, passed=(not reasons) if checked else None, reasons=reasons)
