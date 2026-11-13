"""Oracle matching for Zaraban (SPEC §5.4, Phase 1 Member B Task B3).

Compares test execution results against expected exit codes and output patterns.
Standard error is not compared (it is used solely for crash analysis).
"""

from __future__ import annotations

from typing import Any, Optional, Union

from .models import OracleResult, Outcome, OutputMatch


def match(
    test: Any,
    outcome: Union[Outcome, str],
    exit_code: Optional[int],
    stdout: bytes,
) -> OracleResult:
    """Judge a run against the test's expected outcome, exit code, and stdout (§5.4).

    Parameters:
        test: The TestCase specification containing expected values.
        outcome: The Outcome enum or string (e.g. Outcome.NORMAL, Outcome.CRASH).
        exit_code: Process exit code (None if terminated by signal).
        stdout: Raw standard output captured during the run.

    Returns:
        OracleResult with (checked, passed, reasons).
    """
    outcome_str = outcome.value if isinstance(outcome, Outcome) else str(outcome)
    reasons: list[str] = []

    # If the run did not end normally, it fails the functional oracle (§5.4)
    if outcome_str != Outcome.NORMAL.value:
        reasons.append(f"ended with {outcome_str}")

    # Check exit code
    expected_exit = getattr(test, "expected_exit_code", None)
    if expected_exit is not None:
        if exit_code != expected_exit:
            reasons.append(f"exit code {exit_code}, expected {expected_exit}")

    # Check stdout
    expected_output = getattr(test, "expected_output", None)
    if expected_output is not None:
        want = expected_output.encode("utf-8") if isinstance(expected_output, str) else expected_output
        output_match = getattr(test, "output_match", "contains")
        match_mode = output_match.value if isinstance(output_match, OutputMatch) else str(output_match).lower()

        if match_mode == "exact":
            ok = (stdout == want)
        else:
            ok = (want in stdout)

        if not ok:
            reasons.append(f"output does not {match_mode}-match")

    checked = expected_exit is not None or expected_output is not None
    passed = (not reasons) if checked else None

    return OracleResult(
        checked=checked,
        passed=passed,
        reasons=reasons,
    )
