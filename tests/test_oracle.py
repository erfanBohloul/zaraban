"""Unit tests for oracle matching (SPEC §5.4)."""

from zaraban.models import Outcome, OutputMatch, TestCase, TestKind
from zaraban.oracle import match


def case(**kw) -> TestCase:
    return TestCase(name="t", kind=TestKind.VALID, input_bytes=b"", **kw)


def test_5_4_exit_code_matches():
    r = match(case(expected_exit_code=0), Outcome.NORMAL, 0, b"")
    assert (r.checked, r.passed, r.reasons) == (True, True, [])


def test_5_4_exit_code_mismatch_gives_a_reason():
    r = match(case(expected_exit_code=0), Outcome.NORMAL, 1, b"")
    assert r.passed is False
    assert r.reasons == ["exit code 1, expected 0"]


def test_5_4_contains_matches_utf8_bytes_anywhere():
    t = case(expected_output="PONG")
    assert match(t, Outcome.NORMAL, 0, b"hello PONG\n").passed
    assert match(case(expected_output="سلام"), Outcome.NORMAL, 0, "x سلام y".encode()).passed
    assert match(t, Outcome.NORMAL, 0, b"PING\n").passed is False


def test_5_4_exact_is_byte_for_byte_including_newlines():
    t = case(expected_output="OK\n", output_match=OutputMatch.EXACT)
    assert match(t, Outcome.NORMAL, 0, b"OK\n").passed
    r = match(t, Outcome.NORMAL, 0, b"OK")
    assert r.passed is False and r.reasons == ["output does not exact-match"]
    assert match(t, Outcome.NORMAL, 0, b"OK\n\n").passed is False


def test_5_4_a_run_that_did_not_end_normally_never_matches():
    t = case(expected_exit_code=0)
    for outcome in (Outcome.CRASH, Outcome.TIMEOUT, Outcome.RESOURCE_LIMIT):
        r = match(t, outcome, None, b"")
        assert r.passed is False
        assert r.reasons[0] == f"ended with {outcome.value}"


def test_5_4_all_reasons_are_listed():
    t = case(expected_exit_code=0, expected_output="PONG")
    r = match(t, Outcome.NORMAL, 2, b"nope")
    assert r.reasons == ["exit code 2, expected 0", "output does not contains-match"]


def test_5_4_standard_error_is_not_compared():
    # Only stdout is passed to the oracle; a test with output in stderr fails.
    assert match(case(expected_output="PONG"), Outcome.NORMAL, 0, b"").passed is False


def test_5_4_no_oracle_fields_is_not_checked():
    r = match(case(), Outcome.NORMAL, 0, b"")
    assert (r.checked, r.passed, r.reasons) == (False, None, [])
