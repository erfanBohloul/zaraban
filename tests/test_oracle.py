"""Unit tests for zaraban/oracle.py (Phase 1 Member B Task B3, SPEC §5.4).

Verifies exit code matching, output matching (exact and contains),
crash failure rules, and unchecked test handling. Compatible with pytest and unittest.
"""

import unittest

from zaraban.models import OracleResult, Outcome, OutputMatch, TestCase, TestKind
from zaraban.oracle import match


class TestOracleMatching(unittest.TestCase):
    def test_exit_code_match(self):
        test = TestCase(name="t1", kind=TestKind.VALID, input_bytes=None, expected_exit_code=0)
        res = match(test, Outcome.NORMAL, exit_code=0, stdout=b"OK")
        self.assertTrue(res.checked)
        self.assertTrue(res.passed)
        self.assertEqual(res.reasons, [])

    def test_exit_code_mismatch(self):
        test = TestCase(name="t1", kind=TestKind.VALID, input_bytes=None, expected_exit_code=0)
        res = match(test, Outcome.NORMAL, exit_code=1, stdout=b"Error")
        self.assertTrue(res.checked)
        self.assertFalse(res.passed)
        self.assertIn("exit code 1, expected 0", res.reasons)

    def test_contains_output_match(self):
        test = TestCase(
            name="t1",
            kind=TestKind.VALID,
            input_bytes=None,
            expected_output="SUCCESS",
            output_match=OutputMatch.CONTAINS,
        )
        res_ok = match(test, Outcome.NORMAL, exit_code=0, stdout=b"[INFO] SUCCESS: test passed")
        self.assertTrue(res_ok.passed)

        res_fail = match(test, Outcome.NORMAL, exit_code=0, stdout=b"[INFO] FAILED: test error")
        self.assertFalse(res_fail.passed)
        self.assertIn("output does not contains-match", res_fail.reasons)

    def test_exact_output_match(self):
        test = TestCase(
            name="t1",
            kind=TestKind.VALID,
            input_bytes=None,
            expected_output="42\n",
            output_match=OutputMatch.EXACT,
        )
        res_ok = match(test, Outcome.NORMAL, exit_code=0, stdout=b"42\n")
        self.assertTrue(res_ok.passed)

        res_fail = match(test, Outcome.NORMAL, exit_code=0, stdout=b"42\nextra")
        self.assertFalse(res_fail.passed)
        self.assertIn("output does not exact-match", res_fail.reasons)

    def test_crash_fails_oracle_even_with_matching_exit(self):
        """SPEC §5.4: If outcome != NORMAL, functional oracle must fail."""
        test = TestCase(name="t1", kind=TestKind.VALID, input_bytes=None, expected_exit_code=0)
        res = match(test, Outcome.CRASH, exit_code=0, stdout=b"")
        self.assertFalse(res.passed)
        self.assertIn("ended with CRASH", res.reasons)

    def test_timeout_fails_oracle(self):
        test = TestCase(name="t1", kind=TestKind.VALID, input_bytes=None, expected_exit_code=0)
        res = match(test, Outcome.TIMEOUT, exit_code=None, stdout=b"")
        self.assertFalse(res.passed)
        self.assertIn("ended with TIMEOUT", res.reasons)

    def test_unchecked_oracle(self):
        """Test with no expected_exit_code and no expected_output."""
        test = TestCase(name="t1", kind=TestKind.VALID, input_bytes=None)
        res = match(test, Outcome.NORMAL, exit_code=0, stdout=b"anything")
        self.assertFalse(res.checked)
        self.assertIsNone(res.passed)
        self.assertEqual(res.reasons, [])

    def test_tuple_unpacking(self):
        test = TestCase(name="t1", kind=TestKind.VALID, input_bytes=None, expected_exit_code=0)
        checked, passed, reasons = match(test, Outcome.NORMAL, exit_code=0, stdout=b"")
        self.assertTrue(checked)
        self.assertTrue(passed)
        self.assertEqual(reasons, [])


if __name__ == "__main__":
    unittest.main()
