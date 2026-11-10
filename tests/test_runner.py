"""Unit tests for Zaraban's SafeRunner and resource watchdogs."""

import os
import sys
import unittest
from zaraban.executor.runner import SafeRunner


class TestSafeRunner(unittest.TestCase):

    def test_normal_execution(self):
        res = SafeRunner.run(["echo", "Zaraban Test"], timeout_seconds=2.0)
        self.assertEqual(res.exit_code, 0)
        self.assertIn("Zaraban Test", res.stdout)
        self.assertFalse(res.timed_out)
        self.assertFalse(res.is_crash)

    def test_timeout_watchdog(self):
        # Sleep for 5s with 0.5s limit
        res = SafeRunner.run(["sleep", "5"], timeout_seconds=0.5)
        self.assertTrue(res.timed_out)
        self.assertTrue(res.is_crash)
        self.assertEqual(res.detection_mechanism, "ResourceLimit/Timeout")
        self.assertLess(res.duration_seconds, 2.0)

    def test_stdin_feeding(self):
        res = SafeRunner.run(["cat"], input_data="Security Test Input\n", timeout_seconds=1.0)
        self.assertEqual(res.exit_code, 0)
        self.assertIn("Security Test Input", res.stdout)

    def test_signal_handling(self):
        res = SafeRunner.run(
            [sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGSEGV)"],
            timeout_seconds=2.0
        )
        self.assertTrue(res.is_crash)
        self.assertEqual(res.signal_name, "SIGSEGV")
        self.assertEqual(res.signal_num, 11)


if __name__ == "__main__":
    unittest.main()
