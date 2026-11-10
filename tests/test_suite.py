"""Comprehensive unit and integration test suite for Zaraban.

Runs with Python's standard unittest library:
    python3 -m unittest tests/test_suite.py
"""

import os
import unittest
from pathlib import Path

from zaraban.constants import ExitCode, resolve_exit_code
from zaraban.config import TargetConfig, TestCase, InputMethod
from zaraban.correlator.diff_parser import DiffParser, PatchDiff
from zaraban.correlator.crash_parser import CrashParser, CrashReport, StackFrame, ErrorType
from zaraban.correlator.engine import (
    CorrelationEngine,
    CorrelationStrength,
    FindingCategory
)
from zaraban.minimizer.delta_debugger import DeltaDebugger
from zaraban.hardening.inspector import (
    PurePythonELFParser,
    RelroLevel,
    HardeningStatus,
    HardeningReport,
    compare_hardening
)
from zaraban.reproducer.bundle import ReproducerBundleManager


class TestConstants(unittest.TestCase):
    def test_priority_resolution(self):
        # Mandated priority: 30 > 10 > 20 > 40 > 0
        self.assertEqual(
            resolve_exit_code([ExitCode.PASS, ExitCode.ERROR_CONFIG_OR_BUILD]),
            ExitCode.ERROR_CONFIG_OR_BUILD
        )
        self.assertEqual(
            resolve_exit_code([ExitCode.PASS, ExitCode.FUNC_REGRESSION, ExitCode.VULN_OR_NEW_ISSUE]),
            ExitCode.VULN_OR_NEW_ISSUE
        )
        self.assertEqual(
            resolve_exit_code([ExitCode.PASS, ExitCode.FUNC_REGRESSION]),
            ExitCode.FUNC_REGRESSION
        )
        self.assertEqual(
            resolve_exit_code([ExitCode.PASS, ExitCode.INCONCLUSIVE]),
            ExitCode.INCONCLUSIVE
        )
        self.assertEqual(
            resolve_exit_code([ExitCode.PASS]),
            ExitCode.PASS
        )
        self.assertEqual(
            resolve_exit_code([]),
            ExitCode.INCONCLUSIVE
        )


class TestDiffParser(unittest.TestCase):
    SAMPLE_DIFF = """--- a/src/main.c
+++ b/src/main.c
@@ -25,6 +25,11 @@ int handle_set_command(const char *arg) {
+    size_t val_len = strlen(val_start);
+    if (val_len >= sizeof(value)) {
+        return 1;
+    }
+
     strcpy(value, val_start);
"""

    def test_diff_parsing(self):
        patch = DiffParser.parse_string(self.SAMPLE_DIFF)
        self.assertEqual(len(patch.files), 1)
        f = patch.files[0]
        self.assertEqual(f.filename, "main.c")
        self.assertEqual(len(f.hunks), 1)
        hunk = f.hunks[0]
        self.assertEqual(hunk.new_start, 25)
        self.assertTrue(hunk.contains_new_line(28))
        self.assertFalse(hunk.contains_new_line(50))


class TestCrashParser(unittest.TestCase):
    ASAN_OUTPUT = """
=================================================================
==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff
WRITE of size 120 at 0x7fff thread T0
    #0 0x1000 in handle_set_command /workspace/src/main.c:32:5
    #1 0x2000 in process_input /workspace/src/main.c:63:9
    #2 0x3000 in main /workspace/src/main.c:85:12
SUMMARY: AddressSanitizer: stack-buffer-overflow /workspace/src/main.c:32:5 in handle_set_command
"""

    def test_asan_parsing(self):
        crash = CrashParser.parse_execution(
            stdout="",
            stderr=self.ASAN_OUTPUT,
            exit_code=1
        )
        self.assertIsNotNone(crash)
        self.assertEqual(crash.error_type, ErrorType.STACK_BUFFER_OVERFLOW)
        self.assertEqual(crash.detection_mechanism, "Sanitizer/ASan")
        self.assertEqual(len(crash.stack_frames), 3)
        self.assertEqual(crash.stack_frames[0].function, "handle_set_command")
        self.assertEqual(crash.stack_frames[0].line, 32)
        self.assertEqual(crash.stack_frames[0].basename, "main.c")

    def test_stack_canary_parsing(self):
        canary_err = "*** buffer overflow detected ***: terminated\nAborted"
        crash = CrashParser.parse_execution(stdout="", stderr=canary_err, exit_code=134)
        self.assertIsNotNone(crash)
        self.assertEqual(crash.detection_mechanism, "BinaryProtection/StackCanary")
        self.assertEqual(crash.error_type, ErrorType.STACK_CANARY_CORRUPTION)


class TestCorrelationEngine(unittest.TestCase):
    def test_correlation_fixed(self):
        diff = DiffParser.parse_string(TestDiffParser.SAMPLE_DIFF)
        base_crash = CrashReport(
            error_type="StackBufferOverflow",
            detection_mechanism="Sanitizer/ASan",
            stack_frames=[StackFrame(index=0, function="handle_set_command", filename="main.c", line=28)]
        )
        finding = CorrelationEngine.classify_finding(
            test_name="exploit_1",
            base_crash=base_crash,
            patch_crash=None,
            diff=diff
        )
        self.assertEqual(finding.category, FindingCategory.FIXED)

    def test_correlation_incomplete_fix(self):
        diff = DiffParser.parse_string(TestDiffParser.SAMPLE_DIFF)
        crash = CrashReport(
            error_type="StackBufferOverflow",
            detection_mechanism="Sanitizer/ASan",
            stack_frames=[StackFrame(index=0, function="handle_set_command", filename="main.c", line=28)]
        )
        finding = CorrelationEngine.classify_finding(
            test_name="exploit_2",
            base_crash=crash,
            patch_crash=crash,
            diff=diff
        )
        self.assertEqual(finding.category, FindingCategory.INCOMPLETE_FIX)

    def test_correlation_functional_regression(self):
        finding = CorrelationEngine.classify_finding(
            test_name="valid_test",
            base_crash=None,
            patch_crash=None,
            diff=None,
            is_valid_test=True,
            base_exit_code=0,
            patch_exit_code=1
        )
        self.assertEqual(finding.category, FindingCategory.FUNCTIONAL_REGRESSION)
        self.assertTrue(finding.is_regression)


class TestDeltaDebugger(unittest.TestCase):
    def test_ddmin_minimization(self):
        # Oracle requires 'PING' prefix and length >= 20
        def oracle(data: bytes) -> bool:
            return data.startswith(b"PING") and len(data) >= 20

        initial = b"PING" + b"X" * 100
        res = DeltaDebugger.minimize(initial, oracle)
        self.assertEqual(len(res.minimized_data), 20)
        self.assertTrue(res.minimized_data.startswith(b"PING"))
        self.assertGreater(res.reduction_percent, 70.0)


class TestHardeningComparison(unittest.TestCase):
    def test_hardening_regression_detection(self):
        base_status = HardeningStatus(nx=True, pie=True, relro=RelroLevel.FULL, canary=True)
        base_rep = HardeningReport(binary_path="/bin/base", sha256="abc", status=base_status)

        # Patched build accidentally disabled Canary and downgraded RELRO
        patch_status = HardeningStatus(nx=True, pie=True, relro=RelroLevel.PARTIAL, canary=False)
        patch_rep = HardeningReport(binary_path="/bin/patch", sha256="def", status=patch_status)

        comp = compare_hardening(base_rep, patch_rep)
        self.assertTrue(comp.has_regression)
        self.assertEqual(len(comp.regressions), 2)
        self.assertTrue(any("Canary" in r for r in comp.regressions))
        self.assertTrue(any("RELRO" in r for r in comp.regressions))


if __name__ == "__main__":
    unittest.main()
