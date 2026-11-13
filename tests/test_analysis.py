"""Unit tests for zaraban/analysis.py (Phase 1 Member B Task B2, SPEC §7.4).

Verifies every row of the outcome table and error-type table,
stack frame parsing with runtime exclusion and section isolation,
and crash signature generation. Compatible with pytest and unittest.
"""

import unittest
from pathlib import Path

from zaraban.analysis import (
    analyse,
    classify_error_type,
    extract_summary,
    frames,
    outcome,
    signature,
)
from zaraban.models import (
    Detection,
    ErrorType,
    Frame,
    LimitKind,
    Outcome,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "stderr"


class TestAnalysisOutcomes(unittest.TestCase):
    """SPEC §7.4 Outcome table tests (Rules 1 to 9)."""

    def test_rule_1_timeout(self):
        kind, det = outcome("some stderr", timed_out=True)
        self.assertEqual(kind, Outcome.TIMEOUT)
        self.assertIsNone(det)

    def test_rule_2_resource_limit_cpu(self):
        kind, det = outcome("Process terminated", sig="SIGXCPU")
        self.assertEqual(kind, Outcome.RESOURCE_LIMIT)
        self.assertIsNone(det)

    def test_rule_2_resource_limit_memory(self):
        kind, det = outcome("Memory limit", limit_hit=LimitKind.MEMORY)
        self.assertEqual(kind, Outcome.RESOURCE_LIMIT)
        self.assertIsNone(det)

    def test_rule_3_asan(self):
        stderr = "==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123"
        kind, det = outcome(stderr)
        self.assertEqual(kind, Outcome.CRASH)
        self.assertEqual(det, Detection.ASAN)

    def test_rule_4_ubsan(self):
        stderr = "src/main.c:10:5: runtime error: division by zero"
        kind, det = outcome(stderr, sig="SIGABRT")
        self.assertEqual(kind, Outcome.CRASH)
        self.assertEqual(det, Detection.UBSAN)

    def test_rule_5_stack_canary(self):
        stderr = "*** stack smashing detected ***: terminated"
        kind, det = outcome(stderr)
        self.assertEqual(kind, Outcome.CRASH)
        self.assertEqual(det, Detection.STACK_CANARY)

    def test_rule_6_fortify(self):
        stderr = "*** buffer overflow detected ***: terminated"
        kind, det = outcome(stderr)
        self.assertEqual(kind, Outcome.CRASH)
        self.assertEqual(det, Detection.FORTIFY)

    def test_rule_7_allocator_double_free(self):
        stderr = "double free or corruption (out)"
        kind, det = outcome(stderr)
        self.assertEqual(kind, Outcome.CRASH)
        self.assertEqual(det, Detection.ALLOCATOR_CHECK)

    def test_rule_7_allocator_invalid_pointer(self):
        stderr = "free(): invalid pointer"
        kind, det = outcome(stderr)
        self.assertEqual(kind, Outcome.CRASH)
        self.assertEqual(det, Detection.ALLOCATOR_CHECK)

    def test_rule_8_signals(self):
        for sig in ("SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL", "SIGABRT", "SIGTRAP"):
            kind, det = outcome("", sig=sig)
            self.assertEqual(kind, Outcome.CRASH, f"Failed for {sig}")
            self.assertEqual(det, Detection.SIGNAL, f"Failed for {sig}")

    def test_rule_9_normal_nonzero_exit_not_a_crash(self):
        kind, det = outcome("error: bad input flag\n", sig=None, timed_out=False)
        self.assertEqual(kind, Outcome.NORMAL)
        self.assertIsNone(det)


class TestAnalysisErrorTypes(unittest.TestCase):
    """SPEC §7.4 ErrorType table tests across all supported variants."""

    def test_asan_stack_buffer_overflow(self):
        stderr = "==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x123"
        t = classify_error_type(stderr, detection=Detection.ASAN)
        self.assertEqual(t, ErrorType.STACK_BUFFER_OVERFLOW)

    def test_asan_heap_buffer_overflow(self):
        stderr = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123"
        t = classify_error_type(stderr, detection=Detection.ASAN)
        self.assertEqual(t, ErrorType.HEAP_BUFFER_OVERFLOW)

    def test_asan_global_buffer_overflow(self):
        stderr = "==1==ERROR: AddressSanitizer: global-buffer-overflow on address 0x123"
        t = classify_error_type(stderr, detection=Detection.ASAN)
        self.assertEqual(t, ErrorType.GLOBAL_BUFFER_OVERFLOW)

    def test_asan_use_after_free(self):
        stderr = "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x123"
        t = classify_error_type(stderr, detection=Detection.ASAN)
        self.assertEqual(t, ErrorType.USE_AFTER_FREE)

    def test_asan_use_after_scope(self):
        stderr = "==1==ERROR: AddressSanitizer: stack-use-after-scope on address 0x123"
        t = classify_error_type(stderr, detection=Detection.ASAN)
        self.assertEqual(t, ErrorType.USE_AFTER_SCOPE)

    def test_asan_stack_exhaustion(self):
        stderr = "==1==ERROR: AddressSanitizer: stack-overflow on address 0x123"
        t = classify_error_type(stderr, detection=Detection.ASAN)
        self.assertEqual(t, ErrorType.STACK_EXHAUSTION)

    def test_asan_null_deref(self):
        stderr = "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000\nHint: address points to the zero page."
        t = classify_error_type(stderr, detection=Detection.ASAN)
        self.assertEqual(t, ErrorType.NULL_DEREF)

    def test_asan_segv(self):
        stderr = "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x00007f999999"
        t = classify_error_type(stderr, detection=Detection.ASAN)
        self.assertEqual(t, ErrorType.SEGV)

    def test_ubsan_types(self):
        self.assertEqual(classify_error_type("runtime error: division by zero", detection=Detection.UBSAN), ErrorType.DIV_BY_ZERO)
        self.assertEqual(classify_error_type("runtime error: signed integer overflow", detection=Detection.UBSAN), ErrorType.INTEGER_OVERFLOW)
        self.assertEqual(classify_error_type("runtime error: index 5 out of bounds", detection=Detection.UBSAN), ErrorType.OUT_OF_BOUNDS_INDEX)
        self.assertEqual(classify_error_type("runtime error: member access within null pointer", detection=Detection.UBSAN), ErrorType.NULL_DEREF)
        self.assertEqual(classify_error_type("runtime error: load of value 255", detection=Detection.UBSAN), ErrorType.UB_OTHER)

    def test_canary_and_fortify(self):
        self.assertEqual(classify_error_type("*** stack smashing detected ***", detection=Detection.STACK_CANARY), ErrorType.STACK_BUFFER_OVERFLOW)
        self.assertEqual(classify_error_type("*** buffer overflow detected ***", detection=Detection.FORTIFY), ErrorType.BUFFER_OVERFLOW)

    def test_allocator_types(self):
        self.assertEqual(classify_error_type("double free or corruption", detection=Detection.ALLOCATOR_CHECK), ErrorType.DOUBLE_FREE)
        self.assertEqual(classify_error_type("free(): invalid pointer", detection=Detection.ALLOCATOR_CHECK), ErrorType.INVALID_FREE)
        self.assertEqual(classify_error_type("malloc(): corrupted top size", detection=Detection.ALLOCATOR_CHECK), ErrorType.HEAP_CORRUPTION)

    def test_signals(self):
        self.assertEqual(classify_error_type("", sig="SIGFPE", detection=Detection.SIGNAL), ErrorType.DIV_BY_ZERO)
        self.assertEqual(classify_error_type("", sig="SIGABRT", detection=Detection.SIGNAL), ErrorType.ABORT)
        self.assertEqual(classify_error_type("", sig="SIGSEGV", detection=Detection.SIGNAL), ErrorType.SEGV)


class TestAnalysisFramesAndSignature(unittest.TestCase):
    """SPEC §7.4 Stack frame parsing and signature calculation."""

    SAMPLE_ASAN_STDERR = """\
==1234==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd5c3e1a40 pc 0x00000049a1b2 bp 0x7ffd5c3e19f0 sp 0x7ffd5c3e11a0
WRITE of size 121 at 0x7ffd5c3e1a40 thread T0
    #0 0x49a1b2 in __interceptor_strcpy (/w/bin+0x49a1b2)
    #1 0x4f8a1b in handle_set_command /w/src/main.c:37:5
    #2 0x4f8c10 in process_input /w/src/main.c:60:9
    #3 0x4f8e00 in main /w/src/main.c:80:5
    #4 0x7f0123 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29d90)
    #5 0x402030 in _start (/w/bin+0x402030)

Address 0x7ffd5c3e1a40 is located in stack of thread T0 at offset 96 in frame
    #0 0x4f8a1b in handle_set_command /w/src/main.c:37
"""

    def test_frame_parsing_and_runtime_filtering(self):
        parsed = frames(self.SAMPLE_ASAN_STDERR, source_root="/w")
        self.assertEqual(len(parsed), 6)

        # Frame 0 (__interceptor_strcpy) should be runtime
        self.assertEqual(parsed[0].function, "__interceptor_strcpy")
        self.assertTrue(parsed[0].runtime)

        # Frame 1 (handle_set_command) should be app frame
        self.assertEqual(parsed[1].function, "handle_set_command")
        self.assertEqual(parsed[1].file, "src/main.c")
        self.assertEqual(parsed[1].line, 37)
        self.assertFalse(parsed[1].runtime)

        # Frame 4 (__libc_start_main) should be runtime
        self.assertTrue(parsed[4].runtime)

    def test_signature_skips_runtime(self):
        parsed = frames(self.SAMPLE_ASAN_STDERR, source_root="/w")
        sig = signature(ErrorType.STACK_BUFFER_OVERFLOW, parsed)
        expected = "STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main"
        self.assertEqual(sig, expected)

    def test_prevent_allocated_by_leaking(self):
        """Frames after the first blank line / section header must not leak into signature."""
        uaf_stderr = """\
==3456==ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000040 pc 0x000000412345
READ of size 8 at 0x603000000040 thread T0
    #0 0x412345 in cJSON_Utils_MergePatch /w/src/cJSON_Utils.c:150:18
    #1 0x413456 in run_patch /w/src/main.c:55:10
    #2 0x414567 in main /w/src/main.c:88:5

0x603000000040 is located 0 bytes inside of 32-byte region
freed by thread T0 here:
    #0 0x423456 in free (/usr/lib/clang/libclang_rt.asan.so+0x423456)
    #1 0x412100 in cJSON_Delete /w/src/cJSON.c:200:5
"""
        parsed = frames(uaf_stderr, source_root="/w")
        fn_names = [f.function for f in parsed]
        self.assertEqual(fn_names, ["cJSON_Utils_MergePatch", "run_patch", "main"])
        self.assertNotIn("cJSON_Delete", fn_names)

    def test_fixture_files(self):
        """Verify all fixture files in tests/fixtures/stderr/ parse properly."""
        if not FIXTURES_DIR.exists():
            self.skipTest("Fixtures directory not found")

        for fpath in FIXTURES_DIR.glob("*.txt"):
            content = fpath.read_text(encoding="utf-8")
            res = analyse(stderr=content, sig="SIGABRT")
            self.assertEqual(res.outcome, Outcome.CRASH, f"Fixture {fpath.name} did not produce CRASH")
            self.assertIsNotNone(res.error_type, f"Fixture {fpath.name} error_type is None")


if __name__ == "__main__":
    unittest.main()
