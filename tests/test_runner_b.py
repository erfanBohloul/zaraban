"""Unit tests for zaraban/runner.py (Phase 1 Member B Tasks B1 & B4, SPEC §5.3, §7.2, §7.3, §7.5).

Tests subprocess execution, input methods (stdin, file, args), placeholder substitution,
timeouts, process group termination, 1 MB stream truncation, and repeat combination with flakiness detection.
"""

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from zaraban.models import (
    Analysis,
    BuildName,
    ErrorCode,
    InputMethod,
    LimitKind,
    OracleResult,
    Outcome,
    RunRecord,
    TestCase,
    TestKind,
    ZarabanError,
)
from zaraban.runner import (
    MAX_OUTPUT_BYTES,
    combine,
    run_env,
    run_once,
)


class DummyLimits:
    def __init__(self, timeout: float = 3.0, memory_mb: int = 256):
        self.timeout_seconds = timeout
        self.memory_limit_mb = memory_mb


class DummyConfig:
    def __init__(
        self,
        input_method: str = "stdin",
        placeholder: str = "{input_file}",
        timeout: float = 3.0,
        memory_mb: int = 256,
        env: dict[str, str] = None,
    ):
        self.input_method = input_method
        self.file_arg_placeholder = placeholder
        self.limits = DummyLimits(timeout, memory_mb)
        self.env = env or {}


class TestRunnerExecution(unittest.TestCase):
    def test_run_stdin(self):
        cfg = DummyConfig(input_method="stdin")
        test = TestCase(
            name="t_stdin",
            kind=TestKind.VALID,
            input_bytes=b"Hello Zaraban Stdin",
            expected_exit_code=0,
            expected_output="Hello Zaraban Stdin",
        )
        with TemporaryDirectory() as tmp_dir:
            rec = run_once(
                binary=sys.executable,
                test=test,
                cfg=cfg,
                sanitized=False,
                run_dir=Path(tmp_dir),
                build_name=BuildName.PATCH_RELEASE,
            )
            # Since python without script waits on stdin, let's pass a small python one-liner in args
            # Re-run with python -c "import sys; sys.stdout.write(sys.stdin.read())"
            test.args = ["-c", "import sys; sys.stdout.write(sys.stdin.read())"]
            rec = run_once(
                binary=sys.executable,
                test=test,
                cfg=cfg,
                sanitized=False,
                run_dir=Path(tmp_dir),
                build_name=BuildName.PATCH_RELEASE,
            )
            self.assertEqual(rec.exit_code, 0)
            self.assertEqual(rec.analysis.outcome, Outcome.NORMAL)
            self.assertTrue(rec.oracle.passed)
            self.assertEqual(rec.input.method, InputMethod.STDIN)
            self.assertEqual(rec.input.size, len(b"Hello Zaraban Stdin"))

    def test_run_file_with_placeholder(self):
        cfg = DummyConfig(input_method="file", placeholder="{input_file}")
        test = TestCase(
            name="t_file_ph",
            kind=TestKind.VALID,
            input_bytes=b"Payload from file",
            input_ext=".txt",
            args=["-c", "import sys; print(open(sys.argv[1]).read(), end='')", "{input_file}"],
            expected_exit_code=0,
            expected_output="Payload from file",
        )
        with TemporaryDirectory() as tmp_dir:
            rec = run_once(
                binary=sys.executable,
                test=test,
                cfg=cfg,
                sanitized=False,
                run_dir=Path(tmp_dir),
            )
            self.assertEqual(rec.exit_code, 0)
            self.assertTrue(rec.oracle.passed)
            self.assertEqual(rec.input.name, "input.txt")
            # Verify placeholder was replaced in cmd
            self.assertEqual(rec.cmd[-1], "input.txt")

    def test_run_file_append_when_no_placeholder(self):
        cfg = DummyConfig(input_method="file", placeholder="{placeholder_not_in_args}")
        test = TestCase(
            name="t_file_append",
            kind=TestKind.VALID,
            input_bytes=b"Appended file",
            input_ext=".json",
            args=["-c", "import sys; print(open(sys.argv[1]).read(), end='')"],
            expected_exit_code=0,
            expected_output="Appended file",
        )
        with TemporaryDirectory() as tmp_dir:
            rec = run_once(
                binary=sys.executable,
                test=test,
                cfg=cfg,
                sanitized=False,
                run_dir=Path(tmp_dir),
            )
            self.assertEqual(rec.exit_code, 0)
            self.assertEqual(rec.input.name, "input.json")
            self.assertEqual(rec.cmd[-1], "input.json")

    def test_run_args_method(self):
        cfg = DummyConfig(input_method="args")
        test = TestCase(
            name="t_args",
            kind=TestKind.VALID,
            input_bytes=b"custom_argument",
            args=["-c", "import sys; print(sys.argv[1], end='')"],
            expected_exit_code=0,
            expected_output="custom_argument",
        )
        with TemporaryDirectory() as tmp_dir:
            rec = run_once(
                binary=sys.executable,
                test=test,
                cfg=cfg,
                sanitized=False,
                run_dir=Path(tmp_dir),
            )
            self.assertEqual(rec.exit_code, 0)
            self.assertEqual(rec.cmd[-1], "custom_argument")
            self.assertTrue(rec.oracle.passed)

    def test_run_args_nul_byte_error(self):
        """SPEC §5.2, PHASES.md: NUL byte in args method must raise CONFIG_INVALID."""
        cfg = DummyConfig(input_method="args")
        test = TestCase(
            name="t_nul",
            kind=TestKind.VALID,
            input_bytes=b"arg\0with_nul",
        )
        with TemporaryDirectory() as tmp_dir:
            with self.assertRaises(ZarabanError) as ctx:
                run_once(
                    binary=sys.executable,
                    test=test,
                    cfg=cfg,
                    sanitized=False,
                    run_dir=Path(tmp_dir),
                )
            self.assertEqual(ctx.exception.code, ErrorCode.CONFIG_INVALID)

    def test_timeout_watchdog(self):
        """SPEC §7.3: Wall-clock limit kills process group and produces Outcome.TIMEOUT."""
        cfg = DummyConfig(timeout=0.4)
        test = TestCase(
            name="t_timeout",
            kind=TestKind.VALID,
            input_bytes=None,
            args=["-c", "import time; time.sleep(5)"],
        )
        with TemporaryDirectory() as tmp_dir:
            rec = run_once(
                binary=sys.executable,
                test=test,
                cfg=cfg,
                sanitized=False,
                run_dir=Path(tmp_dir),
            )
            self.assertTrue(rec.timed_out)
            self.assertEqual(rec.analysis.outcome, Outcome.TIMEOUT)
            self.assertFalse(rec.oracle.passed)

    def test_signal_handling(self):
        """SPEC §7.4: Fatal signals result in CRASH and SIGNAL detection."""
        cfg = DummyConfig()
        test = TestCase(
            name="t_sig",
            kind=TestKind.VALID,
            input_bytes=None,
            args=["-c", "import os, signal; os.kill(os.getpid(), signal.SIGSEGV)"],
        )
        with TemporaryDirectory() as tmp_dir:
            rec = run_once(
                binary=sys.executable,
                test=test,
                cfg=cfg,
                sanitized=False,
                run_dir=Path(tmp_dir),
            )
            self.assertEqual(rec.signal, "SIGSEGV")
            self.assertIsNone(rec.exit_code)
            self.assertEqual(rec.analysis.outcome, Outcome.CRASH)

    def test_output_truncation_to_1mb(self):
        """SPEC §7.3: Standard output/error truncated to 1 MB."""
        cfg = DummyConfig()
        # Output ~1.5 MB
        test = TestCase(
            name="t_trunc",
            kind=TestKind.VALID,
            input_bytes=None,
            args=["-c", "import sys; sys.stdout.write('X' * 1500000)"],
        )
        with TemporaryDirectory() as tmp_dir:
            rec = run_once(
                binary=sys.executable,
                test=test,
                cfg=cfg,
                sanitized=False,
                run_dir=Path(tmp_dir),
            )
            self.assertTrue(rec.stdout.truncated)
            self.assertEqual(rec.stdout.bytes, MAX_OUTPUT_BYTES)

    def test_run_env_construction(self):
        cfg = DummyConfig(env={"MY_CUSTOM_VAR": "val123"}, memory_mb=128)
        env_rel = run_env(cfg, sanitized=False)
        self.assertEqual(env_rel["MY_CUSTOM_VAR"], "val123")
        self.assertNotIn("ASAN_OPTIONS", env_rel)

        env_san = run_env(cfg, sanitized=True)
        self.assertIn("ASAN_OPTIONS", env_san)
        self.assertIn("max_allocation_size_mb=128", env_san["ASAN_OPTIONS"])
        self.assertIn("UBSAN_OPTIONS", env_san)


class TestRepeatsAndFlakiness(unittest.TestCase):
    """SPEC §7.5: Combining repeats and detecting flakiness."""

    def _make_dummy_record(self, repeat: int, outcome: Outcome, sig: str = None, passed: bool = True) -> RunRecord:
        ana = Analysis(outcome=outcome, signature=sig)
        ora = OracleResult(checked=True, passed=passed)
        inp = None
        return RunRecord(
            test="test_x",
            kind=TestKind.VALID,
            build=BuildName.PATCH_SANITIZED,
            repeat=repeat,
            cmd=["test"],
            env={},
            cwd="/tmp",
            input=None,
            exit_code=0 if outcome is Outcome.NORMAL else None,
            signal=None,
            timed_out=False,
            limit_hit=None,
            duration_s=0.1,
            stdout=None,
            stderr=None,
            analysis=ana,
            oracle=ora,
        )

    def test_combine_stable(self):
        runs = [
            self._make_dummy_record(1, Outcome.NORMAL, passed=True),
            self._make_dummy_record(2, Outcome.NORMAL, passed=True),
            self._make_dummy_record(3, Outcome.NORMAL, passed=True),
        ]
        comb = combine(runs)
        self.assertFalse(comb.flaky)
        self.assertEqual(comb.outcome, Outcome.NORMAL)
        self.assertTrue(comb.oracle_passed)

    def test_combine_flaky_outcome(self):
        runs = [
            self._make_dummy_record(1, Outcome.NORMAL, passed=True),
            self._make_dummy_record(2, Outcome.TIMEOUT, passed=False),
            self._make_dummy_record(3, Outcome.NORMAL, passed=True),
        ]
        comb = combine(runs)
        self.assertTrue(comb.flaky)

    def test_combine_flaky_signature(self):
        runs = [
            self._make_dummy_record(1, Outcome.CRASH, sig="SIG1", passed=False),
            self._make_dummy_record(2, Outcome.CRASH, sig="SIG2", passed=False),
        ]
        comb = combine(runs)
        self.assertTrue(comb.flaky)


if __name__ == "__main__":
    unittest.main()
