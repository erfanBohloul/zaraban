"""Unit tests for Zaraban's SafeRunner and resource watchdogs."""

import pytest
import sys
from zaraban.executor.runner import SafeRunner


def test_normal_execution():
    res = SafeRunner.run(["echo", "Zaraban Test"], timeout_seconds=2.0)
    assert res.exit_code == 0
    assert "Zaraban Test" in res.stdout
    assert not res.timed_out
    assert not res.is_crash


def test_timeout_watchdog():
    # Attempting to sleep for 5 seconds with a 0.5s timeout limit
    res = SafeRunner.run(["sleep", "5"], timeout_seconds=0.5)
    assert res.timed_out
    assert res.is_crash
    assert res.detection_mechanism == "ResourceLimit/Timeout"
    assert res.duration_seconds < 2.0


def test_stdin_feeding():
    res = SafeRunner.run(["cat"], input_data="Security Test Input\n", timeout_seconds=1.0)
    assert res.exit_code == 0
    assert "Security Test Input" in res.stdout


def test_signal_handling():
    # Run a command that raises SIGSEGV via python or bash
    res = SafeRunner.run(
        [sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGSEGV)"],
        timeout_seconds=2.0
    )
    assert res.is_crash
    assert res.signal_name == "SIGSEGV"
    assert res.signal_num == 11


def test_target_asan_crash_detection(tmp_path):
    # Compile sanitized token_parser
    compile_res = SafeRunner.run([
        "clang",
        "-fsanitize=address,undefined",
        "-g",
        "-O1",
        "-o",
        "/tmp/test_token_parser",
        "targets/target1_sample/src/main.c"
    ])
    assert compile_res.exit_code == 0

    # Execute with exploit input
    run_res = SafeRunner.run(
        ["/tmp/test_token_parser", "targets/target1_sample/tests/exploits/exploit_primary.txt"],
        is_sanitized=True,
        timeout_seconds=2.0
    )
    assert run_res.is_crash
    assert run_res.detection_mechanism == "Sanitizer/ASan"
    assert "stack-buffer-overflow" in run_res.stderr

    # Execute with valid input
    valid_res = SafeRunner.run(
        ["/tmp/test_token_parser", "targets/target1_sample/tests/valid/valid_1_ping.txt"],
        is_sanitized=True,
        timeout_seconds=2.0
    )
    assert not valid_res.is_crash
    assert valid_res.exit_code == 0
    assert "PONG" in valid_res.stdout
