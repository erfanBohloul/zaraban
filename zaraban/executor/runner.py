"""Execution runner with resource limits and crash detection."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import os
import signal
import subprocess
import time

try:
    import resource
except ImportError:
    resource = None  # Windows fallback if needed, but project target is Linux


@dataclass
class ExecutionResult:
    """Detailed result of a binary execution run."""
    stdout: str
    stderr: str
    exit_code: int
    signal_num: Optional[int] = None
    signal_name: Optional[str] = None
    timed_out: bool = False
    cpu_limit_exceeded: bool = False
    memory_limit_exceeded: bool = False
    peak_rss_kb: int = 0
    duration_seconds: float = 0.0
    detection_mechanism: Optional[str] = None
    error_summary: Optional[str] = None

    @property
    def is_crash(self) -> bool:
        """Determines if the termination represents an abnormal crash or signal."""
        if self.signal_num is not None:
            return True
        if "AddressSanitizer" in self.stderr or "UndefinedBehaviorSanitizer" in self.stderr:
            return True
        if "*** buffer overflow detected ***" in self.stderr or "__stack_chk_fail" in self.stderr:
            return True
        return False


class SafeRunner:
    """Executes target binaries with strict CPU, wall-clock, and memory limits."""

    @staticmethod
    def _get_signal_name(sig_num: int) -> str:
        try:
            return signal.Signals(sig_num).name
        except (ValueError, AttributeError):
            return f"SIG_{sig_num}"

    @classmethod
    def run(
        cls,
        cmd: list[str],
        input_data: Optional[str] = None,
        input_file: Optional[str] = None,
        timeout_seconds: float = 3.0,
        memory_limit_mb: int = 256,
        is_sanitized: bool = False,
        env: Optional[dict[str, str]] = None,
        cwd: Optional[str] = None
    ) -> ExecutionResult:
        """Execute a command under resource constraints."""
        start_time = time.perf_counter()
        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        # Configure sanitizer options if sanitized build
        if is_sanitized:
            run_env["ASAN_OPTIONS"] = run_env.get("ASAN_OPTIONS", "") + f":max_allocation_size_mb={memory_limit_mb}:abort_on_error=1:symbolize=1"
            run_env["UBSAN_OPTIONS"] = run_env.get("UBSAN_OPTIONS", "") + ":abort_on_error=1:symbolize=1:print_stacktrace=1"

        stdin_stream = None
        stdin_bytes = None
        if input_file and os.path.exists(input_file):
            with open(input_file, "rb") as f:
                stdin_bytes = f.read()
        elif input_data is not None:
            stdin_bytes = input_data.encode("utf-8")

        def preexec():
            # Put child process into a new process group so we can kill all sub-processes
            os.setsid()

            if resource is not None:
                # 1. Disable core dump generation to save disk space
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

                # 2. CPU time limit (soft limit = timeout + 1, hard limit = timeout + 2)
                cpu_limit = max(1, int(timeout_seconds) + 1)
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit + 1))

                # 3. Memory limit for non-sanitized builds
                # (Notice: DO NOT set RLIMIT_AS for ASan builds, as ASan reserves 16TB+ shadow space)
                if not is_sanitized:
                    mem_bytes = memory_limit_mb * 1024 * 1024
                    try:
                        resource.setrlimit(resource.RLIMIT_DATA, (mem_bytes, mem_bytes))
                    except (ValueError, OSError):
                        pass

        timed_out = False
        stdout_text = ""
        stderr_text = ""
        exit_code = 0
        sig_num = None
        sig_name = None
        cpu_exceeded = False
        peak_rss_kb = 0

        process = None
        try:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE if stdin_bytes is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=run_env,
                preexec_fn=preexec
            )

            raw_out, raw_err = process.communicate(input=stdin_bytes, timeout=timeout_seconds)
            stdout_text = raw_out.decode("utf-8", errors="replace")
            stderr_text = raw_err.decode("utf-8", errors="replace")
            exit_code = process.returncode

        except subprocess.TimeoutExpired:
            timed_out = True
            if process:
                try:
                    # Kill entire process group
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    raw_out, raw_err = process.communicate()
                    stdout_text = raw_out.decode("utf-8", errors="replace")
                    stderr_text = raw_err.decode("utf-8", errors="replace")
                except OSError:
                    pass
            exit_code = -signal.SIGKILL

        duration = time.perf_counter() - start_time

        # Analyze return code and signals
        if exit_code < 0:
            sig_num = -exit_code
            sig_name = cls._get_signal_name(sig_num)
            if sig_num == signal.SIGXCPU:
                cpu_exceeded = True

        # Detect detection mechanism
        detection_mechanism = None
        error_summary = None

        if timed_out:
            detection_mechanism = "ResourceLimit/Timeout"
            error_summary = f"Execution exceeded wall-clock limit ({timeout_seconds:.1f}s)"
        elif cpu_exceeded or sig_num == signal.SIGXCPU:
            detection_mechanism = "ResourceLimit/CPU"
            error_summary = "Execution exceeded CPU time limit (SIGXCPU)"
        elif "AddressSanitizer" in stderr_text:
            detection_mechanism = "Sanitizer/ASan"
            # Extract first line of ASan report
            for line in stderr_text.splitlines():
                if "ERROR: AddressSanitizer:" in line or "SUMMARY: AddressSanitizer:" in line:
                    error_summary = line.strip()
                    break
        elif "UndefinedBehaviorSanitizer" in stderr_text:
            detection_mechanism = "Sanitizer/UBSan"
            for line in stderr_text.splitlines():
                if "runtime error:" in line:
                    error_summary = line.strip()
                    break
        elif "*** buffer overflow detected ***" in stderr_text or "__stack_chk_fail" in stderr_text:
            detection_mechanism = "BinaryProtection/StackCanary"
            error_summary = "Stack canary corruption detected (__stack_chk_fail)"
        elif sig_num is not None:
            detection_mechanism = f"OS_Signal/{sig_name}"
            error_summary = f"Process terminated by signal {sig_name} (code {sig_num})"

        return ExecutionResult(
            stdout=stdout_text,
            stderr=stderr_text,
            exit_code=exit_code,
            signal_num=sig_num,
            signal_name=sig_name,
            timed_out=timed_out,
            cpu_limit_exceeded=cpu_exceeded,
            memory_limit_exceeded=False,  # updated via ASan / rusage checks
            peak_rss_kb=peak_rss_kb,
            duration_seconds=duration,
            detection_mechanism=detection_mechanism,
            error_summary=error_summary
        )
