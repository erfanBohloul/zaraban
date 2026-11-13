"""Subprocess runner with watchdogs and resource isolation (SPEC §5.3, §7.2, §7.3, §7.5).

Implements Phase 1 Member B Tasks B1 & B4:
- Runs a test against a target binary with strict CPU, memory, and timeout limits.
- Enforces input methods: file, stdin, args (§5.3).
- Constructs minimal execution environment with sanitizer flags (§7.2).
- Truncates output to 1 MB (§7.3).
- Coordinates crash analysis and oracle checking.
- Combines repeats and flags flakiness (§7.5).
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Sequence, Union

from . import analysis, oracle
from .models import (
    BuildName,
    CombinedResult,
    ErrorCode,
    InputInfo,
    InputMethod,
    LimitKind,
    Outcome,
    RunRecord,
    StreamInfo,
    TestCase,
    TestKind,
    ZarabanError,
)

try:
    import resource
except ImportError:
    resource = None  # type: ignore[assignment]

MAX_OUTPUT_BYTES = 1 << 20  # 1 MB (SPEC §7.3)


def _apply_limits(cpu_s: int, data_bytes: Optional[int]) -> Any:
    """Pre-exec hook to set kernel resource limits on child process."""
    def apply() -> None:
        if resource is None:
            return
        # RLIMIT_CPU: Kernel sends SIGXCPU when exceeded
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s))
        except (ValueError, OSError):
            pass

        # RLIMIT_CORE: Disable core dumps
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ValueError, OSError):
            pass

        # RLIMIT_DATA: Release builds only (Linux ELF)
        if data_bytes is not None and platform.system() == "Linux":
            try:
                if hasattr(resource, "RLIMIT_DATA"):
                    resource.setrlimit(resource.RLIMIT_DATA, (data_bytes, data_bytes))
            except (ValueError, OSError):
                pass

    return apply


def run_env(cfg: Any, sanitized: bool) -> dict[str, str]:
    """Construct minimal run environment (SPEC §7.2)."""
    env: dict[str, str] = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
    }

    # Add config-specified environment variables
    cfg_env = getattr(cfg, "env", {})
    if isinstance(cfg_env, dict):
        env.update(cfg_env)

    if sanitized:
        symbolizer = shutil.which("llvm-symbolizer") or "/usr/bin/llvm-symbolizer"
        mem_mb = getattr(getattr(cfg, "limits", None), "memory_limit_mb", 256)

        # On macOS Darwin, ASan symbolizer IPC can deadlock in sandboxed subshells;
        # adapt symbolize flag if symbolizer is missing.
        symbolize_flag = 1
        if platform.system() == "Darwin" and not shutil.which("llvm-symbolizer"):
            symbolize_flag = 0

        tool_asan = (
            f"abort_on_error=1:detect_leaks=0:symbolize={symbolize_flag}:"
            f"disable_coredump=1:max_allocation_size_mb={mem_mb}"
        )
        tool_ubsan = f"halt_on_error=1:abort_on_error=1:print_stacktrace=1:symbolize={symbolize_flag}"

        # If cfg sets options, append tool options so tool options win (§7.2)
        if "ASAN_OPTIONS" in env:
            env["ASAN_OPTIONS"] = f"{env['ASAN_OPTIONS']}:{tool_asan}"
        else:
            env["ASAN_OPTIONS"] = tool_asan

        if "UBSAN_OPTIONS" in env:
            env["UBSAN_OPTIONS"] = f"{env['UBSAN_OPTIONS']}:{tool_ubsan}"
        else:
            env["UBSAN_OPTIONS"] = tool_ubsan

        if os.path.exists(symbolizer):
            env["ASAN_SYMBOLIZER_PATH"] = symbolizer

    return env


def run_once(
    binary: Union[str, Path],
    test: Any,
    cfg: Any,
    sanitized: bool,
    run_dir: Path,
    build_name: BuildName = BuildName.BASE_RELEASE,
    repeat: int = 1,
    source_root: str = "",
) -> RunRecord:
    """Execute one test on one build inside a fresh working directory (§5.3, §7.2, §7.3)."""
    run_dir.mkdir(parents=True, exist_ok=True)

    input_method_val = getattr(cfg, "input_method", "stdin")
    if hasattr(input_method_val, "value"):
        input_method_val = input_method_val.value

    test_args = list(getattr(test, "args", []))
    cmd = [str(binary)] + test_args
    stdin_bytes = b""
    input_file_name: Optional[str] = None
    input_bytes = getattr(test, "input_bytes", None)
    if input_bytes is None:
        # Fallback if test has input_data as string
        raw_data = getattr(test, "input_data", None)
        if raw_data is not None:
            input_bytes = raw_data.encode("utf-8")

    if input_method_val == "file":
        ext = getattr(test, "input_ext", ".txt") or ".txt"
        input_file_name = "input" + ext
        input_file_path = run_dir / input_file_name
        input_file_path.write_bytes(input_bytes or b"")

        ph = getattr(cfg, "file_arg_placeholder", "{input_file}")
        if any(ph in a for a in cmd[1:]):
            cmd = [cmd[0]] + [a.replace(ph, input_file_name) for a in cmd[1:]]
        else:
            cmd.append(input_file_name)
    elif input_method_val == "stdin":
        stdin_bytes = input_bytes or b""
    elif input_method_val == "args":
        if input_bytes is not None:
            if b"\0" in input_bytes:
                raise ZarabanError(
                    ErrorCode.CONFIG_INVALID,
                    f"NUL byte in args input for test '{getattr(test, 'name', '')}'",
                    details={"test": getattr(test, "name", ""), "reason": "NUL in args input"},
                )
            cmd.append(input_bytes.decode("utf-8", errors="replace"))

    env = run_env(cfg, sanitized)

    timeout_s = 3.0
    mem_mb = 256
    if hasattr(cfg, "limits") and cfg.limits is not None:
        timeout_s = getattr(cfg.limits, "timeout_seconds", 3.0)
        mem_mb = getattr(cfg.limits, "memory_limit_mb", 256)

    cpu_s = int(timeout_s + 0.999) + 1
    data_bytes = None if sanitized else mem_mb * 1024 * 1024

    t0 = time.monotonic()
    timed_out = False
    limit_hit: Optional[LimitKind] = None

    try:
        p = subprocess.Popen(
            cmd,
            cwd=str(run_dir),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            preexec_fn=_apply_limits(cpu_s, data_bytes),
        )
        try:
            raw_out, raw_err = p.communicate(stdin_bytes, timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                pass
            raw_out, raw_err = p.communicate()
    except Exception as exc:
        raise ZarabanError(
            ErrorCode.TOOL_INTERNAL,
            f"Failed to spawn target process: {exc}",
            {"cmd": cmd, "error": str(exc)},
        )

    duration_s = time.monotonic() - t0
    rc = p.returncode

    sig_name: Optional[str] = None
    exit_code: Optional[int] = None
    if rc < 0:
        sig_name = signal.Signals(-rc).name
        exit_code = None
    else:
        sig_name = None
        exit_code = rc

    if sig_name == "SIGXCPU":
        limit_hit = LimitKind.CPU

    # Check for memory limit exceeded in sanitized build
    if sanitized and (b"allocator is terminating the process" in raw_err or b"allocation-size-too-big" in raw_err):
        limit_hit = LimitKind.MEMORY

    # Truncate outputs to 1 MB (§7.3)
    out_truncated = len(raw_out) > MAX_OUTPUT_BYTES
    err_truncated = len(raw_err) > MAX_OUTPUT_BYTES
    stdout_bytes = raw_out[:MAX_OUTPUT_BYTES]
    stderr_bytes = raw_err[:MAX_OUTPUT_BYTES]

    # Save stdout.txt and stderr.txt in the run directory (§12.3)
    (run_dir / "stdout.txt").write_bytes(stdout_bytes)
    (run_dir / "stderr.txt").write_bytes(stderr_bytes)

    stdout_str = stdout_bytes.decode("utf-8", errors="replace")
    stderr_str = stderr_bytes.decode("utf-8", errors="replace")

    # Run crash analysis (§7.4)
    run_analysis = analysis.analyse(
        stderr=stderr_str,
        stdout=stdout_str,
        exit_code=exit_code,
        sig=sig_name,
        timed_out=timed_out,
        limit_hit=limit_hit,
        source_root=source_root,
    )

    # Run oracle matching (§5.4)
    run_oracle = oracle.match(
        test=test,
        outcome=run_analysis.outcome,
        exit_code=exit_code,
        stdout=stdout_bytes,
    )

    # Prepare stream and input records
    inp_bytes = input_bytes or b""
    input_info = InputInfo(
        method=InputMethod(input_method_val) if hasattr(InputMethod, input_method_val.upper()) else InputMethod.STDIN,
        name=input_file_name,
        size=len(inp_bytes),
        sha256=hashlib.sha256(inp_bytes).hexdigest(),
    )

    stdout_info = StreamInfo(
        path="stdout.txt",
        bytes=len(stdout_bytes),
        sha256=hashlib.sha256(stdout_bytes).hexdigest(),
        truncated=out_truncated,
    )

    stderr_info = StreamInfo(
        path="stderr.txt",
        bytes=len(stderr_bytes),
        sha256=hashlib.sha256(stderr_bytes).hexdigest(),
        truncated=err_truncated,
    )

    test_kind = getattr(test, "kind", TestKind.VALID)
    if isinstance(test_kind, str):
        test_kind = TestKind(test_kind)

    return RunRecord(
        test=getattr(test, "name", "unknown"),
        kind=test_kind,
        build=build_name,
        repeat=repeat,
        cmd=cmd,
        env=env,
        cwd=str(run_dir),
        input=input_info,
        exit_code=exit_code,
        signal=sig_name,
        timed_out=timed_out,
        limit_hit=limit_hit,
        duration_s=duration_s,
        stdout=stdout_info,
        stderr=stderr_info,
        analysis=run_analysis,
        oracle=run_oracle,
    )


def combine(runs: list[RunRecord]) -> CombinedResult:
    """Combine repeats for one test on one build and check for flakiness (§7.5)."""
    if not runs:
        raise ValueError("Cannot combine an empty list of runs")

    # Flakiness rule: outcome, signature, or oracle result differs across repeats
    def key(r: RunRecord) -> tuple[Any, ...]:
        return (r.analysis.outcome, r.analysis.signature, r.oracle.passed)

    distinct_keys = {key(r) for r in runs}
    flaky = len(distinct_keys) > 1

    first = runs[0]
    return CombinedResult(
        test=first.test,
        kind=first.kind,
        build=first.build,
        runs=runs,
        flaky=flaky,
    )


class SafeRunner:
    """Convenience class providing backwards-compatible invocation for Phase 0 tests."""

    @classmethod
    def run(
        cls,
        cmd: Sequence[str],
        input_data: Optional[Union[str, bytes]] = None,
        timeout_seconds: float = 3.0,
        memory_limit_mb: int = 256,
        is_sanitized: bool = False,
        cwd: Optional[Union[str, Path]] = None,
    ) -> Any:
        """Run a command with resource watchdogs and return an ExecutionResult."""
        class DummyLimits:
            def __init__(self, t: float, m: int):
                self.timeout_seconds = t
                self.memory_limit_mb = m

        class DummyConfig:
            def __init__(self, t: float, m: int):
                self.input_method = "stdin"
                self.file_arg_placeholder = "{input_file}"
                self.limits = DummyLimits(t, m)
                self.env = {}

        class DummyTest:
            def __init__(self, raw: Optional[Union[str, bytes]]):
                self.name = "dummy"
                self.kind = TestKind.VALID
                self.args = list(cmd[1:])
                self.input_bytes = raw.encode() if isinstance(raw, str) else raw
                self.input_ext = ".txt"
                self.expected_exit_code = None
                self.expected_output = None

        cfg = DummyConfig(timeout_seconds, memory_limit_mb)
        test = DummyTest(input_data)
        run_dir = Path(cwd) if cwd else Path("/tmp/zaraban_run")
        run_dir.mkdir(parents=True, exist_ok=True)

        rec = run_once(
            binary=cmd[0],
            test=test,
            cfg=cfg,
            sanitized=is_sanitized,
            run_dir=run_dir,
            build_name=BuildName.PATCH_SANITIZED if is_sanitized else BuildName.PATCH_RELEASE,
        )

        @dataclass
        class ExecutionResultCompat:
            stdout: str
            stderr: str
            exit_code: int
            signal_num: Optional[int]
            signal_name: Optional[str]
            timed_out: bool
            cpu_limit_exceeded: bool
            memory_limit_exceeded: bool
            duration_seconds: float
            detection_mechanism: Optional[str]
            error_summary: Optional[str]

            @property
            def is_crash(self) -> bool:
                return self.signal_num is not None or self.signal_name is not None or "AddressSanitizer" in self.stderr or "runtime error:" in self.stderr or "***" in self.stderr

        sig_num = getattr(signal.Signals, rec.signal).value if rec.signal else None
        det_mech = rec.analysis.detection.value if rec.analysis.detection else (
            "ResourceLimit/Timeout" if rec.timed_out else None
        )

        return ExecutionResultCompat(
            stdout=rec.stdout.sha256 and run_dir.joinpath("stdout.txt").exists() and run_dir.joinpath("stdout.txt").read_text(errors="replace") or "",
            stderr=rec.stderr.sha256 and run_dir.joinpath("stderr.txt").exists() and run_dir.joinpath("stderr.txt").read_text(errors="replace") or "",
            exit_code=rec.exit_code if rec.exit_code is not None else -1,
            signal_num=sig_num,
            signal_name=rec.signal,
            timed_out=rec.timed_out,
            cpu_limit_exceeded=rec.limit_hit is LimitKind.CPU,
            memory_limit_exceeded=rec.limit_hit is LimitKind.MEMORY,
            duration_seconds=rec.duration_s,
            detection_mechanism=det_mech,
            error_summary=rec.analysis.summary,
        )
