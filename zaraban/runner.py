"""Running a test on a build.

One run (:func:`run_once`):

* happens in a **fresh, empty working directory** that holds only the input
  file when ``input_method`` is ``file``. It is deleted afterwards;
* uses the agreed command: the build's binary, the test's ``args``, and the
  input as a file (``input<ext>``, or in place of the placeholder), on standard
  input, or as one extra argument, byte for byte;
* gets only ``PATH``, the config's ``env`` and, for sanitized builds, the
  sanitizer options set in :class:`RunSettings`;
* is limited: wall-clock timeout (the whole process group is
  killed), ``RLIMIT_CPU``, ``RLIMIT_DATA`` on release builds,
  ``max_allocation_size_mb`` on sanitized builds, no core dumps, and at most
  1 MB of each output stream kept;
* is analysed (:mod:`zaraban.analysis`) and judged against its oracle
  (:mod:`zaraban.oracle`), and written to
  ``runs/<test>/<build>/<n>.json``, ``<n>.stdout`` and ``<n>.stderr``.

:func:`run_test` runs the repeats of one test on one build and combines them
(:func:`combine`).
"""

from __future__ import annotations

import hashlib
import os
import resource
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from . import analysis, oracle
from .config import Target
from .models import (
    BuildName,
    CombinedResult,
    ErrorCode,
    InputInfo,
    InputMethod,
    Issue,
    LimitKind,
    Profile,
    RunRecord,
    StreamInfo,
    TestCase,
    WarningCode,
    ZarabanError,
    dump_json,
)
from .util import kill_group

MAX_OUTPUT_BYTES = 1 << 20  # 1 MB per stream

def _find_symbolizer() -> Optional[str]:
    found = shutil.which("llvm-symbolizer")
    if found:
        return found
    for n in range(20, 10, -1):  # versioned names, newest first
        found = shutil.which(f"llvm-symbolizer-{n}")
        if found:
            return found
    return None


@dataclass
class RunSettings:
    """The run settings of a target, in one place.

    Build it from a loaded config with :meth:`from_target`, so the config's
    ``env`` and ``limits`` are always the ones used.
    """

    input_method: InputMethod = InputMethod.STDIN
    file_arg_placeholder: str = "{input_file}"
    env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 3.0
    memory_limit_mb: int = 256
    symbolizer: Optional[str] = field(default_factory=_find_symbolizer)
    path: str = field(default_factory=lambda: os.environ.get("PATH", "/usr/bin:/bin"))

    @classmethod
    def from_target(cls, target: Target) -> "RunSettings":
        """From a loaded :class:`zaraban.config.Target`."""
        spec = target.spec
        return cls(
            input_method=InputMethod(spec.input_method),
            file_arg_placeholder=spec.file_arg_placeholder,
            env=dict(spec.env),
            timeout_seconds=float(spec.limits.timeout_seconds),
            memory_limit_mb=int(spec.limits.memory_limit_mb),
        )

    @property
    def cpu_seconds(self) -> int:
        """``RLIMIT_CPU``: the timeout rounded up, plus 1 second."""
        return int(-(-self.timeout_seconds // 1)) + 1

    def env_for(self, sanitized: bool) -> dict[str, str]:
        """The run environment: ``PATH``, the config's ``env`` and, for
        sanitized builds, the tool's sanitizer options, appended after any the
        config sets so that the tool's values win."""
        env = {"PATH": self.path, **self.env}
        if not sanitized:
            return env
        asan = ("abort_on_error=1:detect_leaks=0:symbolize=1:disable_coredump=1:"
                f"max_allocation_size_mb={self.memory_limit_mb}")
        ubsan = "halt_on_error=1:abort_on_error=1:print_stacktrace=1:symbolize=1"
        env["ASAN_OPTIONS"] = f"{env['ASAN_OPTIONS']}:{asan}" if env.get("ASAN_OPTIONS") else asan
        env["UBSAN_OPTIONS"] = (f"{env['UBSAN_OPTIONS']}:{ubsan}" if env.get("UBSAN_OPTIONS")
                                else ubsan)
        if self.symbolizer:
            env["ASAN_SYMBOLIZER_PATH"] = self.symbolizer
        return env

    def warnings(self) -> list[Issue]:
        """``NO_SYMBOLIZER`` when ``llvm-symbolizer`` was not found."""
        if self.symbolizer:
            return []
        return [Issue(WarningCode.NO_SYMBOLIZER.value,
                      "llvm-symbolizer was not found, so sanitizer stack traces have no "
                      "function names and crashes cannot be told apart; install LLVM or "
                      "run the tool in its Docker image", {})]


# ---------------------------------------------------------------------------
# One run
# ---------------------------------------------------------------------------


def run_once(
    binary: str | Path,
    test: TestCase,
    settings: RunSettings,
    build: BuildName,
    repeat: int,
    out_dir: str | Path,
    source_root: str = "",
) -> RunRecord:
    """Run ``test`` once on ``build`` and write its files under ``out_dir``
    (the run's output directory). ``source_root`` is the build's source
    tree; frame paths under it are made relative."""
    out_dir = Path(out_dir)
    rel_dir = f"runs/{test.name}/{build.value}"
    record_dir = out_dir / rel_dir
    record_dir.mkdir(parents=True, exist_ok=True)
    sanitized = build.profile is Profile.SANITIZED
    data = test.input_bytes

    exe = str(Path(binary).resolve())
    args = list(test.args)
    shown = list(test.args)  # the command as recorded in JSON
    stdin_bytes = b""
    input_name: Optional[str] = None
    method = settings.input_method

    if method is InputMethod.FILE:
        input_name = "input" + (test.input_ext or "")
        ph = settings.file_arg_placeholder
        if any(ph in a for a in args):
            args = [a.replace(ph, input_name) for a in args]
            shown = list(args)
        else:
            args.append(input_name)
            shown.append(input_name)
    elif method is InputMethod.STDIN:
        stdin_bytes = data or b""
    elif data is not None:  # args
        if b"\0" in data:
            raise ZarabanError(ErrorCode.CONFIG_INVALID,
                               f"test {test.name}: input_method is 'args', so the input is "
                               "passed as a command-line argument and cannot contain a NUL "
                               "byte", {"test": test.name})
        args.append(os.fsdecode(data))  # passed to the program byte for byte
        shown.append(data.decode("utf-8", errors="backslashreplace"))

    env = settings.env_for(sanitized)
    cwd = tempfile.mkdtemp(prefix="zaraban-run-")
    try:
        if input_name is not None:
            Path(cwd, input_name).write_bytes(data or b"")
        res = _execute([exe, *args], cwd, env, stdin_bytes, settings.timeout_seconds,
                       settings.cpu_seconds,
                       None if sanitized else settings.memory_limit_mb * 1024 * 1024)
    finally:
        shutil.rmtree(cwd, ignore_errors=True)

    rc = res.returncode
    sig = _signal_name(-rc) if rc < 0 else None
    exit_code = None if rc < 0 else rc

    stderr_text = res.stderr.decode("utf-8", errors="replace")
    limit_hit: Optional[LimitKind] = None
    if not res.timed_out:
        if sig == "SIGXCPU" or (sig == "SIGKILL" and res.cpu_s >= settings.cpu_seconds):
            limit_hit = LimitKind.CPU  # SIGKILL: the hard CPU limit, 1 s after SIGXCPU
        elif sanitized and analysis.is_memory_limit(stderr_text):
            limit_hit = LimitKind.MEMORY

    n = repeat
    (record_dir / f"{n}.stdout").write_bytes(res.stdout)
    (record_dir / f"{n}.stderr").write_bytes(res.stderr)

    run_analysis = analysis.analyse(
        stderr=stderr_text,
        exit_code=exit_code, sig=sig, timed_out=res.timed_out, limit_hit=limit_hit,
        source_root=source_root)
    run_oracle = oracle.match(test=test, outcome=run_analysis.outcome, exit_code=exit_code,
                              stdout=res.stdout)

    record = RunRecord(
        test=test.name, kind=test.kind, build=build, repeat=repeat,
        cmd=[exe, *shown], env=env, cwd=cwd,
        input=InputInfo(method=method, name=input_name, size=len(data or b""),
                        sha256=hashlib.sha256(data or b"").hexdigest()),
        exit_code=exit_code, signal=sig, timed_out=res.timed_out, limit_hit=limit_hit,
        duration_s=round(res.duration_s, 4),
        stdout=_stream(f"{rel_dir}/{n}.stdout", res.stdout, res.stdout_truncated),
        stderr=_stream(f"{rel_dir}/{n}.stderr", res.stderr, res.stderr_truncated),
        analysis=run_analysis, oracle=run_oracle,
    )
    dump_json(record, record_dir / f"{n}.json")
    return record


def run_test(
    binary: str | Path,
    test: TestCase,
    settings: RunSettings,
    build: BuildName,
    repeats: int,
    out_dir: str | Path,
    source_root: str = "",
) -> CombinedResult:
    """Run the repeats 1 … ``repeats`` of one test on one build, one at a time,
    and combine them."""
    runs = [run_once(binary, test, settings, build, n, out_dir, source_root)
            for n in range(1, repeats + 1)]
    return combine(runs)


def combine(runs: list[RunRecord]) -> CombinedResult:
    """Combine the repeats of one test on one build. The result is flaky
    when the repeats differ in outcome, signature or oracle result."""
    if not runs:
        raise ValueError("cannot combine an empty list of runs")
    keys = {(r.analysis.outcome, r.analysis.signature, r.oracle.passed) for r in runs}
    first = runs[0]
    return CombinedResult(test=first.test, kind=first.kind, build=first.build, runs=runs,
                          flaky=len(keys) > 1)


def output_warnings(records: list[RunRecord]) -> list[Issue]:
    """``OUTPUT_TRUNCATED`` for each run whose output was cut at 1 MB."""
    out = []
    for r in records:
        for stream in (r.stdout, r.stderr):
            if stream.truncated:
                out.append(Issue(WarningCode.OUTPUT_TRUNCATED.value,
                                 f"{r.test} on {r.build.value}, repeat {r.repeat}: the "
                                 "output was longer than 1 MB and only its first 1 MB was "
                                 "kept", {"path": stream.path}))
    return out


# ---------------------------------------------------------------------------
# Process handling
# ---------------------------------------------------------------------------


@dataclass
class _Result:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    duration_s: float
    cpu_s: float


class _Capture(threading.Thread):
    """Reads a pipe to its end, keeping the first ``limit`` bytes. The
    rest is read and discarded, so the program never blocks on a full pipe and
    the tool never holds more than 1 MB."""

    def __init__(self, pipe: Any, limit: int = MAX_OUTPUT_BYTES):
        super().__init__(daemon=True)
        self.pipe, self.limit = pipe, limit
        self.chunks: list[bytes] = []
        self.kept = 0
        self.truncated = False

    def run(self) -> None:
        try:
            while True:
                chunk = self.pipe.read1(65536) if hasattr(self.pipe, "read1") \
                    else self.pipe.read(65536)
                if not chunk:
                    break
                room = self.limit - self.kept
                if room > 0:
                    self.chunks.append(chunk[:room])
                    self.kept += min(room, len(chunk))
                if len(chunk) > room:
                    self.truncated = True
        except (OSError, ValueError):
            pass

    @property
    def data(self) -> bytes:
        return b"".join(self.chunks)


def _feed(pipe: Any, data: bytes) -> None:
    try:
        if data:
            pipe.write(data)
    except (BrokenPipeError, OSError):
        pass
    finally:
        try:
            pipe.close()  # the program sees end-of-file
        except OSError:
            pass


def _limits(cpu_s: int, data_bytes: Optional[int]) -> Any:
    def apply() -> None:
        # Soft limit -> SIGXCPU; the hard limit one second later -> SIGKILL.
        # (With soft == hard the kernel sends SIGKILL straight away.)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s + 1))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if data_bytes is not None:  # release builds only
            resource.setrlimit(resource.RLIMIT_DATA, (data_bytes, data_bytes))
    return apply


def _execute(cmd: list[str], cwd: str, env: dict[str, str], stdin_bytes: bytes,
             timeout_s: float, cpu_s: int, data_bytes: Optional[int]) -> _Result:
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    t0 = time.monotonic()
    try:
        p = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True, preexec_fn=_limits(cpu_s, data_bytes))
    except OSError as exc:
        raise ZarabanError(ErrorCode.TOOL_INTERNAL, f"could not start {cmd[0]}: {exc}",
                           {"cmd": cmd, "error": str(exc)}) from exc

    out, err = _Capture(p.stdout), _Capture(p.stderr)
    feeder = threading.Thread(target=_feed, args=(p.stdin, stdin_bytes), daemon=True)
    for t in (out, err, feeder):
        t.start()

    timed_out = False
    try:
        p.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_group(p.pid)
        p.wait()
    duration = time.monotonic() - t0
    kill_group(p.pid)  # children left in the process group die with the program
    for t in (out, err, feeder):
        t.join(timeout=5)
    for pipe in (p.stdout, p.stderr):
        try:
            pipe.close()
        except OSError:
            pass

    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = (after.ru_utime + after.ru_stime) - (before.ru_utime + before.ru_stime)
    return _Result(p.returncode, out.data, err.data, out.truncated, err.truncated,
                   timed_out, duration, cpu)


def _signal_name(num: int) -> str:
    try:
        return signal.Signals(num).name
    except ValueError:
        return f"SIG{num}"


def _stream(path: str, data: bytes, truncated: bool) -> StreamInfo:
    return StreamInfo(path=path, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                      truncated=truncated)
