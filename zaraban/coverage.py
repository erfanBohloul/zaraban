"""Execution trace via clang source-based coverage (SPEC §9.4, Phase 2 Task 2.2).

For a finding whose crash stack gives no location evidence, and for every
``FUNCTIONAL_REGRESSION`` (which has no crash at all), the linker needs to know
*which changed lines the input actually executed*. This module answers that:

1. build one extra coverage binary of the relevant version with the config's
   ``build.coverage_cmd`` (``clang -O0 -g -fprofile-instr-generate
   -fcoverage-mapping``), in its own fresh copy ``work/<label>/``;
2. run the finding's test once on it, with ``LLVM_PROFILE_FILE`` pointing into
   the run directory;
3. read the executed lines with ``llvm-profdata merge`` + ``llvm-cov export``;
4. keep the changed lines of that side that ran (hit count > 0).

If the config has no ``coverage_cmd``, or the coverage build / run / export
fails, no trace is made: the result is unavailable and carries the warning
``TRACE_UNAVAILABLE`` (§9.4), and the link falls back to its other evidence.

The three heavy steps (build, run, export) are injectable, so the parsing and
intersection logic is unit-tested without a compiler or LLVM.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .models import InputMethod, Issue, TestCase, WarningCode

# Minimal, identical build/run environment, as in §3.3 / §6.2.
MIN_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "LANG": "C"}
BUILD_TIMEOUT_S = 300


# ---------------------------------------------------------------------------
# Result and the inputs the trace needs
# ---------------------------------------------------------------------------


@dataclass
class TraceResult:
    """The outcome of one execution trace."""

    available: bool                                  # a trace was actually made
    executed_changed_lines: list[int] = field(default_factory=list)   # flat, sorted (for the Link)
    per_file: dict[str, list[int]] = field(default_factory=dict)      # file -> executed changed lines
    warning: Optional[Issue] = None                  # TRACE_UNAVAILABLE when not available


@dataclass
class RunSpec:
    """Everything the coverage run needs from the target config (§5.3, §7.2)."""

    binary_rel: str                                  # build.binary_path, relative to the tree
    input_method: InputMethod
    file_arg_placeholder: str = "{input_file}"
    env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 3.0

    @classmethod
    def from_target(cls, target) -> "RunSpec":
        s = target.spec
        return cls(
            binary_rel=s.build.binary_path,
            input_method=InputMethod(s.input_method),
            file_arg_placeholder=s.file_arg_placeholder,
            env=dict(s.env),
            timeout_seconds=s.limits.timeout_seconds,
        )


# Injectable steps: (version_tree, coverage_cmd, dest, binary_rel) -> binary | None
BuildCoverage = Callable[[Path, str, Path, str], Optional[Path]]
# (binary, test, spec, profraw, run_dir) -> did the run produce a profile?
RunProfile = Callable[[Path, TestCase, RunSpec, Path, Path], bool]
# (binary, profraw, tmp_dir) -> lcov text | None
ExportLcov = Callable[[Path, Path, Path], Optional[str]]


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def trace(
    version_tree: str | Path,
    coverage_cmd: Optional[str],
    test: TestCase,
    changed: dict[str, set[int]],
    work_dir: str | Path,
    spec: RunSpec,
    *,
    label: str = "coverage",
    build: BuildCoverage = None,          # defaults filled below (keeps them overridable in tests)
    run: RunProfile = None,
    export: ExportLcov = None,
) -> TraceResult:
    """Make an execution trace and return the changed lines that executed.

    ``changed`` maps a source path (as it appears in the diff, e.g. ``src/main.c``)
    to the set of changed line numbers on the relevant side (added lines on the
    patch side, removed lines on the base side, §9.4).
    """
    build = build or build_coverage
    run = run or run_for_profile
    export = export or export_lcov

    if not coverage_cmd:
        return TraceResult(False, warning=_unavailable("the config has no coverage_cmd"))

    dest = Path(work_dir) / label
    binary = build(Path(version_tree), coverage_cmd, dest, spec.binary_rel)
    if binary is None:
        return TraceResult(False, warning=_unavailable("the coverage build failed"))

    run_dir = dest / "trace-run"
    profraw = run_dir / "trace.profraw"
    if not run(binary, test, spec, profraw, run_dir) or not profraw.exists():
        return TraceResult(False, warning=_unavailable("the coverage run produced no profile"))

    lcov = export(binary, profraw, dest)
    if lcov is None:
        return TraceResult(False, warning=_unavailable("llvm-profdata/llvm-cov failed"))

    coverage = parse_lcov(lcov)
    per_file = select_executed(coverage, changed)
    flat = sorted({ln for lines in per_file.values() for ln in lines})
    # A trace that ran but touched no changed line is still "available": the link
    # simply stays without CHANGED_CODE_EXECUTED. No warning in that case (§9.4).
    return TraceResult(True, executed_changed_lines=flat, per_file=per_file)


def run_trace(target, version_tree, test, changed, work_dir, *, label="coverage") -> TraceResult:
    """Convenience wrapper for the linker: pulls the RunSpec from the target."""
    return trace(version_tree, target.spec.build.coverage_cmd, test, changed, work_dir,
                 RunSpec.from_target(target), label=label)


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested directly)
# ---------------------------------------------------------------------------


def parse_lcov(text: str) -> dict[str, dict[int, int]]:
    """Parse an ``llvm-cov export -format=lcov`` dump into {file: {line: hits}}.

    Only ``SF:`` (source file) and ``DA:<line>,<count>`` records are used.
    """
    result: dict[str, dict[int, int]] = {}
    current: Optional[str] = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("SF:"):
            current = line[3:]
            result.setdefault(current, {})
        elif line.startswith("DA:") and current is not None:
            parts = line[3:].split(",")
            if len(parts) >= 2:
                try:
                    ln, cnt = int(parts[0]), int(parts[1])
                except ValueError:
                    continue
                result[current][ln] = max(result[current].get(ln, 0), cnt)
        elif line == "end_of_record":
            current = None
    return result


def select_executed(
    coverage: dict[str, dict[int, int]],
    changed: dict[str, set[int]],
) -> dict[str, list[int]]:
    """Changed lines (per file) that executed at least once.

    ``coverage`` keys are the absolute paths llvm-cov prints (inside the build
    copy); ``changed`` keys are diff-relative (``src/main.c``). A coverage path
    matches a changed file when it equals it or ends with ``/<changed path>``.
    """
    out: dict[str, list[int]] = {}
    for rel, lines in changed.items():
        hit: set[int] = set()
        for cov_path, counts in coverage.items():
            if _path_matches(cov_path, rel):
                hit |= {ln for ln in lines if counts.get(ln, 0) > 0}
        if hit:
            out[rel] = sorted(hit)
    return out


def _path_matches(cov_path: str, rel: str) -> bool:
    cov_path = cov_path.replace("\\", "/")
    rel = rel.replace("\\", "/").lstrip("/")
    return cov_path == rel or cov_path.endswith("/" + rel)


def _unavailable(reason: str) -> Issue:
    return Issue(
        WarningCode.TRACE_UNAVAILABLE.value,
        f"no execution trace could be made: {reason}",
        {"reason": reason},
    )


# ---------------------------------------------------------------------------
# Default (real) steps: build, run, export. Each returns None/False on failure
# so the trace degrades to TRACE_UNAVAILABLE instead of raising.
# ---------------------------------------------------------------------------


def build_coverage(version_tree: Path, coverage_cmd: str, dest: Path, binary_rel: str) -> Optional[Path]:
    """Copy the version tree and run the coverage build command (§6.2 style)."""
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(version_tree, dest, ignore=shutil.ignore_patterns(".git", "out"))
    log = dest / "coverage-build.log"
    try:
        with open(log, "wb") as fh:
            r = subprocess.run(["sh", "-c", coverage_cmd], cwd=dest, env=MIN_ENV,
                               stdout=fh, stderr=subprocess.STDOUT, timeout=BUILD_TIMEOUT_S)
    except (subprocess.TimeoutExpired, OSError):
        return None
    binary = dest / binary_rel
    if r.returncode != 0 or not binary.exists():
        return None
    return binary


def run_for_profile(binary: Path, test: TestCase, spec: RunSpec, profraw: Path, run_dir: Path) -> bool:
    """Run the test once on the coverage binary with LLVM_PROFILE_FILE set (§5.3)."""
    run_dir = Path(run_dir)
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    profraw = Path(profraw)
    profraw.parent.mkdir(parents=True, exist_ok=True)

    cmd = [str(binary)] + list(test.args)
    data = test.input_bytes or b""
    stdin_bytes = b""
    if spec.input_method is InputMethod.FILE:
        name = "input" + (test.input_ext or "")
        (run_dir / name).write_bytes(data)
        ph = spec.file_arg_placeholder
        if any(ph in a for a in cmd[1:]):
            cmd = [cmd[0]] + [a.replace(ph, name) for a in cmd[1:]]
        else:
            cmd.append(name)
    elif spec.input_method is InputMethod.STDIN:
        stdin_bytes = data
    elif spec.input_method is InputMethod.ARGS and test.input_bytes is not None:
        cmd.append(data.decode("utf-8", "surrogateescape"))

    env = dict(MIN_ENV)
    env.update(spec.env)
    env["LLVM_PROFILE_FILE"] = str(profraw)          # the tool's value wins
    try:
        subprocess.run(cmd, cwd=run_dir, env=env, input=stdin_bytes,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=spec.timeout_seconds)
    except subprocess.TimeoutExpired:
        pass        # a timeout may still have flushed a partial profile
    except OSError:
        return False
    return profraw.exists()


def export_lcov(binary: Path, profraw: Path, tmp: Path) -> Optional[str]:
    """Merge the raw profile and export executed lines as lcov text."""
    profdata = Path(tmp) / "trace.profdata"
    try:
        m = subprocess.run(["llvm-profdata", "merge", "-sparse", str(profraw), "-o", str(profdata)],
                           capture_output=True, timeout=60)
        if m.returncode != 0:
            return None
        e = subprocess.run(["llvm-cov", "export", str(binary),
                            f"-instr-profile={profdata}", "-format=lcov"],
                           capture_output=True, text=True, timeout=60)
        if e.returncode != 0:
            return None
        return e.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
