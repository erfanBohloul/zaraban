"""Execution trace via clang source-based coverage.

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
``TRACE_UNAVAILABLE``, and the link falls back to its other evidence.

The three heavy steps (build, run, export) are injectable, so the parsing and
intersection logic is unit-tested without a compiler or LLVM.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from . import builder, runner
from .models import InputMethod, Issue, LinkLevel, TestCase, Version, WarningCode, ZarabanError


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
    """Everything the coverage run needs from the target config."""

    binary_rel: str                                  # build.binary_path, relative to the tree
    input_method: InputMethod
    file_arg_placeholder: str = "{input_file}"
    env: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 3.0
    memory_limit_mb: int = 256

    @classmethod
    def from_target(cls, target) -> "RunSpec":
        s = target.spec
        return cls(
            binary_rel=s.build.binary_path,
            input_method=InputMethod(s.input_method),
            file_arg_placeholder=s.file_arg_placeholder,
            env=dict(s.env),
            timeout_seconds=s.limits.timeout_seconds,
            memory_limit_mb=s.limits.memory_limit_mb,
        )

    def run_settings(self) -> runner.RunSettings:
        """The runner's settings for these values, so the coverage run gets the
        same environment and limits as the normal runs."""
        return runner.RunSettings(
            input_method=self.input_method, file_arg_placeholder=self.file_arg_placeholder,
            env=dict(self.env), timeout_seconds=float(self.timeout_seconds),
            memory_limit_mb=int(self.memory_limit_mb), symbolizer=None)


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
    patch side, removed lines on the base side).
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
    # simply stays without CHANGED_CODE_EXECUTED. No warning in that case.
    return TraceResult(True, executed_changed_lines=flat, per_file=per_file)


def run_trace(target, version_tree, test, changed, work_dir, *, label="coverage") -> TraceResult:
    """Convenience wrapper for the linker: pulls the RunSpec from the target.

    A target without ``build.coverage_cmd`` gives an unavailable trace (with
    ``TRACE_UNAVAILABLE``) before anything else is read from its config.
    """
    build_spec = getattr(getattr(target, "spec", None), "build", None)
    coverage_cmd = getattr(build_spec, "coverage_cmd", None)
    if not coverage_cmd:
        return TraceResult(False, warning=_unavailable("the config has no coverage_cmd"))
    return trace(version_tree, coverage_cmd, test, changed, work_dir,
                 RunSpec.from_target(target), label=label)


# ---------------------------------------------------------------------------
# Producing the traces for linking
# ---------------------------------------------------------------------------


def execution_traces(
    findings,
    tests_by_name: dict[str, TestCase],
    changed_by_side: dict[Version, dict[str, set[int]]],  # from diffinfo.changed_lines_by_file
    version_trees: dict[Version, Path],                   # sources.base_tree / .patch_tree
    target,
    work_dir,
    *,
    trace_fn: Optional[Callable] = None,
) -> tuple[dict[str, list[int]], list[Issue]]:
    """Make an execution trace for each finding whose stack gave no location
    evidence, and return the data ``linking.link_findings`` consumes.

    Run this **after** a first ``link_findings`` pass: a finding needs a trace
    exactly when its link came out ``UNDETERMINED`` but has a side — that covers
    both a crash finding whose frames matched nothing and a
    ``FUNCTIONAL_REGRESSION`` (which has no crash stack at all).

    Returns ``(traces, warnings)``: ``traces`` maps a finding id to the changed
    lines its test executed, to pass as ``link_findings(..., traces=traces)``
    for a second pass. A finding whose trace could not be made is absent from
    ``traces`` (so its link stays ``UNDETERMINED``) and adds a
    ``TRACE_UNAVAILABLE`` warning.
    """
    trace_fn = trace_fn or run_trace     # looked up at call time, so tests can patch it
    traces: dict[str, list[int]] = {}
    warnings: list[Issue] = []
    for finding in findings:
        link = getattr(finding, "link", None)
        if link is None or link.level is not LinkLevel.UNDETERMINED or link.side is None:
            continue
        test = _representative_test(finding, tests_by_name)
        changed = changed_by_side.get(link.side) or {}
        tree = version_trees.get(link.side)
        if test is None or not changed or tree is None:
            continue
        # its own copy work/<version>-coverage/, next to the four builds
        result = trace_fn(target, tree, test, changed, work_dir,
                          label=f"{link.side.value}-coverage")
        if result.available:
            traces[finding.id] = result.executed_changed_lines
        # one warning per distinct reason, not one per finding
        if result.warning is not None and all(w.message != result.warning.message for w in warnings):
            warnings.append(result.warning)
    return traces, warnings


def _representative_test(finding, tests_by_name: dict[str, TestCase]) -> Optional[TestCase]:
    """The finding's test to trace: its first comparative test, else its first."""
    link = getattr(finding, "link", None)
    name: Optional[str] = None
    if link is not None and getattr(link, "comparative_tests", None):
        name = link.comparative_tests[0]
    elif finding.tests:
        name = finding.tests[0].test
    return tests_by_name.get(name) if name else None


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
    """Copy the version tree and run the coverage build command, exactly like
    the four builds: the same minimal environment, timeout and process-group
    kill (``builder._run_step``)."""
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(version_tree, dest, ignore=shutil.ignore_patterns(".git", "out"))
    log = dest / "coverage-build.log"
    try:
        with open(log, "wb") as fh:
            code = builder._run_step(coverage_cmd, dest, fh)
    except OSError:
        return None
    binary = dest / binary_rel
    if code != 0 or not binary.exists():
        return None
    return binary


def run_for_profile(binary: Path, test: TestCase, spec: RunSpec, profraw: Path, run_dir: Path) -> bool:
    """Run the test once on the coverage binary with ``LLVM_PROFILE_FILE`` set.

    The input, environment and limits are those of a normal release run:
    the runner's environment and its timeout, CPU and memory
    limits, with the whole process group killed at the end."""
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

    settings = spec.run_settings()
    env = settings.env_for(False)
    env["LLVM_PROFILE_FILE"] = str(profraw.resolve())   # the tool's value wins
    try:
        runner._execute([str(Path(binary).resolve()), *cmd[1:]], str(run_dir), env,
                        stdin_bytes, settings.timeout_seconds, settings.cpu_seconds,
                        settings.memory_limit_mb * 1024 * 1024)
    except (ZarabanError, OSError):  # the binary could not be started
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
