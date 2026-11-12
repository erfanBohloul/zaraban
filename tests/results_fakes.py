"""Fake run results for the findings and linking tests (Member C).

Builds ``Results`` (``results[test][build] -> CombinedResult``) from short
descriptions, so a test can state a scenario as a table:

    r = results({
        "exploit_primary":   {"base-sanitized": crash(), "patch-sanitized": normal(1)},
        "exploit_secondary": {"base-sanitized": crash(), "patch-sanitized": crash()},
    })

Builds that are not given run normally with exit 0. A list of runs instead of
one run is a set of repeats; the result is flaky when they differ (§7.5).
"""

from __future__ import annotations

from typing import Optional, Union

from zaraban.models import (
    BUILD_ORDER, Analysis, BuildName, CombinedResult, Detection, ErrorType, Frame,
    InputInfo, InputMethod, LimitKind, OracleResult, Outcome, Results, RunRecord,
    StreamInfo, TestKind,
)

# The crash of token_parser: strcpy overflow in handle_set_command (§8.9).
TOKEN_FRAMES = (("handle_set_command", "src/main.c", 37),
                ("process_input", "src/main.c", 60),
                ("main", "src/main.c", 80))


def frames(*specs, runtime_top: bool = True) -> list[Frame]:
    """Frames from ``(function, file, line)`` tuples. With ``runtime_top`` an
    ``__interceptor_strcpy`` runtime frame is put first, as ASan prints it."""
    out: list[Frame] = []
    if runtime_top:
        out.append(Frame(0, "__interceptor_strcpy", None, None, True))
    for fn, file, line in specs:
        out.append(Frame(len(out), fn, file, line, False))
    return out


def signature(error_type: ErrorType, fr: list[Frame]) -> Optional[str]:
    """The signature as the runner computes it (§7.4)."""
    names = [f.function for f in fr if not f.runtime and f.function][:3]
    return f"{error_type.value} @ {' < '.join(names)}" if names else None


def crash(error_type: str = "STACK_BUFFER_OVERFLOW", stack=TOKEN_FRAMES, *,
          detection: str = "ASAN", signal: Optional[str] = "SIGABRT",
          exit_code: Optional[int] = None, runtime_top: bool = True) -> dict:
    """A crash run. ``stack=()`` gives a crash without a signature (§8.3)."""
    et = ErrorType(error_type)
    fr = frames(*stack, runtime_top=runtime_top) if stack else []
    return dict(outcome=Outcome.CRASH, detection=Detection(detection), error_type=et,
                frames=fr, signature=signature(et, fr), signal=signal,
                exit_code=exit_code, oracle=False)


def normal(exit_code: int = 0, oracle: Optional[bool] = None, reasons=()) -> dict:
    """A run that ended normally. ``oracle`` is True/False when checked;
    ``reasons`` are the oracle's mismatch reasons."""
    return dict(outcome=Outcome.NORMAL, exit_code=exit_code, oracle=oracle, reasons=list(reasons))


def timeout() -> dict:
    return dict(outcome=Outcome.TIMEOUT, exit_code=None, signal="SIGKILL", oracle=False)


def resource_limit(kind: str = "memory") -> dict:
    return dict(outcome=Outcome.RESOURCE_LIMIT, exit_code=None, signal="SIGKILL",
                limit=LimitKind(kind), oracle=False)


def run_record(test: str, kind: TestKind, build: BuildName, spec: dict, repeat: int = 1) -> RunRecord:
    oracle = spec.get("oracle")
    analysis = Analysis(
        outcome=spec["outcome"], detection=spec.get("detection"),
        error_type=spec.get("error_type"), frames=spec.get("frames", []),
        signature=spec.get("signature"),
    )
    stream = StreamInfo(path=f"runs/{test}/{build.value}/{repeat}.out", bytes=0, sha256="0" * 64)
    return RunRecord(
        test=test, kind=kind, build=build, repeat=repeat, cmd=["./prog"], env={},
        cwd=".", input=InputInfo(InputMethod.STDIN, None, 0, "0" * 64),
        exit_code=spec.get("exit_code"), signal=spec.get("signal"),
        timed_out=spec["outcome"] is Outcome.TIMEOUT, limit_hit=spec.get("limit"),
        duration_s=0.01, stdout=stream, stderr=stream, analysis=analysis,
        oracle=OracleResult(checked=oracle is not None, passed=oracle,
                            reasons=spec.get("reasons", [])),
    )


Spec = Union[dict, list]


def combined(test: str, kind: TestKind, build: BuildName, spec: Spec) -> CombinedResult:
    specs = spec if isinstance(spec, list) else [spec]
    runs = [run_record(test, kind, build, s, i + 1) for i, s in enumerate(specs)]
    keys = {(r.analysis.outcome, r.analysis.signature, r.oracle.passed) for r in runs}
    return CombinedResult(test, kind, build, runs, flaky=len(keys) > 1)


def results(table: dict[str, dict[str, Spec]],
            kinds: Optional[dict[str, str]] = None) -> Results:
    """``Results`` from a table; a test's kind defaults from its name
    (``exploit_*`` -> security, ``reg-*`` -> regression, else valid)."""
    out: Results = {}
    for test, builds in table.items():
        kind = TestKind((kinds or {}).get(test) or _kind_from_name(test))
        out[test] = {b: combined(test, kind, b, builds.get(b.value, normal()))
                     for b in BUILD_ORDER}
    return out


def _kind_from_name(test: str) -> str:
    if test.startswith("exploit"):
        return "security"
    if test.startswith("reg-"):
        return "regression"
    return "valid"
