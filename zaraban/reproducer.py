"""Reproducer bundles: minimize a crashing input and confirm it is stable
(SPEC §10.1–§10.3).

For each crash finding, this takes the crashing input, shrinks it with
delta-debugging (ddmin) while the *same* crash still happens, then replays the
chosen input several times to confirm the crash is stable, and writes a
``reproducers/<finding>/`` bundle. The result is a
:class:`~zaraban.models.Bundle` with its :class:`~zaraban.models.Replay`
records.

The program is run through an injected ``run`` callable that returns a
:class:`RunOutcome` (crashed?, signature, signal, …). That keeps this module
independent of Member B's runner (§7): the pipeline adapts a real
``RunRecord`` with :meth:`RunOutcome.from_record`; the tests pass a fake
``run``. "Same crash" means the same crash signature (error type + top
application frames, §7.4), so minimization never drifts to a *different* bug.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .models import (
    Bundle,
    BuildName,
    ErrorType,
    Issue,
    Replay,
    RunRecord,
    WarningCode,
)

MINIMIZE_LIMIT = 200  # most ``run`` calls ddmin may make before giving up (§10.2)


@dataclass
class RunOutcome:
    """One execution's result, as the reproducer needs it (a slim view of
    Member B's :class:`RunRecord`)."""

    crashed: bool
    signature: Optional[str]
    signal: Optional[str] = None
    exit_code: Optional[int] = None
    error_type: Optional[ErrorType] = None
    top_functions: list[str] = None  # type: ignore[assignment]
    duration_s: float = 0.0

    def __post_init__(self) -> None:
        if self.top_functions is None:
            self.top_functions = []

    @classmethod
    def from_record(cls, rec: RunRecord) -> "RunOutcome":
        """Adapt Member B's full run record to the slim outcome (used by the
        pipeline; the tests build RunOutcome directly)."""
        a = rec.analysis
        return cls(
            crashed=a.is_crash,
            signature=a.signature,
            signal=rec.signal,
            exit_code=rec.exit_code,
            error_type=a.error_type,
            top_functions=[f.function for f in a.app_frames[:3] if f.function],
            duration_s=rec.duration_s,
        )


RunFn = Callable[[bytes], RunOutcome]


def reproduce(
    *,
    finding_id: str,
    source_test: str,
    build: BuildName,
    input_bytes: bytes,
    run: RunFn,
    out_dir: str | Path,
    repeats: int = 3,
    minimize: bool = True,
    minimize_limit: int = MINIMIZE_LIMIT,
) -> tuple[Bundle, list[Issue]]:
    """Minimize ``input_bytes``, replay it, and write the bundle (§10.1–§10.3).

    Returns the :class:`Bundle` and any warnings (``MINIMIZE_LIMIT`` when ddmin
    ran out of its budget). When the input does not crash with a signature at
    all, no minimization is done and the bundle is marked unstable.
    """
    warnings: list[Issue] = []
    bundle_dir = Path(out_dir) / "reproducers" / finding_id
    bundle_dir.mkdir(parents=True, exist_ok=True)
    rel_path = f"reproducers/{finding_id}"

    first = run(input_bytes)
    target_sig = first.signature

    # No reproducible crash signature: record the bundle, do not minimize.
    if not first.crashed or target_sig is None:
        _write_input(bundle_dir / "input.orig", input_bytes)
        replay = Replay(1, reproduced=False, signal=first.signal, exit_code=first.exit_code,
                        error_type=first.error_type, top_functions=first.top_functions,
                        duration_s=first.duration_s)
        bundle = Bundle(finding=finding_id, source_test=source_test, build=build, path=rel_path,
                        original_size=len(input_bytes), minimized_size=None, minimize_runs=0,
                        minimize_limit_hit=False, replayed_input="orig", replays=[replay],
                        stable=False)
        return bundle, warnings

    minimized = input_bytes
    minimize_runs = 0
    limit_hit = False
    if minimize and len(input_bytes) > 1:
        def interesting(candidate: bytes) -> bool:
            o = run(candidate)
            return o.crashed and o.signature == target_sig

        minimized, minimize_runs, limit_hit = ddmin(input_bytes, interesting, minimize_limit)
        if limit_hit:
            warnings.append(Issue(
                WarningCode.MINIMIZE_LIMIT.value,
                f"{finding_id}: minimization stopped after {minimize_limit} runs; "
                "the saved input may be larger than the smallest reproducer",
                {"finding": finding_id, "limit": minimize_limit}))

    replayed_input = "min" if len(minimized) < len(input_bytes) else "orig"
    chosen = minimized if replayed_input == "min" else input_bytes

    _write_input(bundle_dir / "input.orig", input_bytes)
    if replayed_input == "min":
        _write_input(bundle_dir / "input.min", minimized)
    _write_replay_script(bundle_dir / "replay.sh", build, replayed_input)

    replays: list[Replay] = []
    for n in range(1, repeats + 1):
        o = run(chosen)
        reproduced = o.crashed and o.signature == target_sig
        replays.append(Replay(n, reproduced=reproduced, signal=o.signal, exit_code=o.exit_code,
                              error_type=o.error_type, top_functions=o.top_functions,
                              duration_s=o.duration_s))
    stable = all(r.reproduced for r in replays)

    bundle = Bundle(
        finding=finding_id, source_test=source_test, build=build, path=rel_path,
        original_size=len(input_bytes),
        minimized_size=len(minimized) if minimize else None,
        minimize_runs=minimize_runs, minimize_limit_hit=limit_hit,
        replayed_input=replayed_input, replays=replays, stable=stable,
    )
    return bundle, warnings


# ---------------------------------------------------------------------------
# Delta debugging (§10.2)
# ---------------------------------------------------------------------------


def ddmin(data: bytes, interesting: Callable[[bytes], bool], limit: int) -> tuple[bytes, int, bool]:
    """Shrink ``data`` to a local minimum that is still ``interesting`` (ddmin).

    ``interesting(candidate)`` says whether a shorter input still triggers the
    same crash. Returns the minimized bytes, the number of ``interesting``
    calls made, and whether the ``limit`` was hit before finishing.
    """
    best = data
    n = 2
    calls = 0
    while len(best) >= 2:
        chunk = len(best) // n
        complements = []
        for i in range(n):
            start = i * chunk
            end = start + chunk if i < n - 1 else len(best)
            complements.append(best[:start] + best[end:])

        reduced = False
        for comp in complements:
            if calls >= limit:
                return best, calls, True
            calls += 1
            if comp and interesting(comp):
                best = comp
                n = max(n - 1, 2)
                reduced = True
                break

        if not reduced:
            if n >= len(best):
                break
            n = min(len(best), n * 2)
    return best, calls, False


# ---------------------------------------------------------------------------
# Bundle files
# ---------------------------------------------------------------------------


def _write_input(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def _write_replay_script(path: Path, build: BuildName, which: str) -> None:
    """A tiny, self-describing script so a person can rerun the crash by hand."""
    name = "input.min" if which == "min" else "input.orig"
    path.write_text(
        "#!/bin/sh\n"
        f"# Replay the crash of {build.value} on its reproducer input.\n"
        "# Point BINARY at the kept sanitized binary for this build, e.g.\n"
        f"#   builds/{build.value}/bin/<binary>\n"
        'BINARY="${BINARY:?set BINARY to the built sanitized binary}"\n'
        f'exec "$BINARY" "$(dirname "$0")/{name}"\n',
        encoding="utf-8",
    )
    path.chmod(0o755)
