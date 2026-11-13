"""The execution matrix: run every test on every build, repeatedly (SPEC §7).

For each test, on each of the four builds, ``repeats`` times, this runs the
program and records one :class:`~zaraban.models.RunRecord` per execution
(written to ``runs/<test>/<build>/<n>.json``, §12.3). The repeats of one
(test, build) pair are combined into a :class:`~zaraban.models.CombinedResult`,
which is flagged **flaky** when they disagree (§7.5). The whole set is the
``Results`` matrix the analysis stage consumes.

The program is run through an injected ``run_one`` callable, so this module is
independent of Member B's runner (§7): the exec stage wraps ``run_once``;
the tests pass a fake. This module decides *what* to run and *how to combine*
repeats; it does not itself start a process or parse a crash.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

from .models import (
    BuildName,
    CombinedResult,
    Results,
    RunRecord,
    TestCase,
    dump_json,
)

# run_one(test, build, repeat, run_dir) -> RunRecord
RunOne = Callable[[TestCase, BuildName, int, Path], RunRecord]


@dataclass
class Execution:
    """The outcome of the whole matrix, for the context and the report."""

    results: Results  # results[test_name][build] -> CombinedResult
    execution_logs: dict[BuildName, dict[str, dict]] = field(default_factory=dict)
    all_runs_completed: bool = True
    results_stable: bool = True


def run_matrix(
    tests: Sequence[TestCase],
    builds: Sequence[BuildName],
    repeats: int,
    run_one: RunOne,
    out_dir: str | Path,
    *,
    write_json: bool = True,
) -> Execution:
    """Run ``tests`` × ``builds`` × ``repeats`` and combine the repeats (§7.5).

    ``all_runs_completed`` is true only when every planned run produced a
    record; ``results_stable`` is true when no combined result is flaky. A run
    whose ``run_one`` raises is counted as not completed and skipped, so one
    bad run never aborts the matrix.
    """
    out = Path(out_dir)
    results: Results = {}
    logs: dict[BuildName, dict[str, dict]] = {}
    expected = len(tests) * len(builds) * repeats
    completed = 0

    for test in tests:
        results.setdefault(test.name, {})
        for build in builds:
            runs: list[RunRecord] = []
            for n in range(1, repeats + 1):
                try:
                    rec = run_one(test, build, n, out)
                except Exception:
                    continue  # not completed; counted as a gap below
                completed += 1
                if write_json:
                    dump_json(rec, out / "runs" / test.name / build.value / f"{n}.json")
                runs.append(rec)
            if not runs:
                continue
            combined = combine(runs)
            results[test.name][build] = combined
            logs.setdefault(build, {})[test.name] = _log_entry(combined, test.name, build, repeats)

    all_completed = completed == expected
    stable = all(not c.flaky for per_build in results.values() for c in per_build.values())
    return Execution(results=results, execution_logs=logs,
                     all_runs_completed=all_completed, results_stable=stable)


def combine(runs: list[RunRecord]) -> CombinedResult:
    """Combine the repeats of one (test, build) pair (§7.5).

    Flaky when the repeats disagree on what happened: their (outcome,
    signature, oracle result) fingerprints are not all identical.
    """
    first = runs[0]
    fingerprints = {
        (r.analysis.outcome, r.analysis.signature, r.oracle.passed) for r in runs
    }
    return CombinedResult(test=first.test, kind=first.kind, build=first.build,
                          runs=runs, flaky=len(fingerprints) > 1)


def _log_entry(combined: CombinedResult, test: str, build: BuildName, repeats: int) -> dict:
    """A short per-(build, test) summary for ``report.execution_logs`` (§12.4)."""
    return {
        "outcome": combined.outcome.value,
        "signature": combined.signature,
        "flaky": combined.flaky,
        "repeats": len(combined.runs),
        "runs": [f"runs/{test}/{build.value}/{n}.json" for n in range(1, len(combined.runs) + 1)],
    }
