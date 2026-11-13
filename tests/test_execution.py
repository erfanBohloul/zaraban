"""Unit tests for the execution matrix (SPEC §7.5, §12.3).

The program is an injected ``run_one``, so these are deterministic and need no
compiler or Member B's runner: a fake returns the RunRecord we dictate.
"""

import json

from zaraban import execution
from zaraban.models import (
    BUILD_ORDER,
    Analysis,
    BuildName,
    InputInfo,
    InputMethod,
    Outcome,
    OracleResult,
    RunRecord,
    StreamInfo,
    TestCase,
    TestKind,
)


# -- fixtures ----------------------------------------------------------------

def two_tests() -> list[TestCase]:
    return [
        TestCase("valid_ping", TestKind.VALID, b"PING"),
        TestCase("exploit_primary", TestKind.SECURITY, b"BOOM"),
    ]


def record(test: TestCase, build: BuildName, repeat: int, *,
           outcome=Outcome.NORMAL, signature=None, passed=True) -> RunRecord:
    return RunRecord(
        test=test.name, kind=test.kind, build=build, repeat=repeat,
        cmd=["./prog"], env={}, cwd=".",
        input=InputInfo(method=InputMethod.STDIN, name=None, size=0, sha256="0" * 64),
        exit_code=0, signal=None, timed_out=False, limit_hit=None, duration_s=0.01,
        stdout=StreamInfo("stdout.bin", 0, "0" * 64),
        stderr=StreamInfo("stderr.bin", 0, "0" * 64),
        analysis=Analysis(outcome=outcome, signature=signature),
        oracle=OracleResult(checked=passed is not None, passed=passed),
    )


def constant_runner(**kw):
    """A run_one that returns the same kind of record for every call."""
    def run_one(test, build, repeat, run_dir):
        return record(test, build, repeat, **kw)
    return run_one


# -- the matrix shape (§7.1) -------------------------------------------------

def test_7_matrix_covers_every_test_and_build(tmp_path):
    ts = two_tests()
    ex = execution.run_matrix(ts, BUILD_ORDER, repeats=3,
                              run_one=constant_runner(), out_dir=tmp_path)
    assert set(ex.results) == {"valid_ping", "exploit_primary"}
    for name in ex.results:
        assert set(ex.results[name]) == set(BUILD_ORDER)
        for build in BUILD_ORDER:
            assert len(ex.results[name][build].runs) == 3  # repeats
    assert ex.all_runs_completed  # 2 * 4 * 3 all produced a record


def test_12_3_run_json_written_per_execution(tmp_path):
    execution.run_matrix(two_tests(), [BuildName.BASE_RELEASE], repeats=2,
                         run_one=constant_runner(), out_dir=tmp_path)
    for n in (1, 2):
        p = tmp_path / "runs" / "valid_ping" / "base-release" / f"{n}.json"
        assert p.exists()
        data = json.loads(p.read_text())
        assert data["build"] == "base-release" and data["repeat"] == n


# -- combining repeats (§7.5) ------------------------------------------------

def test_7_5_agreeing_repeats_are_not_flaky(tmp_path):
    ex = execution.run_matrix(two_tests(), [BuildName.PATCH_SANITIZED], repeats=3,
                              run_one=constant_runner(outcome=Outcome.CRASH,
                                                      signature="SEGV @ f", passed=None),
                              out_dir=tmp_path)
    combined = ex.results["valid_ping"][BuildName.PATCH_SANITIZED]
    assert not combined.flaky
    assert combined.stable_crash  # stable + CRASH
    assert ex.results_stable


def test_7_5_disagreeing_repeats_are_flaky(tmp_path):
    # Crash on odd repeats, normal on even -> flaky.
    def flaky_runner(test, build, repeat, run_dir):
        if repeat % 2 == 1:
            return record(test, build, repeat, outcome=Outcome.CRASH,
                          signature="SEGV @ f", passed=None)
        return record(test, build, repeat, outcome=Outcome.NORMAL, passed=True)

    ex = execution.run_matrix(two_tests(), [BuildName.PATCH_SANITIZED], repeats=3,
                              run_one=flaky_runner, out_dir=tmp_path)
    assert ex.results["valid_ping"][BuildName.PATCH_SANITIZED].flaky
    assert not ex.results_stable


# -- execution_logs (§12.4) --------------------------------------------------

def test_12_4_execution_logs_summarize_each_cell(tmp_path):
    ex = execution.run_matrix(two_tests(), [BuildName.BASE_RELEASE], repeats=2,
                              run_one=constant_runner(outcome=Outcome.NORMAL),
                              out_dir=tmp_path)
    entry = ex.execution_logs[BuildName.BASE_RELEASE]["valid_ping"]
    assert entry["outcome"] == "NORMAL"
    assert entry["flaky"] is False
    assert entry["repeats"] == 2
    assert entry["runs"] == ["runs/valid_ping/base-release/1.json",
                             "runs/valid_ping/base-release/2.json"]


# -- robustness (§7) ---------------------------------------------------------

def test_7_a_failing_run_marks_incomplete_without_aborting(tmp_path):
    # run_one raises for one specific build; the rest of the matrix still runs.
    def partial(test, build, repeat, run_dir):
        if build is BuildName.PATCH_SANITIZED:
            raise RuntimeError("runner blew up")
        return record(test, build, repeat)

    ex = execution.run_matrix(two_tests(), BUILD_ORDER, repeats=2,
                              run_one=partial, out_dir=tmp_path)
    assert not ex.all_runs_completed  # some planned runs didn't produce a record
    # The failing cell is simply absent; the others are present.
    assert BuildName.PATCH_SANITIZED not in ex.results["valid_ping"]
    assert BuildName.BASE_RELEASE in ex.results["valid_ping"]


def test_combine_directly():
    ts = two_tests()[0]
    runs = [record(ts, BuildName.BASE_RELEASE, n) for n in (1, 2)]
    combined = execution.combine(runs)
    assert combined.test == "valid_ping"
    assert combined.build is BuildName.BASE_RELEASE
    assert not combined.flaky
    assert combined.first.repeat == 1
