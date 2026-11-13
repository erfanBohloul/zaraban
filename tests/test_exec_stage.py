"""Unit tests for the build & execute stage (SPEC §2 steps 3–5).

The builder and the hardening checker are replaced with fakes and
``run_test`` is injected, so this tests the *orchestration*: the build-failure
stop, the build-side Checks, where each run writes, and the warnings carried
into the report, without compiling or running anything.
"""

from pathlib import Path
from types import SimpleNamespace

from zaraban import builder, exec_stage, hardening, runner
from zaraban.models import (
    BUILD_ORDER,
    Analysis,
    BuildName,
    CombinedResult,
    InputInfo,
    InputMethod,
    Issue,
    OracleResult,
    Outcome,
    RunRecord,
    StreamInfo,
    TestCase,
    TestKind,
)
from zaraban.pipeline_state import RunContext

TESTS = [TestCase("valid_ping", TestKind.VALID, b"PING"),
         TestCase("exploit_primary", TestKind.SECURITY, b"BOOM")]


def fake_target():
    spec = SimpleNamespace(repeats=2, regression_dir="tests/regression",
                           limits=SimpleNamespace(timeout_seconds=2.0, memory_limit_mb=128))
    return SimpleNamespace(name="t", all_tests=lambda: list(TESTS), spec=spec,
                           config_dir=Path("."))


def fake_build_set(ok=True, error=None, warnings=None):
    records = {b: SimpleNamespace(status="ok" if ok or b is BuildName.BASE_RELEASE else "failed",
                                  binary=SimpleNamespace(path=f"builds/{b.value}/bin/prog"))
               for b in (BUILD_ORDER if ok else BUILD_ORDER[:2])}
    return SimpleNamespace(ok=ok, error=error, warnings=warnings or [], records=records)


def record(test, build, repeat, *, truncated=False, outcome=Outcome.NORMAL):
    return RunRecord(
        test=test.name, kind=test.kind, build=build, repeat=repeat,
        cmd=["./prog"], env={}, cwd=".",
        input=InputInfo(method=InputMethod.STDIN, name=None, size=0, sha256="0" * 64),
        exit_code=0, signal=None, timed_out=False, limit_hit=None, duration_s=0.01,
        stdout=StreamInfo("o", 0, "0" * 64, truncated), stderr=StreamInfo("e", 0, "0" * 64),
        analysis=Analysis(outcome=outcome), oracle=OracleResult(checked=True, passed=True),
    )


def make_ctx(tmp_path) -> RunContext:
    work = tmp_path / "run" / "work"
    return RunContext(
        args=SimpleNamespace(), target=fake_target(), work_dir=work, out_dir=tmp_path / "run",
        run_id="20261113-000000-abcd1234", started_at="2026-11-13T00:00:00Z",
        sources=SimpleNamespace(base_tree=work / "base", patch_tree=work / "patch"),
        run_settings=runner.RunSettings(),
    )


def fake_stages(monkeypatch, build_set, seen_hardening=None):
    monkeypatch.setattr(builder, "build_all", lambda bt, pt, t, w, o: build_set)

    def fake_hardening(b1, b2):
        if seen_hardening is not None:
            seen_hardening.append((b1, b2))
        return SimpleNamespace(changes=[]), [Issue("HARDENING_DOWNGRADE", "x")]
    monkeypatch.setattr(hardening, "report", fake_hardening)


def recording_run_test(calls, flaky_on=None, truncated=False):
    """A fake runner.run_test that records its arguments."""
    def run_test(binary, test, settings, build, repeats, out_dir, source_root=""):
        calls.append(dict(binary=binary, test=test.name, build=build, repeats=repeats,
                          out_dir=out_dir, source_root=source_root))
        runs = [record(test, build, n, truncated=truncated) for n in range(1, repeats + 1)]
        flaky = flaky_on == (test.name, build)
        return CombinedResult(test=test.name, kind=test.kind, build=build, runs=runs, flaky=flaky)
    return run_test


# -- happy path --------------------------------------------------------------

def test_fills_results_and_build_side_checks(tmp_path, monkeypatch):
    fake_stages(monkeypatch, fake_build_set())
    ctx = exec_stage.build_and_execute(make_ctx(tmp_path), run_test=recording_run_test([]))

    assert [t.name for t in ctx.tests] == ["valid_ping", "exploit_primary"]
    assert set(ctx.results) == {"valid_ping", "exploit_primary"}
    assert set(ctx.results["valid_ping"]) == set(BUILD_ORDER)
    c = ctx.checks
    assert c.builds_ok and c.profiles_verified and c.hardening_checked
    assert c.all_runs_completed and c.results_stable
    assert not c.base_reproduced and not c.bundles_replayed  # the analyze stage's
    assert ctx.errors == []


def test_7_1_every_run_writes_into_the_run_dir_with_its_build_copy_as_source_root(
        tmp_path, monkeypatch):
    # run_once puts its files at <out_dir>/runs/<test>/<build>/ itself (§12.3),
    # so out_dir must be the run directory, not a per-run subdirectory; and
    # frame paths are relative to the build's own copy work/<build>/ (§7.4).
    fake_stages(monkeypatch, fake_build_set())
    calls = []
    ctx = exec_stage.build_and_execute(make_ctx(tmp_path), run_test=recording_run_test(calls))

    assert len(calls) == len(TESTS) * len(BUILD_ORDER)
    for call in calls:
        assert call["out_dir"] == ctx.out_dir
        assert call["source_root"] == str(ctx.work_dir / call["build"].value)
        assert call["binary"] == ctx.out_dir / f"builds/{call['build'].value}/bin/prog"
        assert call["repeats"] == 2


def test_hardening_runs_on_the_two_release_binaries(tmp_path, monkeypatch):
    seen = []
    fake_stages(monkeypatch, fake_build_set(), seen_hardening=seen)
    exec_stage.build_and_execute(make_ctx(tmp_path), run_test=recording_run_test([]))
    assert len(seen) == 1
    b1, b2 = seen[0]
    assert "base-release" in str(b1) and "patch-release" in str(b2)


def test_7_5_a_flaky_result_fails_results_stable(tmp_path, monkeypatch):
    fake_stages(monkeypatch, fake_build_set())
    run_test = recording_run_test([], flaky_on=("valid_ping", BuildName.PATCH_SANITIZED))
    ctx = exec_stage.build_and_execute(make_ctx(tmp_path), run_test=run_test)
    assert not ctx.checks.results_stable


# -- warnings ----------------------------------------------------------------

def test_build_and_hardening_warnings_are_carried_once(tmp_path, monkeypatch):
    warn = Issue("NO_DEBUG_INFO", "sanitized binary has no debug info")
    fake_stages(monkeypatch, fake_build_set(warnings=[warn]))
    ctx = exec_stage.build_and_execute(make_ctx(tmp_path), run_test=recording_run_test([]))
    codes = [w.code for w in ctx.warnings]
    assert codes.count("NO_DEBUG_INFO") == 1
    assert codes.count("HARDENING_DOWNGRADE") == 1


def test_7_3_truncated_output_gives_output_truncated(tmp_path, monkeypatch):
    fake_stages(monkeypatch, fake_build_set())
    ctx = exec_stage.build_and_execute(make_ctx(tmp_path),
                                       run_test=recording_run_test([], truncated=True))
    assert any(w.code == "OUTPUT_TRUNCATED" for w in ctx.warnings)


# -- build failure stops the stage (§6.2) ------------------------------------

def test_6_2_build_failure_stops_before_hardening_and_execution(tmp_path, monkeypatch):
    seen, calls = [], []
    err = Issue("BUILD_FAILED", "base-sanitized: build command exited with code 2")
    fake_stages(monkeypatch, fake_build_set(ok=False, error=err), seen_hardening=seen)

    ctx = exec_stage.build_and_execute(make_ctx(tmp_path), run_test=recording_run_test(calls))

    assert not ctx.checks.builds_ok and not ctx.checks.profiles_verified
    assert [e.code for e in ctx.errors] == ["BUILD_FAILED"]  # once, not twice
    assert seen == [] and calls == []
    assert ctx.hardening is None and ctx.results is None
    assert not ctx.checks.hardening_checked


def test_6_3_profile_failure_keeps_builds_ok(tmp_path, monkeypatch):
    # All four builds succeeded but one failed profile verification: builds_ok
    # holds, profiles_verified does not (§13.2).
    bs = fake_build_set()
    bs.ok, bs.error = False, Issue("SANITIZER_MISSING", "patch-sanitized has no ASan")
    fake_stages(monkeypatch, bs)
    ctx = exec_stage.build_and_execute(make_ctx(tmp_path), run_test=recording_run_test([]))
    assert ctx.checks.builds_ok and not ctx.checks.profiles_verified
    assert [e.code for e in ctx.errors] == ["SANITIZER_MISSING"]
    assert ctx.results is None
