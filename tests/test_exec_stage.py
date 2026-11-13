"""Unit tests for the build & execute stage wiring (SPEC §2 steps 2–5).

The heavy sub-stages (sources, builder, hardening, environment) are replaced
with fakes, and ``run_one`` is injected, so this tests the *orchestration* —
field filling, the build-failure short-circuit, and the build-side Checks —
without compiling or running anything.
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from zaraban import builder, environment, exec_stage, hardening, pipeline, sources
from zaraban.models import (
    BUILD_ORDER,
    Analysis,
    BuildName,
    EnvironmentInfo,
    InputInfo,
    InputMethod,
    Issue,
    Outcome,
    OracleResult,
    RunRecord,
    StreamInfo,
    TestCase,
    TestKind,
)


# -- fakes -------------------------------------------------------------------

def fake_target(tmp_path):
    tests = [TestCase("valid_ping", TestKind.VALID, b"PING"),
             TestCase("exploit_primary", TestKind.SECURITY, b"BOOM")]
    limits = SimpleNamespace(timeout_seconds=2.0, memory_limit_mb=128)
    spec = SimpleNamespace(repeats=2, limits=limits)
    return SimpleNamespace(all_tests=lambda: tests, spec=spec, base_dir=tmp_path / "base")


def fake_sources(tmp_path):
    return SimpleNamespace(base_tree=tmp_path / "work" / "base",
                           patch_tree=tmp_path / "work" / "patch")


def fake_build_set(ok=True, error=None, warnings=None):
    records = {b: SimpleNamespace(binary=SimpleNamespace(path=f"builds/{b.value}/bin/prog"))
               for b in BUILD_ORDER}
    return SimpleNamespace(ok=ok, error=error, warnings=warnings or [], records=records)


def fake_run_record(test, build, repeat, run_dir=None):
    return RunRecord(
        test=test.name, kind=test.kind, build=build, repeat=repeat,
        cmd=["./prog"], env={}, cwd=".",
        input=InputInfo(method=InputMethod.STDIN, name=None, size=0, sha256="0" * 64),
        exit_code=0, signal=None, timed_out=False, limit_hit=None, duration_s=0.01,
        stdout=StreamInfo("o", 0, "0" * 64), stderr=StreamInfo("e", 0, "0" * 64),
        analysis=Analysis(outcome=Outcome.NORMAL),
        oracle=OracleResult(checked=True, passed=True),
    )


def make_ctx(tmp_path):
    args = SimpleNamespace(patch="patch.diff", base=None, out=str(tmp_path / "out"))
    return pipeline.new_context(args, fake_target(tmp_path), tmp_path / "out", [])


def patch_substages(monkeypatch, *, build_set, hardening_called=None):
    monkeypatch.setattr(sources, "prepare", lambda b, p, w: fake_sources(Path(w).parent))
    monkeypatch.setattr(builder, "build_all", lambda bt, pt, t, w, o: build_set)
    monkeypatch.setattr(environment, "gather",
                        lambda: EnvironmentInfo("Ubuntu", "6", "x86_64", None, "3.10",
                                                "11", "14", "14"))

    def fake_hardening(b1, b2):
        if hardening_called is not None:
            hardening_called.append((b1, b2))
        return SimpleNamespace(changes=[]), [Issue("HARDENING_DOWNGRADE", "x")]
    monkeypatch.setattr(hardening, "report", fake_hardening)


# -- happy path --------------------------------------------------------------

def test_2_5_fills_context_and_build_checks(tmp_path, monkeypatch):
    patch_substages(monkeypatch, build_set=fake_build_set())
    ctx = make_ctx(tmp_path)

    out = exec_stage.build_and_execute(ctx, run_one=fake_run_record)

    assert out.sources is not None
    assert out.build_set is not None
    assert out.hardening is not None
    assert isinstance(out.environment, EnvironmentInfo)
    # Every test ran on every build.
    assert set(out.results) == {"valid_ping", "exploit_primary"}
    assert set(out.results["valid_ping"]) == set(BUILD_ORDER)
    # Build-side checks are all set; the two analyze-side ones stay False.
    c = out.checks
    assert c.builds_ok and c.profiles_verified and c.hardening_checked
    assert c.all_runs_completed and c.results_stable
    assert not c.base_reproduced and not c.bundles_replayed
    assert out.settings["repeats"] == 2


def test_hardening_runs_on_the_two_release_binaries(tmp_path, monkeypatch):
    seen = []
    patch_substages(monkeypatch, build_set=fake_build_set(), hardening_called=seen)
    ctx = make_ctx(tmp_path)
    exec_stage.build_and_execute(ctx, run_one=fake_run_record)
    assert len(seen) == 1
    b1, b2 = seen[0]
    assert "base-release" in str(b1) and "patch-release" in str(b2)


# -- build failure short-circuits (§6.2) -------------------------------------

def test_6_2_build_failure_stops_before_hardening_and_execution(tmp_path, monkeypatch):
    seen = []
    err = Issue("BUILD_FAILED", "base-sanitized: build command exited with code 2")
    patch_substages(monkeypatch, build_set=fake_build_set(ok=False, error=err),
                    hardening_called=seen)
    ctx = make_ctx(tmp_path)

    out = exec_stage.build_and_execute(ctx, run_one=fake_run_record)

    assert not out.checks.builds_ok
    assert out.errors and out.errors[0].code == "BUILD_FAILED"
    # Hardening and execution never ran.
    assert seen == []
    assert out.hardening is None
    assert out.results is None
    assert not out.checks.hardening_checked
    # Environment is still snapshotted so the report is complete.
    assert isinstance(out.environment, EnvironmentInfo)


def test_build_warnings_are_carried(tmp_path, monkeypatch):
    warn = Issue("NO_DEBUG_INFO", "sanitized binary has no debug info")
    patch_substages(monkeypatch, build_set=fake_build_set(warnings=[warn]))
    ctx = make_ctx(tmp_path)
    out = exec_stage.build_and_execute(ctx, run_one=fake_run_record)
    assert any(w.code == "NO_DEBUG_INFO" for w in out.warnings)
