"""Unit tests for Phase 2 Person 2: analyze_and_report stage."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from zaraban import analysis_stage
from zaraban.analysis_stage import execution_logs
from zaraban.builder import BuildSet
from zaraban.models import (
    BUILD_ORDER,
    Analysis,
    BinaryInfo,
    BuildName,
    BuildRecord,
    Checks,
    CombinedResult,
    Detection,
    DiffInfo,
    EnvironmentInfo,
    ErrorCode,
    ErrorType,
    Frame,
    HardeningReport,
    HardeningResult,
    InputInfo,
    InputMethod,
    Issue,
    OracleResult,
    Outcome,
    ProtectionResult,
    Relro,
    RunRecord,
    StreamInfo,
    TestCase,
    TestKind,
    VersionInfo,
)
from zaraban.pipeline_state import RunContext
from zaraban.reproducer import RunOutcome
from zaraban.sources import Sources

SIG = "STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main"


def _fake_environment() -> EnvironmentInfo:
    return EnvironmentInfo(
        os="Linux",
        kernel="5.15",
        arch="x86_64",
        docker_image="zaraban:latest",
        python="3.12.0",
        gcc="11.4.0",
        clang="14.0.0",
        llvm_symbolizer="/usr/bin/llvm-symbolizer",
    )


def _fake_hardening() -> HardeningReport:
    p = ProtectionResult(True, "verified")
    res = HardeningResult(nx=p, pie=p, relro=ProtectionResult(Relro.FULL, "verified"), canary=p)
    return HardeningReport(
        base=res,
        patch=res,
        changes=[],
        notes=["Hardening matches between base and patch."],
    )


def _fake_sources(tmp_path: Path) -> Sources:
    base_tree = tmp_path / "base"
    patch_tree = tmp_path / "patch"
    base_tree.mkdir(parents=True, exist_ok=True)
    patch_tree.mkdir(parents=True, exist_ok=True)
    (base_tree / "src").mkdir(exist_ok=True)
    (patch_tree / "src").mkdir(exist_ok=True)
    (base_tree / "src" / "main.c").write_text("int main() { return 0; }\n")
    (patch_tree / "src" / "main.c").write_text("int main() { return 0; }\n")

    diff_path = tmp_path / "patch.diff"
    diff_path.write_text(
        "--- a/src/main.c\n+++ b/src/main.c\n@@ -1,1 +1,2 @@\n int main() { return 0; }\n+// fix\n"
    )

    base_v = VersionInfo("directory", str(base_tree), "c76e9ca", "0" * 64)
    patch_v = VersionInfo("diff", str(diff_path), "c76e9ca", "1" * 64, strip_level=1)
    diff_i = DiffInfo("inputs/patch.diff", "2" * 64, ["src/main.c"], 1)
    return Sources(base_tree, patch_tree, diff_path, base_v, patch_v, diff_i)


def _fake_build_set(tmp_path: Path, failed_build: BuildName | None = None) -> BuildSet:
    records = {}
    error = None
    for name in BUILD_ORDER:
        bin_rel = f"builds/{name.value}/bin/token_parser"
        bin_disk = tmp_path / "out" / bin_rel
        bin_disk.parent.mkdir(parents=True, exist_ok=True)
        bin_disk.write_bytes(b"\x7fELFfake")
        status = "failed" if name is failed_build else "ok"
        records[name] = BuildRecord(
            build=name,
            status=status,
            cmd="make",
            env={},
            cwd=str(tmp_path / "work"),
            exit_code=1 if name is failed_build else 0,
            duration_s=0.5,
            log=f"builds/{name.value}/build.log",
            binary=BinaryInfo(bin_rel, 8, "f" * 64),
            sanitizers_verified=True if "sanitized" in name.value else None,
            has_debug_info=True if "sanitized" in name.value else None,
        )
    if failed_build is not None:
        error = Issue(ErrorCode.BUILD_FAILED.value, f"{failed_build.value} failed")
    return BuildSet(records=records, warnings=[], error=error)


def _run_record(test: str, kind: TestKind, build: BuildName, repeat: int,
                crashed: bool, oracle_passed: bool) -> RunRecord:
    outcome = Outcome.CRASH if crashed else Outcome.NORMAL
    analysis = Analysis(
        outcome=outcome,
        detection=Detection.ASAN if crashed else None,
        error_type=ErrorType.STACK_BUFFER_OVERFLOW if crashed else None,
        summary="stack-buffer-overflow in handle_set_command" if crashed else "normal exit",
        frames=[Frame(0, "handle_set_command", "src/main.c", 37, False)] if crashed else [],
        signature=SIG if crashed else None,
    )
    return RunRecord(
        test=test,
        kind=kind,
        build=build,
        repeat=repeat,
        cmd=["token_parser", "input.txt"],
        env={},
        cwd="/tmp/run",
        input=InputInfo(InputMethod.FILE, "input.txt", 10, "0" * 64),
        exit_code=None if crashed else (0 if oracle_passed else 1),
        signal="SIGABRT" if crashed else None,
        timed_out=False,
        limit_hit=None,
        duration_s=0.01,
        stdout=StreamInfo("1.stdout", 4, "a" * 64, False),
        stderr=StreamInfo("1.stderr", 100, "b" * 64, False),
        analysis=analysis,
        oracle=OracleResult(checked=True, passed=oracle_passed),
    )


def _fake_results(scenario: str = "correct", flaky: bool = False) -> dict[str, dict[BuildName, CombinedResult]]:
    """Build results table for a given scenario: 'correct', 'incomplete', 'regression'."""
    tests = [
        ("valid_ping", TestKind.VALID),
        ("valid_echo", TestKind.VALID),
        ("valid_set", TestKind.VALID),
        ("boundary_empty", TestKind.BOUNDARY),
        ("boundary_max_safe", TestKind.BOUNDARY),
        ("exploit_primary", TestKind.SECURITY),
        ("exploit_secondary", TestKind.SECURITY),
    ]
    res: dict[str, dict[BuildName, CombinedResult]] = {}
    for test_name, kind in tests:
        res[test_name] = {}
        for bname in BUILD_ORDER:
            crashed = False
            passed = True
            if kind is TestKind.SECURITY:
                if "base" in bname.value:
                    crashed = True
                elif scenario == "incomplete" and test_name == "exploit_secondary":
                    crashed = True
            elif scenario == "regression" and test_name == "valid_set" and "patch" in bname.value:
                passed = False

            runs = [_run_record(test_name, kind, bname, r, crashed, passed) for r in (1, 2, 3)]
            is_flaky = flaky and test_name == "valid_ping" and bname is BuildName.BASE_RELEASE
            if is_flaky:
                runs[1] = _run_record(test_name, kind, bname, 2, not crashed, not passed)
            res[test_name][bname] = CombinedResult(
                test=test_name,
                kind=kind,
                build=bname,
                runs=runs,
                flaky=is_flaky,
            )
    return res


def _fake_target(tmp_path: Path):
    tests = [
        TestCase("valid_ping", TestKind.VALID, b"PING", ".txt", expected_exit_code=0),
        TestCase("valid_echo", TestKind.VALID, b"ECHO", ".txt", expected_exit_code=0),
        TestCase("valid_set", TestKind.VALID, b"SET x=1", ".txt", expected_exit_code=0),
        TestCase("boundary_empty", TestKind.BOUNDARY, b"", ".txt", expected_exit_code=0),
        TestCase("boundary_max_safe", TestKind.BOUNDARY, b"A" * 10, ".txt", expected_exit_code=0),
        TestCase("exploit_primary", TestKind.SECURITY, b"SET " + b"A" * 120, ".txt"),
        TestCase("exploit_secondary", TestKind.SECURITY, b"SET " + b"A" * 80, ".txt"),
    ]
    config_file = tmp_path / "zaraban.yaml"
    config_file.write_text("name: token_parser\n")
    spec = SimpleNamespace(
        name="token_parser",
        repeats=3,
        input_method="file",
        regression_dir="tests/regression",
        limits=SimpleNamespace(timeout_seconds=2.0, memory_limit_mb=128),
    )
    return SimpleNamespace(
        name="token_parser",
        config_path=config_file,
        config_dir=tmp_path,
        spec=spec,
        all_tests=lambda: list(tests),
    )


def fake_run_input(ctx, test, build, data: bytes) -> RunOutcome:
    """Stands in for running the binary: inputs with "SET " crash like the exploit."""
    if b"SET " in data:
        return RunOutcome(
            crashed=True,
            signature=SIG,
            signal="SIGABRT",
            error_type=ErrorType.STACK_BUFFER_OVERFLOW,
            detection=Detection.ASAN,
            top_functions=["handle_set_command", "process_input", "main"],
        )
    return RunOutcome(crashed=False, signature=None, exit_code=0)


def analyze_and_report(ctx: RunContext) -> int:
    return analysis_stage.analyze_and_report(ctx, run_input=fake_run_input)


def _make_context(tmp_path: Path, scenario: str = "correct", failed_build: BuildName | None = None,
                  flaky: bool = False) -> RunContext:
    """A context as the build & execute stage leaves it."""
    out_dir = tmp_path / "out"
    work_dir = out_dir / "work"
    work_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "inputs").mkdir(exist_ok=True)
    (out_dir / "inputs" / "config.yaml").write_text("name: token_parser\n")
    target = _fake_target(tmp_path)
    build_set = _fake_build_set(tmp_path, failed_build=failed_build)

    ctx = RunContext(
        args=SimpleNamespace(out=str(tmp_path), no_promote=True, keep_work=False),
        target=target,
        work_dir=work_dir,
        out_dir=out_dir,
        run_id="20261113-000000-test0001",
        started_at="2026-11-13T00:00:00Z",
        sources=_fake_sources(tmp_path),
        environment=_fake_environment(),
        build_set=build_set,
    )
    ctx.checks.builds_ok = failed_build is None
    ctx.checks.profiles_verified = failed_build is None
    if failed_build is not None:  # the stage stops at the build (§6.2)
        ctx.add_errors([build_set.error])
        return ctx
    ctx.hardening = _fake_hardening()
    ctx.checks.hardening_checked = True
    ctx.tests = target.all_tests()
    ctx.results = _fake_results(scenario=scenario, flaky=flaky)
    ctx.checks.all_runs_completed = True
    ctx.checks.results_stable = not flaky
    return ctx


# -- Test cases --------------------------------------------------------------

def test_pass_correct_scenario(tmp_path):
    ctx = _make_context(tmp_path, scenario="correct")
    rc = analyze_and_report(ctx)

    assert rc == 0
    assert ctx.checks.all_ok
    assert ctx.checks.builds_ok
    assert ctx.checks.profiles_verified
    assert ctx.checks.all_runs_completed
    assert ctx.checks.base_reproduced
    assert ctx.checks.results_stable
    assert ctx.checks.bundles_replayed
    assert ctx.checks.hardening_checked

    report_file = ctx.out_dir / "report.json"
    summary_file = ctx.out_dir / "summary.txt"
    assert report_file.exists()
    assert summary_file.exists()

    data = json.loads(report_file.read_text())
    assert data["status"]["exit_code"] == 0
    assert data["status"]["exit_name"] == "PASS"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["category"] == "FIXED"


def test_vuln_remains_incomplete_scenario(tmp_path):
    ctx = _make_context(tmp_path, scenario="incomplete")
    rc = analyze_and_report(ctx)

    assert rc == 10
    report_file = ctx.out_dir / "report.json"
    data = json.loads(report_file.read_text())
    assert data["status"]["exit_code"] == 10
    assert data["status"]["exit_name"] == "VULN_REMAINS"
    assert any(f["category"] == "INCOMPLETE_FIX" for f in data["findings"])


def test_functional_regression_scenario(tmp_path):
    ctx = _make_context(tmp_path, scenario="regression")
    rc = analyze_and_report(ctx)

    assert rc == 20
    report_file = ctx.out_dir / "report.json"
    data = json.loads(report_file.read_text())
    assert data["status"]["exit_code"] == 20
    assert data["status"]["exit_name"] == "FUNC_REGRESSION"
    assert any(f["category"] == "FUNCTIONAL_REGRESSION" for f in data["findings"])


def test_build_failed_is_30(tmp_path):
    ctx = _make_context(tmp_path, failed_build=BuildName.PATCH_SANITIZED)
    rc = analyze_and_report(ctx)

    assert rc == 30
    report_file = ctx.out_dir / "report.json"
    data = json.loads(report_file.read_text())
    assert data["status"]["exit_code"] == 30
    assert data["status"]["exit_name"] == "BUILD_OR_CONFIG_ERROR"
    assert [e["code"] for e in data["errors"]] == ["BUILD_FAILED"]  # once, not twice
    assert data["findings"] == [] and data["execution_logs"] == {}


def test_inconclusive_when_results_flaky(tmp_path):
    ctx = _make_context(tmp_path, scenario="correct", flaky=True)
    rc = analyze_and_report(ctx)

    assert rc == 40
    report_file = ctx.out_dir / "report.json"
    data = json.loads(report_file.read_text())
    assert data["status"]["exit_code"] == 40
    assert data["status"]["exit_name"] == "INCONCLUSIVE"


def test_inconclusive_when_base_not_reproduced(tmp_path):
    ctx = _make_context(tmp_path, scenario="correct")
    # Make exploit_primary not crash on base-sanitized
    old = ctx.results["exploit_primary"][BuildName.BASE_SANITIZED]
    runs = [_run_record("exploit_primary", TestKind.SECURITY, BuildName.BASE_SANITIZED, r, False, True) for r in (1, 2, 3)]
    ctx.results["exploit_primary"][BuildName.BASE_SANITIZED] = CombinedResult(
        test="exploit_primary",
        kind=TestKind.SECURITY,
        build=BuildName.BASE_SANITIZED,
        runs=runs,
        flaky=False,
    )

    rc = analyze_and_report(ctx)
    assert rc == 40
    report_file = ctx.out_dir / "report.json"
    data = json.loads(report_file.read_text())
    assert data["status"]["exit_code"] == 40
    assert data["status"]["exit_name"] == "INCONCLUSIVE"


def test_work_dir_cleaned_up_unless_keep_work(tmp_path):
    ctx = _make_context(tmp_path, scenario="correct")
    assert ctx.work_dir.exists()
    analyze_and_report(ctx)
    assert not ctx.work_dir.exists()

    ctx2 = _make_context(tmp_path / "second", scenario="correct")
    ctx2.args.keep_work = True
    analyze_and_report(ctx2)
    assert ctx2.work_dir.exists()


def test_execution_logs_formatting(tmp_path):
    results = _fake_results("correct")
    logs = execution_logs(results)
    assert set(logs.keys()) == set(BUILD_ORDER)
    for b in BUILD_ORDER:
        assert "valid_ping" in logs[b]
        entry = logs[b]["valid_ping"]
        assert entry["kind"] == "valid"
        assert entry["outcome"] == "NORMAL"
        assert not entry["flaky"]


def test_report_paths_are_relative_to_the_run_dir(tmp_path):
    ctx = _make_context(tmp_path, scenario="incomplete")
    analyze_and_report(ctx)
    data = json.loads((ctx.out_dir / "report.json").read_text())
    assert data["target"]["config"] == "inputs/config.yaml"
    assert data["versions"]["diff"]["path"] == "inputs/patch.diff"
    bundles = [f["reproducer"] for f in data["findings"] if f["reproducer"]]
    assert bundles
    for path in bundles:
        assert (ctx.out_dir / path / "reproduce.sh").is_file()


def test_10_2_candidates_run_through_run_once_with_the_new_input(tmp_path, monkeypatch):
    # Minimization candidates run exactly like the matrix runs (same runner),
    # with only the input replaced, and their files are not kept in the run dir.
    from zaraban import runner
    ctx = _make_context(tmp_path)
    seen = {}

    def fake_run_once(binary, test, settings, build, repeat, out_dir, source_root=""):
        seen.update(binary=binary, input=test.input_bytes, name=test.name, build=build,
                    out_dir=Path(out_dir), source_root=source_root)
        return _run_record(test.name, test.kind, build, 1, True, True)

    monkeypatch.setattr(runner, "run_once", fake_run_once)
    test = ctx.tests[-1]
    outcome = analysis_stage.run_once_with_input(ctx, test, BuildName.PATCH_SANITIZED, b"SET x")

    assert outcome.crashed and outcome.signature == SIG
    assert seen["input"] == b"SET x" and seen["name"] == test.name
    assert seen["binary"] == ctx.out_dir / "builds/patch-sanitized/bin/token_parser"
    assert seen["source_root"] == str(ctx.work_dir / "patch-sanitized")
    assert ctx.out_dir not in seen["out_dir"].parents and not seen["out_dir"].exists()
