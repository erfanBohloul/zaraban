"""End-to-end tests for Zaraban (SPEC §2, §8.9, §13).

Validates the full tool behavior on targets/target1_sample (token_parser):
- correct patch -> exit 0 / PASS
- incomplete patch -> exit 10 / VULN_REMAINS
- behavior-breaking (regression) patch -> exit 20 / FUNC_REGRESSION
- bad config -> exit 30 / BUILD_OR_CONFIG_ERROR

Asserts report.json and summary.txt are written and valid.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import pytest

from zaraban import cli, diffinfo, exec_stage, pipeline, runner
from zaraban.builder import BuildSet
from zaraban.models import (
    BUILD_ORDER,
    Analysis,
    BinaryInfo,
    BuildName,
    BuildRecord,
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
    TestKind,
    VersionInfo,
)
from zaraban.pipeline_state import RunContext
from zaraban.reproducer import RunOutcome
from zaraban.sources import Sources, prepare

SIG = "STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main"
TARGET1_DIR = Path("targets/target1_sample")
TARGET1_CONFIG = TARGET1_DIR / "zaraban.yaml"
PATCH_CORRECT = TARGET1_DIR / "patches/correct.patch"
PATCH_INCOMPLETE = TARGET1_DIR / "patches/incomplete.patch"
PATCH_REGRESSION = TARGET1_DIR / "patches/regression.patch"

REQUIRED_REPORT_KEYS = [
    "schema_version",
    "tool",
    "run_id",
    "started_at",
    "duration_s",
    "target",
    "versions",
    "environment",
    "settings",
    "builds",
    "hardening",
    "execution_logs",
    "findings",
    "regression_added",
    "status",
    "warnings",
    "errors",
]


# ---------------------------------------------------------------------------
# Helpers for running E2E before & after Person 1 merges exec_stage
# ---------------------------------------------------------------------------

def _is_exec_stage_implemented() -> bool:
    try:
        from zaraban import exec_stage
        import inspect
        src = inspect.getsource(exec_stage.build_and_execute)
        return "NotImplementedError" not in src
    except Exception:
        return False


def _build_fake_token_parser_exec(patch_name: str):
    """Produces the execution stage results for token_parser (§8.9)."""
    def _exec(ctx: RunContext) -> RunContext:
        # Prepare sources
        patch_path = Path(ctx.args.patch)
        ctx.sources = prepare(
            base_arg=ctx.target.base_dir,
            patch_arg=patch_path,
            work_dir=ctx.work_dir,
        )

        # Build records
        records = {}
        for name in BUILD_ORDER:
            bin_rel = f"builds/{name.value}/bin/token_parser"
            bin_path = ctx.out_dir / bin_rel
            bin_path.parent.mkdir(parents=True, exist_ok=True)
            bin_path.write_bytes(b"\x7fELFtoken_parser")
            records[name] = BuildRecord(
                build=name,
                status="ok",
                cmd="make",
                env={},
                cwd=str(ctx.work_dir),
                exit_code=0,
                duration_s=0.2,
                log=f"builds/{name.value}/build.log",
                binary=BinaryInfo(bin_rel, 16, "e" * 64),
                sanitizers_verified=True if "sanitized" in name.value else None,
                has_debug_info=True if "sanitized" in name.value else None,
            )
        ctx.build_set = BuildSet(records=records)

        # Hardening
        p = ProtectionResult(True, "verified")
        hres = HardeningResult(nx=p, pie=p, relro=ProtectionResult(Relro.FULL, "verified"), canary=p)
        ctx.hardening = HardeningReport(base=hres, patch=hres, changes=[], notes=["Hardening verified."])

        # Environment
        ctx.environment = EnvironmentInfo(
            os="Linux",
            kernel="5.15",
            arch="x86_64",
            docker_image="zaraban:latest",
            python="3.12.0",
            gcc="11.4.0",
            clang="14.0.0",
            llvm_symbolizer="/usr/bin/llvm-symbolizer",
        )

        # Execution matrix for token_parser (§8.9)
        tests = ctx.target.all_tests()
        results: dict[str, dict[BuildName, CombinedResult]] = {}
        for tc in tests:
            results[tc.name] = {}
            for bname in BUILD_ORDER:
                crashed = False
                passed = True
                if tc.kind is TestKind.SECURITY:
                    if "base" in bname.value:
                        crashed = True
                    elif patch_name == "incomplete" and tc.name == "exploit_secondary":
                        crashed = True
                elif patch_name == "regression" and tc.name == "valid_set" and "patch" in bname.value:
                    passed = False

                outcome = Outcome.CRASH if crashed else Outcome.NORMAL
                runs = []
                for r in (1, 2, 3):
                    analysis = Analysis(
                        outcome=outcome,
                        detection=Detection.ASAN if crashed else None,
                        error_type=ErrorType.STACK_BUFFER_OVERFLOW if crashed else None,
                        summary="stack-buffer-overflow in handle_set_command" if crashed else "normal exit",
                        frames=[Frame(0, "handle_set_command", "src/main.c", 37, False)] if crashed else [],
                        signature=SIG if crashed else None,
                    )
                    runs.append(
                        RunRecord(
                            test=tc.name,
                            kind=tc.kind,
                            build=bname,
                            repeat=r,
                            cmd=["token_parser", "input.txt"],
                            env={},
                            cwd=str(ctx.work_dir),
                            input=InputInfo(InputMethod.FILE, "input.txt", len(tc.input_bytes or b""), "0" * 64),
                            exit_code=None if crashed else (0 if passed else 1),
                            signal="SIGABRT" if crashed else None,
                            timed_out=False,
                            limit_hit=None,
                            duration_s=0.01,
                            stdout=StreamInfo(f"{r}.stdout", 4, "a" * 64, False),
                            stderr=StreamInfo(f"{r}.stderr", 100, "b" * 64, False),
                            analysis=analysis,
                            oracle=OracleResult(checked=True, passed=passed),
                        )
                    )
                results[tc.name][bname] = CombinedResult(
                    test=tc.name,
                    kind=tc.kind,
                    build=bname,
                    runs=runs,
                    flaky=False,
                )
        ctx.results = results

        # Simulated run function for reproducer ddmin / replay
        def fake_run(data: bytes) -> RunOutcome:
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

        setattr(ctx, "_run_fn", fake_run)
        return ctx

    return _exec


def run_e2e(argv: list[str], patch_kind: Optional[str] = None) -> int:
    """Run E2E via CLI, falling back to simulated execution if exec_stage is a stub."""
    if _is_exec_stage_implemented():
        return cli.main(argv)

    if patch_kind is not None:
        fake_exec = _build_fake_token_parser_exec(patch_kind)

        def custom_run(args, target, warnings):
            return pipeline.run(args, target, warnings, build_and_execute=fake_exec)

        return cli.main(argv, run=custom_run)

    return cli.main(argv)


# ---------------------------------------------------------------------------
# E2E Tests
# ---------------------------------------------------------------------------

def test_e2e_bad_config_missing_file(tmp_path):
    """Exit 30 when config file does not exist."""
    rc = run_e2e(["-c", str(tmp_path / "nonexistent.yaml"), "--patch", str(PATCH_CORRECT)])
    assert rc == 30


def test_e2e_bad_config_missing_patch(tmp_path):
    """Exit 30 when --patch is missing without --check-config."""
    rc = run_e2e(["-c", str(TARGET1_CONFIG)])
    assert rc == 30


def test_e2e_bad_config_invalid_schema(tmp_path):
    """Exit 30 when config YAML is semantically invalid."""
    bad_cfg = tmp_path / "bad.yaml"
    bad_cfg.write_text("invalid_key: true\nname: 12345\n")
    rc = run_e2e(["-c", str(bad_cfg), "--patch", str(PATCH_CORRECT)])
    assert rc == 30


def test_e2e_correct_patch_scenario(tmp_path):
    """Correct patch -> exit 0 / PASS; report.json and summary.txt valid."""
    out_dir = tmp_path / "out_correct"
    argv = [
        "-c", str(TARGET1_CONFIG),
        "--patch", str(PATCH_CORRECT),
        "--out", str(out_dir),
        "--no-promote",
    ]
    rc = run_e2e(argv, patch_kind="correct")
    assert rc == 0

    report_path = out_dir / "report.json"
    summary_path = out_dir / "summary.txt"
    assert report_path.is_file(), "report.json was not created"
    assert summary_path.is_file(), "summary.txt was not created"

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"]["exit_code"] == 0
    assert report["status"]["exit_name"] == "PASS"

    checks = report["status"]["checks"]
    assert checks["builds_ok"] is True
    assert checks["profiles_verified"] is True
    assert checks["all_runs_completed"] is True
    assert checks["base_reproduced"] is True
    assert checks["results_stable"] is True
    assert checks["bundles_replayed"] is True
    assert checks["hardening_checked"] is True

    findings = report["findings"]
    assert len(findings) >= 1
    assert any(f["category"] == "FIXED" for f in findings)


def test_e2e_incomplete_patch_scenario(tmp_path):
    """Known-incomplete patch -> exit 10 / VULN_REMAINS; report.json valid."""
    out_dir = tmp_path / "out_incomplete"
    argv = [
        "-c", str(TARGET1_CONFIG),
        "--patch", str(PATCH_INCOMPLETE),
        "--out", str(out_dir),
        "--no-promote",
    ]
    rc = run_e2e(argv, patch_kind="incomplete")
    assert rc == 10

    report_path = out_dir / "report.json"
    assert report_path.is_file()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"]["exit_code"] == 10
    assert report["status"]["exit_name"] == "VULN_REMAINS"
    assert any(f["category"] == "INCOMPLETE_FIX" for f in report["findings"])


def test_e2e_regression_patch_scenario(tmp_path):
    """Behavior-breaking (regression) patch -> exit 20 / FUNC_REGRESSION."""
    out_dir = tmp_path / "out_regression"
    argv = [
        "-c", str(TARGET1_CONFIG),
        "--patch", str(PATCH_REGRESSION),
        "--out", str(out_dir),
        "--no-promote",
    ]
    rc = run_e2e(argv, patch_kind="regression")
    assert rc == 20

    report_path = out_dir / "report.json"
    assert report_path.is_file()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"]["exit_code"] == 20
    assert report["status"]["exit_name"] == "FUNC_REGRESSION"
    assert any(f["category"] == "FUNCTIONAL_REGRESSION" for f in report["findings"])


def test_e2e_report_json_schema(tmp_path):
    """Validate all required top-level keys in report.json (SPEC §12.4)."""
    out_dir = tmp_path / "out_schema"
    argv = [
        "-c", str(TARGET1_CONFIG),
        "--patch", str(PATCH_CORRECT),
        "--out", str(out_dir),
        "--no-promote",
    ]
    rc = run_e2e(argv, patch_kind="correct")
    assert rc == 0

    report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    for key in REQUIRED_REPORT_KEYS:
        assert key in report, f"Missing key in report.json: {key}"

    assert report["schema_version"] == 1
    assert "name" in report["tool"]
    assert "version" in report["tool"]
    assert "target" in report and report["target"]["name"] == "token_parser"
    assert "builds" in report
    assert "status" in report
    assert "execution_logs" in report
