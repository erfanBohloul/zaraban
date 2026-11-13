"""Stage 2 of the pipeline: analyze and report (SPEC §2 steps 6–11).

Person 2 (Phase 2) implements this. It reads the filled
:class:`~zaraban.pipeline_state.RunContext` and drives the diff parse,
findings and links (Member C), the reproducers and regression tests
(Member D), the status decision and the report writer — then returns the
process exit code.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from . import analysis, diffinfo, findings, linking, models, regression, report, reproducer, runner, status
from .models import (
    BUILD_ORDER,
    BuildName,
    BuildRecord,
    Bundle,
    Checks,
    EnvironmentInfo,
    Finding,
    InputMethod,
    Issue,
    LimitKind,
    Outcome,
    Profile,
    RegressionTest,
    Results,
    TestCase,
    TestKind,
    Version,
)
from .pipeline_state import RunContext
from .reproducer import RunOutcome
from .pipeline_state import RunContext
from .runner import RunSettings


def analyze_and_report(
    ctx: RunContext,
    *,
    run_fn: Optional[reproducer.RunFn] = None,
) -> int:
    """Drive findings -> reproducers -> regression -> status -> report (6–11).

    Completes ``ctx.checks``, writes ``report.json`` and ``summary.txt``, and
    returns the final exit code (``status.exit_code``).
    """
    # -----------------------------------------------------------------------
    # Step 6: Diff hunks (Member C)
    # -----------------------------------------------------------------------
    hunks: list[diffinfo.Hunk] = []
    if ctx.sources is not None:
        try:
            hunks = diffinfo.sources_hunks(ctx.sources)
        except Exception as exc:
            ctx.warnings.append(
                Issue(
                    "DIFF_PARSE_FAILED",
                    f"Could not parse diff hunks: {exc}",
                    {"error": str(exc)},
                )
            )

    # -----------------------------------------------------------------------
    # Step 7: Findings and patch links (Member C)
    # -----------------------------------------------------------------------
    findings_list: list[Finding] = []
    if ctx.results is not None:
        target_test_names: Optional[list[str]] = None
        if ctx.target and hasattr(ctx.target, "all_tests"):
            try:
                target_test_names = [t.name for t in ctx.target.all_tests()]
            except Exception:
                target_test_names = None

        findings_order: Optional[list[str]] = None
        if target_test_names is not None and set(target_test_names) == set(ctx.results.keys()):
            findings_order = target_test_names

        findings_list = findings.build_findings(ctx.results, findings_order)

        if hunks and ctx.sources is not None:
            try:
                findings_list = linking.link_findings(
                    findings_list,
                    ctx.results,
                    hunks,
                    ctx.sources.base_tree,
                    ctx.sources.patch_tree,
                )
            except Exception as exc:
                ctx.warnings.append(
                    Issue(
                        "LINK_FINDINGS_FAILED",
                        f"Diff linking could not run: {exc}",
                        {"error": str(exc)},
                    )
                )
                for f in findings_list:
                    if f.link is None:
                        f.link = models.Link(level=models.LinkLevel.UNDETERMINED)
        else:
            for f in findings_list:
                if f.link is None:
                    f.link = models.Link(level=models.LinkLevel.UNDETERMINED)

    # -----------------------------------------------------------------------
    # Step 8 & 9: Reproducers and regression tests (Member D)
    # -----------------------------------------------------------------------
    bundles: list[Bundle] = []
    regression_tests: list[RegressionTest] = []
    repro_warnings: list[Issue] = []
    regr_warnings: list[Issue] = []

    tests_by_name: dict[str, TestCase] = {}
    if ctx.target and hasattr(ctx.target, "all_tests"):
        try:
            tests_by_name = {t.name: t for t in ctx.target.all_tests()}
        except Exception:
            tests_by_name = {}

    versions_dict: dict[str, Any] = {}
    if ctx.sources is not None:
        versions_dict = {
            "base": ctx.sources.base,
            "patch": ctx.sources.patch,
            "diff": ctx.sources.diff,
        }

    for f in findings_list:
        bname = reproducer.bundle_build(f.category)
        if bname is None:
            continue
        source_test_name = reproducer.source_test(f)
        if source_test_name is None:
            continue
        combined = ctx.results.get(source_test_name, {}).get(bname) if ctx.results else None
        if combined is None or not combined.runs:
            continue
        source_rec = combined.first

        tc = tests_by_name.get(source_test_name)
        input_bytes = tc.input_bytes if tc and tc.input_bytes is not None else b""
        input_ext = tc.input_ext if tc and tc.input_ext else ".txt"
        if input_ext and not input_ext.startswith("."):
            input_ext = f".{input_ext}"

        build_rec = (
            ctx.build_set.records.get(bname)
            if ctx.build_set and ctx.build_set.records
            else None
        )
        if build_rec is None or build_rec.binary is None:
            continue

        active_run_fn = run_fn or getattr(ctx, "_run_fn", None) or _make_run_fn(ctx, build_rec, tc, bname)

        try:
            bundle, issues = reproducer.reproduce(
                finding=f,
                source=source_rec,
                input_bytes=input_bytes,
                input_ext=input_ext,
                build=build_rec,
                run_dir=ctx.out_dir,
                run=active_run_fn,
                versions=versions_dict,
                environment=ctx.environment,
            )
            bundles.append(bundle)
            repro_warnings.extend(issues)
            reproducer.apply_bundle(f, bundle)
        except Exception as exc:
            ctx.warnings.append(
                Issue(
                    "REPRODUCE_FAILED",
                    f"{f.id}: could not create reproducer bundle: {exc}",
                    {"finding": f.id, "error": str(exc)},
                )
            )
            continue

        # Step 9: Regression test (§10.6)
        base_bname = BuildName.BASE_SANITIZED
        base_build_rec = (
            ctx.build_set.records.get(base_bname)
            if ctx.build_set and ctx.build_set.records
            else None
        )
        run_base = (
            run_fn
            or getattr(ctx, "_run_base_fn", None)
            or (
                _make_run_fn(ctx, base_build_rec, tc, base_bname)
                if base_build_rec and base_build_rec.binary and tc
                else lambda data: RunOutcome(crashed=False, signature=None, exit_code=0)
            )
        )

        replayed_path = ctx.out_dir / bundle.path / f"input.{bundle.replayed_input}{input_ext}"
        if replayed_path.exists():
            replayed_bytes = replayed_path.read_bytes()
        else:
            replayed_bytes = input_bytes

        source_kind = tc.kind if tc else TestKind.SECURITY
        regression_dir = (
            Path(ctx.target.config_dir) / getattr(ctx.target.spec, "regression_dir", "tests/regression")
            if ctx.target and hasattr(ctx.target, "config_dir")
            else ctx.out_dir / "regression"
        )
        promote = not getattr(ctx.args, "no_promote", False)
        base_ver = ctx.sources.base.git_commit if ctx.sources and ctx.sources.base else None
        base_sha = (
            base_build_rec.binary.sha256
            if base_build_rec and base_build_rec.binary
            else None
        )

        try:
            reg_test, r_issues = regression.add_regression(
                finding=f,
                bundle=bundle,
                input_bytes=replayed_bytes,
                input_ext=input_ext,
                source_kind=source_kind,
                signature=f.signature,
                run_base=run_base,
                run_id=ctx.run_id,
                base_version=base_ver,
                base_binary_sha256=base_sha,
                out_dir=ctx.out_dir,
                regression_dir=regression_dir,
                promote=promote,
            )
            if reg_test is not None:
                regression_tests.append(reg_test)
            regr_warnings.extend(r_issues)
        except Exception as exc:
            ctx.warnings.append(
                Issue(
                    "REGRESSION_FAILED",
                    f"{f.id}: could not add regression test: {exc}",
                    {"finding": f.id, "error": str(exc)},
                )
            )

    # -----------------------------------------------------------------------
    # Step 10: Checks and status determination (SPEC §13)
    # -----------------------------------------------------------------------
    base_not_reproduced: list[str] = []
    if ctx.results is not None:
        sec_names = []
        if ctx.target and hasattr(ctx.target, "all_tests"):
            try:
                sec_names = [t.name for t in ctx.target.all_tests() if t.kind is TestKind.SECURITY]
            except Exception:
                sec_names = []
        if not sec_names:
            sec_names = [
                t for t, by_b in ctx.results.items()
                if any(c.kind is TestKind.SECURITY for c in by_b.values())
            ]
        for st in sec_names:
            c = ctx.results.get(st, {}).get(BuildName.BASE_SANITIZED)
            if c is None or c.outcome is not Outcome.CRASH:
                base_not_reproduced.append(st)

    checks = build_checks(ctx, bundles, base_not_reproduced)
    ctx.checks = checks

    warnings = list(ctx.warnings)
    warnings.extend(repro_warnings)
    warnings.extend(regr_warnings)
    if ctx.build_set:
        warnings.extend(ctx.build_set.warnings)

    errors = list(ctx.errors)
    if ctx.build_set and ctx.build_set.error:
        errors.append(ctx.build_set.error)

    status_obj = status.compute_status(
        findings=findings_list,
        checks=checks,
        errors=errors,
        base_not_reproduced=base_not_reproduced,
    )

    # -----------------------------------------------------------------------
    # Step 11: Report assembly and writing (SPEC §12)
    # -----------------------------------------------------------------------
    environment = ctx.environment
    if environment is None:
        environment = EnvironmentInfo(
            os=platform.system(),
            kernel=platform.release(),
            arch=platform.machine(),
            docker_image=os.environ.get("DOCKER_IMAGE"),
            python=platform.python_version(),
            gcc=None,
            clang=None,
            llvm_symbolizer=None,
        )

    settings_dict = dict(ctx.settings)
    if "repeats" not in settings_dict:
        settings_dict["repeats"] = (
            getattr(ctx.target.spec, "repeats", 3)
            if ctx.target and hasattr(ctx.target, "spec")
            else 3
        )
    if "limits" not in settings_dict and ctx.target and hasattr(ctx.target, "spec") and hasattr(ctx.target.spec, "limits"):
        settings_dict["limits"] = {
            "timeout_seconds": float(ctx.target.spec.limits.timeout_seconds),
            "memory_limit_mb": int(ctx.target.spec.limits.memory_limit_mb),
        }

    duration_s = 0.0
    if ctx.started_at:
        try:
            t_start = datetime.fromisoformat(ctx.started_at.replace("Z", "+00:00"))
            duration_s = max(0.0, (datetime.now(timezone.utc) - t_start).total_seconds())
        except Exception:
            duration_s = 0.0

    target_name = ctx.target.name if ctx.target and hasattr(ctx.target, "name") else ""
    config_path = str(ctx.target.config_path) if ctx.target and hasattr(ctx.target, "config_path") else ""
    config_sha256 = ""
    if config_path and Path(config_path).exists():
        try:
            config_sha256 = hashlib.sha256(Path(config_path).read_bytes()).hexdigest()
        except Exception:
            config_sha256 = ""

    builds_entries = {}
    if ctx.build_set and ctx.build_set.records:
        builds_entries = report.build_entries(ctx.build_set.records)

    exec_logs = getattr(ctx, "execution_logs", None)
    if exec_logs is None and ctx.results is not None:
        exec_logs = format_execution_logs(ctx.results)

    rep = report.assemble_report(
        run_id=ctx.run_id,
        started_at=ctx.started_at,
        duration_s=duration_s,
        target_name=target_name,
        config_path=config_path,
        config_sha256=config_sha256,
        versions=versions_dict,
        environment=environment,
        settings=settings_dict,
        builds=builds_entries,
        status=status_obj,
        execution_logs=exec_logs,
        hardening=ctx.hardening,
        findings=findings_list,
        regression_added=regression_tests,
        warnings=warnings,
        errors=errors,
    )

    ctx.out_dir.mkdir(parents=True, exist_ok=True)
    report.write(rep, ctx.out_dir, bundles=bundles)

    if not getattr(ctx.args, "keep_work", False) and ctx.work_dir.exists():
        shutil.rmtree(ctx.work_dir, ignore_errors=True)

    return int(status_obj.exit_code)


def build_checks(
    ctx: RunContext,
    bundles: list[Bundle],
    base_not_reproduced: list[str],
) -> Checks:
    """Build the Checks object from stage outputs (SPEC §13.2)."""
    # 1. builds_ok
    builds_ok = ctx.checks.builds_ok or (
        ctx.build_set is not None and ctx.build_set.ok
    )

    # 2. profiles_verified
    profiles_verified = ctx.checks.profiles_verified or (
        ctx.build_set is not None
        and ctx.build_set.ok
        and all(r.sanitizers_verified is not False for r in ctx.build_set.records.values())
    )

    # 3. all_runs_completed
    repeats = 3
    if ctx.target and hasattr(ctx.target, "spec") and hasattr(ctx.target.spec, "repeats"):
        repeats = ctx.target.spec.repeats
    elif "repeats" in ctx.settings:
        repeats = ctx.settings["repeats"]

    if ctx.checks.all_runs_completed:
        all_runs_completed = True
    elif ctx.results is not None:
        expected_tests = set(ctx.results.keys())
        if ctx.target and hasattr(ctx.target, "all_tests"):
            target_tests = {t.name for t in ctx.target.all_tests()}
            if target_tests:
                expected_tests = target_tests
        all_runs_completed = bool(
            ctx.results
            and expected_tests.issubset(ctx.results.keys())
            and all(
                len(ctx.results[t]) == len(BUILD_ORDER)
                and all(len(c.runs) >= repeats for c in ctx.results[t].values())
                for t in expected_tests
                if t in ctx.results
            )
        )
    else:
        all_runs_completed = False

    # 4. base_reproduced
    if ctx.checks.base_reproduced:
        base_reproduced = True
    elif ctx.results is not None:
        base_reproduced = (len(base_not_reproduced) == 0)
    else:
        base_reproduced = False

    # 5. results_stable
    if ctx.checks.results_stable:
        results_stable = True
    elif ctx.results is not None:
        results_stable = not any(
            c.flaky for by_build in ctx.results.values() for c in by_build.values()
        )
    else:
        results_stable = False

    # 6. bundles_replayed
    if ctx.checks.bundles_replayed:
        bundles_replayed = True
    elif bundles:
        bundles_replayed = all(b.stable for b in bundles)
    else:
        bundles_replayed = True

    # 7. hardening_checked
    hardening_checked = ctx.checks.hardening_checked or (ctx.hardening is not None)

    return Checks(
        builds_ok=builds_ok,
        profiles_verified=profiles_verified,
        all_runs_completed=all_runs_completed,
        base_reproduced=base_reproduced,
        results_stable=results_stable,
        bundles_replayed=bundles_replayed,
        hardening_checked=hardening_checked,
    )


def format_execution_logs(results: Results) -> dict[BuildName, dict[str, dict[str, Any]]]:
    """Format execution logs dictionary matching SPEC §12.4."""
    logs: dict[BuildName, dict[str, dict[str, Any]]] = {b: {} for b in BUILD_ORDER}
    for test_name, by_build in results.items():
        for bname, combined in by_build.items():
            if not combined.runs:
                continue
            first = combined.first
            a = first.analysis
            top_frame = None
            if a.app_frames:
                f0 = a.app_frames[0]
                top_frame = f"{f0.function} {f0.file or '?'}:{f0.line or '?'}"
            logs.setdefault(bname, {})[test_name] = {
                "kind": combined.kind.value if hasattr(combined.kind, "value") else str(combined.kind),
                "outcome": combined.outcome.value if hasattr(combined.outcome, "value") else str(combined.outcome),
                "exit_code": first.exit_code,
                "signal": first.signal,
                "detection": a.detection.value if hasattr(a.detection, "value") and a.detection else None,
                "error_type": a.error_type.value if hasattr(a.error_type, "value") and a.error_type else None,
                "signature": combined.signature,
                "top_frame": top_frame,
                "oracle_passed": combined.oracle_passed,
                "flaky": combined.flaky,
                "runs": f"runs/{test_name}/{bname.value}/",
            }
    return logs


def _make_run_fn(
    ctx: RunContext,
    build_rec: BuildRecord,
    tc: Optional[TestCase],
    build_name: BuildName,
) -> reproducer.RunFn:
    if tc is None or build_rec.binary is None:
        return lambda data: RunOutcome(crashed=False, signature=None, exit_code=0)

    binary_path = ctx.out_dir / build_rec.binary.path
    if not binary_path.exists():
        direct = Path(build_rec.binary.path)
        if direct.exists():
            binary_path = direct

    source_root = ""
    if ctx.sources:
        source_root = str(
            ctx.sources.patch_tree
            if build_name.version is Version.PATCH
            else ctx.sources.base_tree
        )

    def run_fn(data: bytes) -> RunOutcome:
        if not binary_path.exists():
            return RunOutcome(crashed=False, signature=None, exit_code=1)
        try:
            return _execute_candidate(
                binary_path=binary_path,
                test=tc,
                data=data,
                target=ctx.target,
                build_name=build_name,
                source_root=source_root,
            )
        except Exception:
            return RunOutcome(crashed=False, signature=None, exit_code=1)

    return run_fn


def _execute_candidate(
    binary_path: Path,
    test: TestCase,
    data: bytes,
    target: Any,
    build_name: BuildName,
    source_root: str = "",
) -> RunOutcome:
    settings = RunSettings.from_target(target)
    sanitized = build_name.profile is Profile.SANITIZED
    exe = str(binary_path.resolve())
    args = list(test.args)
    stdin_bytes = b""
    input_name: Optional[str] = None
    method = settings.input_method

    if method is InputMethod.FILE:
        ext = test.input_ext or ".txt"
        if not ext.startswith("."):
            ext = f".{ext}"
        input_name = f"input{ext}"
        ph = settings.file_arg_placeholder
        if any(ph in a for a in args):
            args = [a.replace(ph, input_name) for a in args]
        else:
            args.append(input_name)
    elif method is InputMethod.STDIN:
        stdin_bytes = data or b""
    elif data is not None:  # args
        if b"\0" in data:
            return RunOutcome(crashed=False, signature=None, exit_code=1)
        args.append(os.fsdecode(data))

    env = settings.env_for(sanitized)
    cwd = tempfile.mkdtemp(prefix="zaraban-repro-")
    try:
        if input_name is not None:
            Path(cwd, input_name).write_bytes(data or b"")
        res = runner._execute(
            [exe, *args],
            cwd,
            env,
            stdin_bytes,
            settings.timeout_seconds,
            settings.cpu_seconds,
            None if sanitized else settings.memory_limit_mb * 1024 * 1024,
        )
    finally:
        shutil.rmtree(cwd, ignore_errors=True)

    rc = res.returncode
    sig = runner._signal_name(-rc) if rc < 0 else None
    exit_code = None if rc < 0 else rc
    stderr_text = res.stderr.decode("utf-8", errors="replace")
    limit_hit: Optional[LimitKind] = None
    if not res.timed_out:
        if sig == "SIGXCPU" or (sig == "SIGKILL" and res.cpu_s >= settings.cpu_seconds):
            limit_hit = LimitKind.CPU
        elif sanitized and analysis.is_memory_limit(stderr_text):
            limit_hit = LimitKind.MEMORY

    run_analysis = analysis.analyse(
        stderr=stderr_text,
        stdout=res.stdout.decode("utf-8", errors="replace"),
        exit_code=exit_code,
        sig=sig,
        timed_out=res.timed_out,
        limit_hit=limit_hit,
        source_root=source_root,
    )
    return RunOutcome(
        crashed=run_analysis.is_crash,
        signature=run_analysis.signature,
        signal=sig,
        exit_code=exit_code,
        error_type=run_analysis.error_type,
        detection=run_analysis.detection,
        top_functions=[f.function for f in run_analysis.app_frames if f.function][:3],
        duration_s=round(res.duration_s, 4),
    )
