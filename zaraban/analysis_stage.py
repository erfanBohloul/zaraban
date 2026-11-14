"""Stage 2 of the pipeline: analyze and report (SPEC §2 steps 6–11).

:func:`analyze` reads the filled :class:`~zaraban.pipeline_state.RunContext`
and runs, in order:

6. the diff hunks (``diffinfo.sources_hunks``);
7. the findings and their links to the patch (``findings``, ``linking``);
8. a reproducer bundle per finding that gets one (``reproducer``, §10.1–§10.5);
9. a regression test per stable bundle (``regression``, §10.6);
   then ``REGRESSION_BASE_CLEAN`` for regression tests of earlier runs that no
   longer crash on base (§8.6), the completeness check (§8.7) and the
   analyze-side checks.

:func:`finish` decides the status and writes ``report.json`` and
``summary.txt`` (steps 10–11). It works with whatever the context holds, so
the pipeline also calls it after a failure, for the partial report (§13.4).
Each step stores its result in the context as soon as it has it.
"""

from __future__ import annotations

import dataclasses
import hashlib
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from . import completeness, coverage, diffinfo, findings, linking, regression, report, reproducer, runner, status
from .exec_stage import binary, source_root
from .models import (BUILD_ORDER, BuildName, Finding, Issue, Outcome, Results, TestCase, TestKind,
                     Version, WarningCode)
from .pipeline_state import CONFIG_COPY, RunContext
from .reproducer import RunOutcome

# run_input(ctx, test, build, data): run ``test`` once on ``build`` with ``data``
# as its input. Injectable so the stage is testable without a real binary.
RunInputFn = Callable[[RunContext, TestCase, BuildName, bytes], RunOutcome]


def analyze_and_report(ctx: RunContext, *, run_input: Optional[RunInputFn] = None) -> int:
    """Run steps 6–11 and return the exit code."""
    analyze(ctx, run_input=run_input)
    return finish(ctx)


# ---------------------------------------------------------------------------
# Steps 6–9
# ---------------------------------------------------------------------------


def analyze(ctx: RunContext, *, run_input: Optional[RunInputFn] = None) -> None:
    """Findings, links, bundles and regression tests (steps 6–9), stored in ``ctx``.

    Does nothing when the execution did not happen (a build failure, §6.2).
    """
    if ctx.results is None:
        return
    run_input = run_input or run_once_with_input

    # 6–7. Findings in run order, then their links to the patch (§8, §9).
    hunks = diffinfo.sources_hunks(ctx.sources)
    ctx.findings = findings.build_findings(ctx.results, [t.name for t in ctx.tests])
    linking.link_findings(ctx.findings, ctx.results, hunks,
                          ctx.sources.base_tree, ctx.sources.patch_tree)
    #      A link still UNDETERMINED gets an execution trace and a second pass (§9.4).
    link_with_traces(ctx, hunks)

    # 8–9. A bundle for each finding that gets one, and its regression test.
    tests = {t.name: t for t in ctx.tests}
    for f in ctx.findings:
        build, test_name = reproducer.bundle_build(f.category), reproducer.source_test(f)
        if build is None or test_name is None:
            continue
        make_bundle(ctx, f, tests[test_name], build, run_input)

    # §8.6: a regression test of an earlier run that no longer crashes on base
    # is a warning, not a finding (Task 2.3).
    ctx.add_warnings(regression.base_clean_warnings(ctx.tests, ctx.results))

    # §8.7: every abnormal result is in a finding (Task 2.4).
    completeness.check(ctx.results, ctx.findings)

    ctx.base_not_reproduced = base_not_reproduced(ctx.tests, ctx.results)
    ctx.checks.base_reproduced = not ctx.base_not_reproduced
    ctx.checks.bundles_replayed = all(b.stable for b in ctx.bundles)


def link_with_traces(ctx: RunContext, hunks: list) -> None:
    """Second linking pass with execution traces (§9.4, Task 2.2).

    The first pass has set every ``finding.link``. A finding whose link is
    ``UNDETERMINED`` but has a side (a crash whose frames match no changed code,
    or a ``FUNCTIONAL_REGRESSION``, which has no crash) gets one run of its test
    on a coverage build of that side, in ``work/<version>-coverage/``. The changed
    lines it executed upgrade the link to ``CHANGED_CODE_EXECUTED``. A trace that
    cannot be made (no ``coverage_cmd``, or the coverage build, run or export
    fails) adds ``TRACE_UNAVAILABLE`` and keeps the first-pass link. The trace
    never changes a category or the exit code (§9.6).
    """
    try:
        traces, warnings = coverage.execution_traces(
            ctx.findings,
            {t.name: t for t in ctx.tests},
            {v: diffinfo.changed_lines_by_file(hunks, v) for v in (Version.BASE, Version.PATCH)},
            {Version.BASE: ctx.sources.base_tree, Version.PATCH: ctx.sources.patch_tree},
            ctx.target,
            ctx.work_dir,
        )
    except OSError as exc:  # e.g. the source tree could not be copied for the coverage build
        ctx.add_warnings([Issue(WarningCode.TRACE_UNAVAILABLE.value,
                                f"no execution trace could be made: {exc}", {"error": str(exc)})])
        return
    ctx.add_warnings(warnings)
    if traces:
        linking.link_findings(ctx.findings, ctx.results, hunks,
                              ctx.sources.base_tree, ctx.sources.patch_tree, traces=traces)


def make_bundle(ctx: RunContext, f: Finding, test: TestCase, build: BuildName,
                run_input: RunInputFn) -> None:
    """The reproducer bundle of one finding (§10.3) and its regression test (§10.6)."""
    source = ctx.results[test.name][build].first
    input_bytes = test.input_bytes or b""
    bundle, issues = reproducer.reproduce(
        finding=f, source=source, input_bytes=input_bytes, input_ext=test.input_ext,
        build=ctx.build_set.records[build], run_dir=ctx.out_dir,
        run=lambda data: run_input(ctx, test, build, data),
        versions=versions(ctx), environment=ctx.environment)
    ctx.bundles.append(bundle)
    ctx.add_warnings(issues)
    reproducer.apply_bundle(f, bundle)

    replayed = ctx.out_dir / bundle.path / f"input.{bundle.replayed_input}{test.input_ext}"
    base = ctx.build_set.records[BuildName.BASE_SANITIZED]
    reg, issues = regression.add_regression(
        finding=f, bundle=bundle, input_bytes=replayed.read_bytes(),
        input_ext=test.input_ext, source_kind=test.kind, signature=source.analysis.signature,
        run_base=lambda data: run_input(ctx, test, BuildName.BASE_SANITIZED, data),
        run_id=ctx.run_id, base_version=ctx.sources.base.git_commit,
        base_binary_sha256=base.binary.sha256, out_dir=ctx.out_dir,
        regression_dir=regression.target_regression_dir(ctx.target),
        promote=not getattr(ctx.args, "no_promote", False))
    if reg is not None:
        ctx.regression_added.append(reg)
    ctx.add_warnings(issues)


def run_once_with_input(ctx: RunContext, test: TestCase, build: BuildName,
                        data: bytes) -> RunOutcome:
    """Run ``test`` once on ``build`` with ``data`` as its input, exactly as the
    matrix runs it (same command, environment and limits, §10.2), through the
    runner's ``run_once``. Its run files go to a temporary directory: they
    are minimization candidates, not results of the run."""
    with tempfile.TemporaryDirectory(prefix="zaraban-candidate-") as tmp:
        rec = runner.run_once(binary(ctx, build), dataclasses.replace(test, input_bytes=data),
                              ctx.run_settings, build, 1, tmp,
                              source_root=source_root(ctx, build))
    return RunOutcome.from_record(rec)


def base_not_reproduced(tests: list[TestCase], results: Results) -> list[str]:
    """The security tests that do not crash on ``base-sanitized`` (§13.2)."""
    return [t.name for t in tests if t.kind is TestKind.SECURITY
            and results[t.name][BuildName.BASE_SANITIZED].outcome is not Outcome.CRASH]


# ---------------------------------------------------------------------------
# Steps 10–11
# ---------------------------------------------------------------------------


def finish(ctx: RunContext) -> int:
    """Decide the status, write ``report.json`` and ``summary.txt``, delete
    ``work/`` unless ``--keep-work``; return the exit code (§12, §13)."""
    st = status.compute_status(findings=ctx.findings, checks=ctx.checks, errors=ctx.errors,
                               base_not_reproduced=ctx.base_not_reproduced)
    config_copy = ctx.out_dir / CONFIG_COPY
    rep = report.assemble_report(
        run_id=ctx.run_id,
        started_at=ctx.started_at,
        duration_s=_seconds_since(ctx.started_at),
        target_name=ctx.target.name,
        config_path=CONFIG_COPY,
        config_sha256=hashlib.sha256(config_copy.read_bytes()).hexdigest(),
        versions=versions(ctx),
        environment=ctx.environment,
        settings=ctx.settings,
        builds=report.build_entries(ctx.build_set.records) if ctx.build_set else {},
        status=st,
        execution_logs=execution_logs(ctx.results) if ctx.results else None,
        hardening=ctx.hardening,
        findings=ctx.findings,
        regression_added=ctx.regression_added,
        warnings=ctx.warnings,
        errors=ctx.errors,
    )
    report.write(rep, ctx.out_dir, bundles=ctx.bundles)
    if not getattr(ctx.args, "keep_work", False):
        shutil.rmtree(ctx.work_dir, ignore_errors=True)
    return int(st.exit_code)


def versions(ctx: RunContext) -> dict[str, Any]:
    """``report.versions`` (§12.4); empty when the sources could not be prepared."""
    if ctx.sources is None:
        return {}
    return {"base": ctx.sources.base, "patch": ctx.sources.patch, "diff": ctx.sources.diff}


def execution_logs(results: Results) -> dict[BuildName, dict[str, dict[str, Any]]]:
    """``report.execution_logs`` (§12.4): per build, per test, the combined
    result of its repeats."""
    logs: dict[BuildName, dict[str, dict[str, Any]]] = {b: {} for b in BUILD_ORDER}
    for test_name, by_build in results.items():
        for build, c in by_build.items():
            first, a = c.first, c.first.analysis
            top = a.app_frames[0] if a.app_frames else None
            logs[build][test_name] = {
                "kind": c.kind.value,
                "outcome": c.outcome.value,
                "exit_code": first.exit_code,
                "signal": first.signal,
                "detection": a.detection.value if a.detection else None,
                "error_type": a.error_type.value if a.error_type else None,
                "signature": c.signature,
                "top_frame": f"{top.function} {top.file or '?'}:{top.line or '?'}" if top else None,
                "oracle_passed": c.oracle_passed,
                "flaky": c.flaky,
                "runs": f"runs/{test_name}/{build.value}/",
            }
    return logs


def _seconds_since(iso: str) -> float:
    started = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - started).total_seconds())
