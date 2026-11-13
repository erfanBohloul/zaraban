"""The Phase 2 pipeline: one run, wired end to end (SPEC §2).

``cli.py`` imports :func:`run` for a full run. It is deliberately **thin**: it
builds the initial :class:`~zaraban.pipeline_state.RunContext`, then calls the
two stages in order and returns the exit code. All the work lives in
:mod:`zaraban.exec_stage` (Person 1) and :mod:`zaraban.analysis_stage`
(Person 2), so only this file sequences them and neither person edits the
other's module.

The two stages are injectable (``build_and_execute`` / ``analyze_and_report``
keyword arguments) so the wiring can be tested with fakes before either stage
is implemented, exactly like ``cli.main``'s ``run=`` seam.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

from . import analysis_stage, exec_stage
from .pipeline_state import RunContext

if TYPE_CHECKING:
    import argparse

    from .config import Target
    from .models import Issue

BuildExecFn = Callable[[RunContext], RunContext]
AnalyzeReportFn = Callable[[RunContext], int]


def run(
    args: "argparse.Namespace",
    target: "Target",
    warnings: Optional[list["Issue"]] = None,
    *,
    build_and_execute: Optional[BuildExecFn] = None,
    analyze_and_report: Optional[AnalyzeReportFn] = None,
) -> int:
    """Run the whole pipeline and return the process exit code (§13.1).

    ``warnings`` are the config-load warnings from the CLI; they carry into the
    report. The two stage functions default to the real modules and are
    overridable for testing.
    """
    build_exec = build_and_execute or exec_stage.build_and_execute
    analyze_report = analyze_and_report or analysis_stage.analyze_and_report

    out_dir = Path(getattr(args, "out", "out"))
    ctx = new_context(args, target, out_dir, warnings or [])
    ctx = build_exec(ctx)
    return analyze_report(ctx)


def new_context(
    args: "argparse.Namespace",
    target: "Target",
    out_dir: Path,
    warnings: list["Issue"],
) -> RunContext:
    """Build the initial context with the always-present fields set."""
    return RunContext(
        args=args,
        target=target,
        work_dir=out_dir / "work",
        out_dir=out_dir,
        run_id=new_run_id(),
        started_at=utc_now_iso(),
        warnings=list(warnings),
    )


def new_run_id() -> str:
    """A short, unique id for this run, used in output paths and the report."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
