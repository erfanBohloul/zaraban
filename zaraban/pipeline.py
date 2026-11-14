"""The pipeline: one run, wired end to end.

``cli.py`` imports :func:`run` for a full run. This module owns the run's
set-up and its safety net; the work itself lives in :mod:`zaraban.exec_stage`
(builds, hardening, execution) and :mod:`zaraban.analysis_stage` (findings,
reproducers, status, report):

1. :func:`start_run` prepares the sources, creates the run directory
   ``out/<target>/<run id>/`` with ``inputs/`` and builds the
   :class:`~zaraban.pipeline_state.RunContext`;
2. the two stages run in order;
3. whatever goes wrong, a report is still written: a
   :class:`~zaraban.models.ZarabanError` becomes its error (exit 30), and any
   other exception becomes ``TOOL_INTERNAL`` with the traceback in
   ``errors.log`` (exit 30).

The two stages are injectable (``build_and_execute`` / ``analyze_and_report``)
so the wiring is testable with fakes, like ``cli.main``'s ``run=`` seam.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import shutil
import tempfile
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

from . import analysis_stage, environment, exec_stage, runner, sources
from .models import ErrorCode, Issue, ZarabanError
from .pipeline_state import CONFIG_COPY, DIFF_COPY, RunContext

if TYPE_CHECKING:
    import argparse

    from .config import Target

BuildExecFn = Callable[[RunContext], RunContext]
AnalyzeReportFn = Callable[[RunContext], int]

ERRORS_LOG = "errors.log"


def run(
    args: "argparse.Namespace",
    target: "Target",
    warnings: Optional[list[Issue]] = None,
    *,
    build_and_execute: Optional[BuildExecFn] = None,
    analyze_and_report: Optional[AnalyzeReportFn] = None,
) -> int:
    """Run the whole pipeline and return the process exit code.

    ``warnings`` are the config-load warnings from the CLI; they carry into the
    report.
    """
    build_exec = build_and_execute or exec_stage.build_and_execute
    analyze_report = analyze_and_report or analysis_stage.analyze_and_report

    ctx = start_run(args, target, list(warnings or []))
    if ctx.errors:  # the sources could not be prepared: report the error
        return analysis_stage.finish(ctx)
    try:
        ctx = build_exec(ctx)
        return analyze_report(ctx)
    except ZarabanError as exc:
        if exc.code is ErrorCode.TOOL_INTERNAL:
            write_errors_log(ctx.out_dir, traceback.format_exc())
        ctx.add_errors([exc.to_issue()])
    except Exception as exc:  # a bug in the tool
        write_errors_log(ctx.out_dir, traceback.format_exc())
        ctx.add_errors([internal_error(exc)])
    return analysis_stage.finish(ctx)


# ---------------------------------------------------------------------------
# Run set-up
# ---------------------------------------------------------------------------


def start_run(args: "argparse.Namespace", target: "Target", warnings: list[Issue]) -> RunContext:
    """Prepare the sources and the run directory; return the initial context.

    The run id needs the diff's hash, which is only known once the sources are
    prepared, so they are prepared in a temporary directory next to the runs
    and then moved to ``<run dir>/work``. A source error (``SOURCE_NOT_FOUND``,
    ``PATCH_APPLY_FAILED``) does not stop here: it is put in the context, so
    the run still gets its directory and report.
    """
    started = datetime.now(timezone.utc)
    target_out = Path(getattr(args, "out", None) or "out") / target.name
    target_out.mkdir(parents=True, exist_ok=True)
    tmp_work = Path(tempfile.mkdtemp(prefix=".work-", dir=target_out))

    srcs, error, trace = None, None, None
    try:
        base = getattr(args, "base", None) or target.base_dir
        srcs = sources.prepare(base, args.patch, tmp_work)
    except ZarabanError as exc:
        error = exc.to_issue()
    except Exception as exc:  # a bug in the tool
        error, trace = internal_error(exc), traceback.format_exc()

    diff_sha = srcs.diff.sha256 if srcs else _file_sha256(getattr(args, "patch", None))
    run_dir = _new_run_dir(target_out, new_run_id(started, diff_sha))
    work = run_dir / "work"
    os.replace(tmp_work, work)
    if srcs is not None:
        srcs = _moved(srcs, tmp_work, work)
    _copy_inputs(run_dir, target, srcs)
    if trace is not None:
        write_errors_log(run_dir, trace)

    settings = runner.RunSettings.from_target(target)
    ctx = RunContext(
        args=args, target=target, work_dir=work, out_dir=run_dir, run_id=run_dir.name,
        started_at=started.strftime("%Y-%m-%dT%H:%M:%SZ"), sources=srcs,
        environment=environment.gather(settings.symbolizer), run_settings=settings,
        settings=report_settings(target, settings), warnings=warnings,
    )
    ctx.add_warnings(settings.warnings())  # NO_SYMBOLIZER
    if error is not None:
        ctx.add_errors([error])
    return ctx


def new_run_id(started: datetime, diff_sha256: str) -> str:
    """``20261111-183002-3f2a91c0``: the UTC start time and the first 8 hex
    digits of the diff's SHA-256."""
    return f"{started.strftime('%Y%m%d-%H%M%S')}-{diff_sha256[:8]}"


def report_settings(target: "Target", settings: runner.RunSettings) -> dict:
    """``report.settings``: repeats, limits and the sanitizer options
    that sanitized runs get."""
    sanitized_env = settings.env_for(True)
    return {
        "repeats": target.spec.repeats,
        "limits": {"timeout_seconds": settings.timeout_seconds,
                   "memory_limit_mb": settings.memory_limit_mb},
        "sanitizer_options": {k: sanitized_env[k] for k in ("ASAN_OPTIONS", "UBSAN_OPTIONS")},
    }


def internal_error(exc: BaseException) -> Issue:
    """The ``TOOL_INTERNAL`` error of an unexpected exception."""
    return Issue(ErrorCode.TOOL_INTERNAL.value,
                 f"unexpected error in zaraban (a bug in the tool): {exc!r}",
                 {"exception": type(exc).__name__, "log": ERRORS_LOG})


def write_errors_log(run_dir: Path, text: str) -> None:
    """Append full error details to ``errors.log``."""
    with open(run_dir / ERRORS_LOG, "a", encoding="utf-8") as f:
        f.write(text if text.endswith("\n") else text + "\n")


def _new_run_dir(target_out: Path, run_id: str) -> Path:
    """Create the run's own new directory. Two runs of the same diff in the
    same second get ``-2``, ``-3``, ... so no run overwrites another."""
    candidate, n = target_out / run_id, 1
    while True:
        try:
            candidate.mkdir()
            return candidate
        except FileExistsError:
            n += 1
            candidate = target_out / f"{run_id}-{n}"


def _moved(srcs: sources.Sources, old: Path, new: Path) -> sources.Sources:
    """The same sources after their work directory moved from ``old`` to ``new``."""
    def move(p: Path) -> Path:
        return new / Path(p).relative_to(old)
    return dataclasses.replace(srcs, base_tree=move(srcs.base_tree),
                               patch_tree=move(srcs.patch_tree),
                               diff_path=move(srcs.diff_path))


def _copy_inputs(run_dir: Path, target: "Target", srcs: Optional[sources.Sources]) -> None:
    """``inputs/config.yaml`` and ``inputs/patch.diff``. The report's
    diff path then points at the copy, relative to the run directory."""
    (run_dir / "inputs").mkdir()
    shutil.copyfile(target.config_path, run_dir / CONFIG_COPY)
    if srcs is not None:
        shutil.copyfile(srcs.diff_path, run_dir / DIFF_COPY)
        srcs.diff.path = DIFF_COPY


def _file_sha256(path: Optional[str]) -> str:
    """The hash used for the run id when no diff could be made: that of the
    ``--patch`` file if it is one, else of nothing."""
    data = b""
    if path and Path(path).is_file():
        data = Path(path).read_bytes()
    return hashlib.sha256(data).hexdigest()
