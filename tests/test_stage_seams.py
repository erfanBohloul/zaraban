"""Unit tests for the two pipeline stage seams (Phase 2 step 0, commit 2).

The stages are stubs until Person 1 and Person 2 implement them. These lock
down that the entry points exist, take a RunContext, and fail loudly (not
silently) while unimplemented.
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from zaraban import analysis_stage, exec_stage
from zaraban.pipeline_state import RunContext


def _ctx() -> RunContext:
    return RunContext(
        args=SimpleNamespace(out="out"),
        target=SimpleNamespace(name="token_parser"),
        work_dir=Path("out/work"),
        out_dir=Path("out"),
        run_id="run-0001",
        started_at="2026-11-13T00:00:00Z",
    )


# -- the entry points exist and take a RunContext ----------------------------

def test_stage_functions_are_callable():
    assert callable(exec_stage.build_and_execute)
    assert callable(analysis_stage.analyze_and_report)


# -- analyze_and_report is still a stub on this branch (Person 2 owns it) ----

def test_analyze_and_report_is_implemented(tmp_path):
    ctx = _ctx()
    ctx.out_dir = tmp_path / "out"
    ctx.work_dir = tmp_path / "out" / "work"
    rc = analysis_stage.analyze_and_report(ctx)
    assert isinstance(rc, int)
    assert (ctx.out_dir / "report.json").exists()
    assert (ctx.out_dir / "summary.txt").exists()
