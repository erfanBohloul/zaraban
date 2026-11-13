"""Unit tests for the pipeline wiring (Phase 2 step 0, commit 3).

RunContext is covered by test_pipeline_state.py and the stage stubs by
test_stage_seams.py; this file only tests that pipeline.run builds the context
and calls the two stages in order, with fakes injected so no stage needs to be
implemented yet.
"""

from types import SimpleNamespace

from zaraban import pipeline
from zaraban.models import Issue
from zaraban.pipeline_state import RunContext


# -- run id ------------------------------------------------------------------

def test_new_run_id_is_unique():
    assert pipeline.new_run_id() != pipeline.new_run_id()


# -- the pipeline wires the two stages in order ------------------------------

def test_pipeline_calls_stages_in_order(tmp_path):
    order = []

    def fake_exec(ctx: RunContext) -> RunContext:
        order.append("exec")
        ctx.results = {}  # pretend the matrix ran
        return ctx

    def fake_report(ctx: RunContext) -> int:
        order.append("report")
        assert ctx.results == {}  # exec ran first and its output is visible here
        return 10

    rc = pipeline.run(
        SimpleNamespace(out=str(tmp_path / "out")),
        SimpleNamespace(name="t"),
        [Issue("NO_INVALID_TESTS", "x")],
        build_and_execute=fake_exec,
        analyze_and_report=fake_report,
    )
    assert order == ["exec", "report"]
    assert rc == 10


def test_pipeline_passes_initialized_context_to_first_stage(tmp_path):
    seen = {}

    def fake_exec(ctx: RunContext) -> RunContext:
        seen["run_id"] = ctx.run_id
        seen["out"] = ctx.out_dir
        seen["work"] = ctx.work_dir
        seen["warnings"] = [w.code for w in ctx.warnings]
        return ctx

    pipeline.run(
        SimpleNamespace(out=str(tmp_path / "out")),
        SimpleNamespace(name="t"),
        [Issue("NO_INVALID_TESTS", "x")],
        build_and_execute=fake_exec,
        analyze_and_report=lambda ctx: 0,
    )
    assert seen["run_id"]
    assert seen["out"] == tmp_path / "out"
    assert seen["work"] == tmp_path / "out" / "work"
    assert seen["warnings"] == ["NO_INVALID_TESTS"]  # config warnings carried in


def test_pipeline_defaults_out_dir_when_arg_missing():
    # args without .out -> defaults to "out" (getattr fallback).
    seen = {}
    pipeline.run(
        SimpleNamespace(),  # no .out attribute
        SimpleNamespace(name="t"),
        None,               # no warnings
        build_and_execute=lambda ctx: seen.setdefault("ctx", ctx) or ctx,
        analyze_and_report=lambda ctx: 0,
    )
    assert str(seen["ctx"].out_dir) == "out"
    assert seen["ctx"].warnings == []


# -- the CLI's injection seam still reaches this pipeline --------------------

def test_cli_imports_pipeline_run():
    # cli.main does `from .pipeline import run` when no runner is injected.
    from zaraban.pipeline import run as pipeline_run
    assert callable(pipeline_run)
