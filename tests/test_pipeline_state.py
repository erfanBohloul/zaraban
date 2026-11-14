"""Unit tests for the shared pipeline state.

RunContext is a plain data container, so these build it directly — no pipeline
or stages needed, which keeps these tests independent of the stages.
"""

from pathlib import Path
from types import SimpleNamespace

from zaraban.models import Checks, Issue
from zaraban.pipeline_state import RunContext


def make(**over) -> RunContext:
    """A RunContext with the always-present fields set; override any of them."""
    base = dict(
        args=SimpleNamespace(out="out"),
        target=SimpleNamespace(name="token_parser"),
        work_dir=Path("out/work"),
        out_dir=Path("out"),
        run_id="20261113-000000-abcd1234",
        started_at="2026-11-13T00:00:00Z",
    )
    base.update(over)
    return RunContext(**base)


# -- the always-present fields -----------------------------------------------

def test_required_fields_are_held():
    ctx = make()
    assert ctx.run_id == "20261113-000000-abcd1234"
    assert ctx.started_at == "2026-11-13T00:00:00Z"
    assert ctx.work_dir == Path("out/work")
    assert ctx.out_dir == Path("out")
    assert ctx.target.name == "token_parser"


# -- stage-filled fields start empty -----------------------------------------

def test_stage_fields_default_to_none():
    ctx = make()
    assert ctx.sources is None
    assert ctx.build_set is None
    assert ctx.hardening is None
    assert ctx.results is None
    assert ctx.environment is None
    assert ctx.run_settings is None


def test_analyze_fields_default_empty():
    ctx = make()
    assert ctx.tests == [] and ctx.findings == [] and ctx.bundles == []
    assert ctx.regression_added == [] and ctx.base_not_reproduced == []


# -- accumulators ------------------------------------------------------------

def test_checks_defaults_to_all_false():
    ctx = make()
    assert isinstance(ctx.checks, Checks)
    assert not ctx.checks.all_ok


def test_settings_and_lists_default_empty():
    ctx = make()
    assert ctx.settings == {}
    assert ctx.warnings == [] and ctx.errors == []


def test_each_context_gets_its_own_collections():
    # default_factory, not a shared mutable default.
    a, b = make(), make()
    a.warnings.append(Issue("W", "only on a"))
    assert b.warnings == []


def test_add_warnings_and_errors_accumulate():
    ctx = make()
    ctx.add_warnings([Issue("W1", "first")])
    ctx.add_warnings([Issue("W2", "second")])
    ctx.add_errors([Issue("E1", "boom")])
    assert [w.code for w in ctx.warnings] == ["W1", "W2"]
    assert [e.code for e in ctx.errors] == ["E1"]


# -- stage fields can be filled in place -------------------------------------

def test_fields_are_writable_by_stages():
    ctx = make()
    ctx.results = {}            # the execute stage sets this
    ctx.settings["repeats"] = 3
    assert ctx.results == {}
    assert ctx.settings["repeats"] == 3
