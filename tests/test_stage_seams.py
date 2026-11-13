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


# -- they fail loudly while unimplemented ------------------------------------

def test_build_and_execute_stub_raises():
    with pytest.raises(NotImplementedError) as e:
        exec_stage.build_and_execute(_ctx())
    assert "Person 1" in str(e.value)  # points at who owns it


def test_analyze_and_report_stub_raises():
    with pytest.raises(NotImplementedError) as e:
        analysis_stage.analyze_and_report(_ctx())
    assert "Person 2" in str(e.value)
