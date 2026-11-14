"""Unit tests for the pipeline wiring: run set-up and safety net (SPEC §12.1, §13.4).

The two stages are injected as fakes, so these test what pipeline.py itself
owns: the run directory ``out/<target>/<run id>/`` with ``inputs/``, the run
id, the stage order, and that every failure still ends in a report with
exit 30.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from zaraban import analysis_stage, pipeline
from zaraban.config import Target
from zaraban.models import ErrorCode, Issue, ZarabanError
from zaraban.pipeline_state import RunContext

TARGET1 = Path("targets/target1_sample/zaraban.yaml")
PATCH_CORRECT = Path("targets/target1_sample/patches/correct.patch")
RUN_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{8}$")


@pytest.fixture
def target():
    t, _ = Target.load(TARGET1)
    return t


def args(tmp_path, patch=PATCH_CORRECT, **over):
    a = dict(out=str(tmp_path / "out"), patch=str(patch), base=None, keep_work=False,
             no_promote=True)
    a.update(over)
    return SimpleNamespace(**a)


def only_run_dir(tmp_path) -> Path:
    runs = [p for p in (tmp_path / "out" / "token_parser").iterdir() if p.is_dir()]
    assert len(runs) == 1, runs
    return runs[0]


def no_exec(ctx: RunContext) -> RunContext:
    return ctx


# -- run directory and run id (§12.1) ----------------------------------------

def test_12_1_run_id_is_utc_time_and_diff_hash():
    started = datetime(2026, 11, 11, 18, 30, 2, tzinfo=timezone.utc)
    assert pipeline.new_run_id(started, "3f2a91c0" + "0" * 56) == "20261111-183002-3f2a91c0"


def test_12_1_each_run_gets_its_own_directory_with_inputs(tmp_path, target):
    seen = {}

    def fake_exec(ctx):
        seen["ctx"] = ctx
        return ctx

    pipeline.run(args(tmp_path), target, [], build_and_execute=fake_exec,
                 analyze_and_report=lambda ctx: 0)
    ctx = seen["ctx"]
    run_dir = only_run_dir(tmp_path)

    assert ctx.out_dir == run_dir and ctx.run_id == run_dir.name
    assert RUN_ID.match(ctx.run_id)
    assert ctx.run_id.endswith(ctx.sources.diff.sha256[:8])
    assert ctx.work_dir == run_dir / "work"
    assert ctx.sources.base_tree == run_dir / "work" / "base"  # moved with the work dir
    assert ctx.sources.base_tree.is_dir()
    assert (run_dir / "inputs" / "config.yaml").read_bytes() == TARGET1.read_bytes()
    assert (run_dir / "inputs" / "patch.diff").read_bytes() == PATCH_CORRECT.read_bytes()
    assert ctx.sources.diff.path == "inputs/patch.diff"  # relative to the run dir (§12.2)
    # No temporary work directory is left next to the runs.
    assert [p.name for p in run_dir.parent.iterdir()] == [run_dir.name]


def test_12_1_two_runs_never_share_a_directory(tmp_path, target):
    for _ in range(2):
        pipeline.run(args(tmp_path), target, [], build_and_execute=no_exec,
                     analyze_and_report=lambda ctx: 0)
    runs = sorted(p.name for p in (tmp_path / "out" / "token_parser").iterdir())
    assert len(runs) == 2


def test_context_has_settings_environment_and_config_warnings(tmp_path, target):
    seen = {}
    pipeline.run(args(tmp_path), target, [Issue("NO_INVALID_TESTS", "x")],
                 build_and_execute=lambda ctx: seen.setdefault("ctx", ctx),
                 analyze_and_report=lambda ctx: 0)
    ctx = seen["ctx"]
    assert "NO_INVALID_TESTS" in [w.code for w in ctx.warnings]
    assert ctx.environment is not None and ctx.run_settings is not None
    assert set(ctx.settings) == {"repeats", "limits", "sanitizer_options"}
    assert "abort_on_error=1" in ctx.settings["sanitizer_options"]["ASAN_OPTIONS"]


# -- stage order -------------------------------------------------------------

def test_pipeline_calls_stages_in_order(tmp_path, target):
    order = []

    def fake_exec(ctx):
        order.append("exec")
        ctx.results = {}
        return ctx

    def fake_report(ctx):
        order.append("report")
        assert ctx.results == {}
        return 10

    rc = pipeline.run(args(tmp_path), target, [], build_and_execute=fake_exec,
                      analyze_and_report=fake_report)
    assert order == ["exec", "report"] and rc == 10


# -- failures still write a report (§13.4) -----------------------------------

def read_report(run_dir: Path) -> dict:
    return json.loads((run_dir / "report.json").read_text(encoding="utf-8"))


def test_3_2_patch_that_does_not_apply_gives_report_and_30(tmp_path, target):
    bad = tmp_path / "bad.patch"
    bad.write_text("--- a/src/nope.c\n+++ b/src/nope.c\n@@ -1 +1 @@\n-x\n+y\n")
    called = []
    rc = pipeline.run(args(tmp_path, patch=bad), target, [],
                      build_and_execute=lambda ctx: called.append(1) or ctx)
    assert rc == 30 and called == []  # no stage ran
    run_dir = only_run_dir(tmp_path)
    rep = read_report(run_dir)
    assert [e["code"] for e in rep["errors"]] == ["PATCH_APPLY_FAILED"]
    assert rep["status"]["exit_code"] == 30
    assert (run_dir / "summary.txt").is_file()
    assert not (run_dir / "errors.log").exists()  # not a tool failure


def test_13_4_zaraban_error_in_a_stage_gives_report_and_30(tmp_path, target):
    def boom(ctx):
        raise ZarabanError(ErrorCode.CONFIG_INVALID, "bad input for args method")

    rc = pipeline.run(args(tmp_path), target, [], build_and_execute=boom)
    assert rc == 30
    rep = read_report(only_run_dir(tmp_path))
    assert [e["code"] for e in rep["errors"]] == ["CONFIG_INVALID"]


def test_13_4_tool_bug_gives_tool_internal_errors_log_and_partial_report(tmp_path, target):
    def half_done(ctx):
        ctx.warnings.append(Issue("NO_DEBUG_INFO", "collected before the crash"))
        raise KeyError("bug")

    rc = pipeline.run(args(tmp_path), target, [], build_and_execute=half_done)
    assert rc == 30
    run_dir = only_run_dir(tmp_path)
    rep = read_report(run_dir)
    assert [e["code"] for e in rep["errors"]] == ["TOOL_INTERNAL"]
    assert "NO_DEBUG_INFO" in [w["code"] for w in rep["warnings"]]  # nothing collected is lost
    assert "KeyError" in (run_dir / "errors.log").read_text()
    assert not (run_dir / "work").exists()  # still cleaned up


def test_13_4_failure_in_the_analyze_stage_still_writes_the_report(tmp_path, target):
    def analyze_then_crash(ctx):
        raise RuntimeError("linking bug")

    rc = pipeline.run(args(tmp_path), target, [], build_and_execute=no_exec,
                      analyze_and_report=analyze_then_crash)
    assert rc == 30
    assert [e["code"] for e in read_report(only_run_dir(tmp_path))["errors"]] == ["TOOL_INTERNAL"]


def test_keep_work_keeps_the_work_dir(tmp_path, target):
    pipeline.run(args(tmp_path, keep_work=True), target, [], build_and_execute=no_exec,
                 analyze_and_report=analysis_stage.finish)
    assert (only_run_dir(tmp_path) / "work" / "base").is_dir()


# -- the CLI reaches this pipeline -------------------------------------------

def test_cli_imports_pipeline_run():
    from zaraban.pipeline import run as pipeline_run
    assert callable(pipeline_run)
