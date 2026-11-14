"""Task 2.3: the build & execute stage runs the regression tests of earlier runs."""

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from zaraban import builder, exec_stage, hardening, runner
from zaraban.models import (
    BUILD_ORDER,
    BinaryInfo,
    Checks,
    CombinedResult,
    ErrorCode,
    InputMethod,
    TestCase,
    TestKind,
    ZarabanError,
)

CONFIG_TESTS = [
    TestCase("valid_ping", TestKind.VALID, b"PING", ".txt"),
    TestCase("exploit_secondary", TestKind.SECURITY, b"SET " + b"A" * 80, ".txt"),
]
REG = "reg-exploit_secondary-3f2a91c0"


def _write_regression_test(reg: Path, name: str = REG) -> None:
    reg.mkdir(parents=True, exist_ok=True)
    (reg / f"{name}.txt").write_bytes(b"SET AAAA")
    (reg / f"{name}.yaml").write_text(yaml.safe_dump({
        "name": name,
        "input_file": f"{name}.txt",
        "expect_base_crash": True,
        "signature": "STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main",
        "created_by": {"tool_version": "0.2.0", "run_id": "20261111-183002-3f2a91c0",
                       "finding": "F-001", "source_test": "exploit_secondary"},
        "created_on": {"base_version": "c76e9ca", "base_binary_sha256": "e" * 64},
    }, sort_keys=False))


def _target(tmp_path: Path):
    return SimpleNamespace(
        name="token_parser", config_dir=tmp_path, input_method=InputMethod.FILE,
        spec=SimpleNamespace(regression_dir="tests/regression", repeats=2),
        all_tests=lambda: list(CONFIG_TESTS))


class _Ctx(SimpleNamespace):
    def add_warnings(self, issues):
        self.warnings.extend(i for i in issues if i is not None)

    def add_errors(self, issues):
        self.errors.extend(i for i in issues if i is not None)


def _ctx(tmp_path: Path) -> _Ctx:
    return _Ctx(args=SimpleNamespace(), target=_target(tmp_path), work_dir=tmp_path / "work", out_dir=tmp_path / "out",
                sources=SimpleNamespace(base_tree=tmp_path / "base", patch_tree=tmp_path / "patch"),
                run_settings=object(), checks=Checks(), warnings=[], errors=[],
                build_set=None, hardening=None, tests=[], results=None)


def _fake_builds(monkeypatch, built: list):
    records = {b: SimpleNamespace(status="ok", binary=BinaryInfo(f"builds/{b.value}/bin/t", 1, "f" * 64))
               for b in BUILD_ORDER}

    def build_all(*args, **kwargs):
        built.append(True)
        return SimpleNamespace(records=records, warnings=[], error=None, ok=True)

    monkeypatch.setattr(builder, "build_all", build_all)
    monkeypatch.setattr(hardening, "report", lambda base, patch: (None, []))
    monkeypatch.setattr(runner, "output_warnings", lambda runs: [])


def test_2_3_regression_tests_run_last_on_all_four_builds(tmp_path, monkeypatch):
    _write_regression_test(tmp_path / "tests" / "regression")
    _fake_builds(monkeypatch, built := [])
    calls = []

    def run_test(binary, test, settings, build, repeats, out_dir, source_root=""):
        calls.append((test.name, build, repeats))
        return CombinedResult(test.name, test.kind, build, runs=[], flaky=False)

    ctx = exec_stage.build_and_execute(_ctx(tmp_path), run_test=run_test)

    assert [t.name for t in ctx.tests] == ["valid_ping", "exploit_secondary", REG]
    reg = ctx.tests[-1]
    assert reg.kind is TestKind.REGRESSION and reg.expect_base_crash is True
    assert set(ctx.results) == {"valid_ping", "exploit_secondary", REG}
    assert [(b, n) for name, b, n in calls if name == REG] == [(b, 2) for b in BUILD_ORDER]
    assert ctx.checks.all_runs_completed and ctx.checks.results_stable


def test_2_3_no_regression_dir_runs_only_the_config_tests(tmp_path, monkeypatch):
    _fake_builds(monkeypatch, [])
    ctx = exec_stage.build_and_execute(
        _ctx(tmp_path),
        run_test=lambda binary, test, settings, build, repeats, out_dir, source_root="":
            CombinedResult(test.name, test.kind, build, runs=[], flaky=False))
    assert [t.name for t in ctx.tests] == ["valid_ping", "exploit_secondary"]


def test_2_3_bad_regression_file_is_a_config_error_before_any_build(tmp_path, monkeypatch):
    reg = tmp_path / "tests" / "regression"
    _write_regression_test(reg)
    (reg / "broken.yaml").write_text("name: [unclosed\n")
    _fake_builds(monkeypatch, built := [])

    with pytest.raises(ZarabanError) as e:
        exec_stage.build_and_execute(_ctx(tmp_path), run_test=lambda *a, **k: pytest.fail("ran"))

    assert e.value.code is ErrorCode.CONFIG_INVALID
    assert any("broken.yaml" in p for p in e.value.details["problems"])
    assert built == []  # nothing was built (§4.5)


def test_7_4_source_root_is_absolute_even_for_a_relative_out_dir(tmp_path, monkeypatch):
    # The debug info has absolute paths; a relative work_dir must not leave
    # frames with build-specific paths (seen as FIXED + NEW_ISSUE instead of
    # INCOMPLETE_FIX on token_parser).
    from zaraban.models import BuildName
    monkeypatch.chdir(tmp_path)
    ctx = SimpleNamespace(work_dir=Path("out/token_parser/run/work"))
    for build in (BuildName.BASE_SANITIZED, BuildName.PATCH_SANITIZED):
        root = exec_stage.source_root(ctx, build)
        assert root == str(tmp_path / "out/token_parser/run/work" / build.value)
    ctx = SimpleNamespace(work_dir=tmp_path / "abs" / "work")
    assert exec_stage.source_root(ctx, BuildName.BASE_SANITIZED) == str(tmp_path / "abs/work/base-sanitized")
