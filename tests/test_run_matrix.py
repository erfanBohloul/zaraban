"""Unit tests for scripts/run_matrix.py (SPEC §14.3, PHASES Task 2.5)."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

_PATH = Path(__file__).resolve().parent.parent / "scripts" / "run_matrix.py"
_spec = importlib.util.spec_from_file_location("run_matrix", _PATH)
rm = importlib.util.module_from_spec(_spec)
sys.modules["run_matrix"] = rm  # dataclasses look the module up
_spec.loader.exec_module(rm)

BASE_MAIN = "int main(void) {\n    char buf[8];\n    return 0;\n}\n"
FIXED_MAIN = "int main(void) {\n    char buf[64];\n    return 0;\n}\n"
FIXED = {"category": "FIXED", "tests": ["exploit_primary", "exploit_secondary"]}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _target(root: Path, scenarios: list[dict], *, version_text: str = FIXED_MAIN) -> Path:
    """A tiny target: base src/, one patch made with git, its version tree."""
    t = root / "targets" / "toy"
    _write(t / "zaraban.yaml", "name: toy\nbase_dir: .\n")
    _write(t / "Makefile", "all:\n")
    _write(t / "src" / "main.c", BASE_MAIN)
    v = t / "versions" / "patch_correct"
    _write(v / "Makefile", "all:\n")
    _write(v / "src" / "main.c", version_text)
    mk = root / "mk"  # a/src = base, b/src = fixed; git adds its own a/ b/ prefix
    _write(mk / "a" / "src" / "main.c", BASE_MAIN)
    _write(mk / "b" / "src" / "main.c", FIXED_MAIN)
    diff = subprocess.run(["git", "diff", "--no-index", "a/src", "b/src"],
                          cwd=mk, capture_output=True, text=True).stdout
    assert diff, "git diff produced nothing"
    _write(t / "patches" / "correct.patch", diff)
    _write(t / "scenarios.yaml", yaml.safe_dump(scenarios))
    return t


def _scenario(**kw):
    return {"name": "correct", "patch": "patches/correct.patch",
            "version_dir": "versions/patch_correct", "expect_exit": 0,
            "expect_findings": [FIXED], **kw}


def _fake_tool(exit_code=0, findings=(FIXED,), errors=()):
    """Writes a report like the tool does: <out>/<target>/<run id>/report.json."""
    calls = []

    def run(config, patch, out_dir):
        calls.append((config, patch, out_dir))
        run_dir = out_dir / "toy" / "20261114-000000-abcd0001"
        report = {"findings": [{"category": f["category"],
                                "tests": [{"test": t, "kind": "security"} for t in f["tests"]]}
                               for f in findings],
                  "errors": [{"code": c, "message": "m"} for c in errors]}
        _write(run_dir / "report.json", json.dumps(report))
        _write(run_dir / "summary.txt", "summary\n")
        _write(run_dir / "builds" / "base-release" / "bin" / "toy", "ELF")
        _write(run_dir / "builds" / "base-release" / "build.log", "log")
        _write(run_dir / "work" / "base-release" / "src" / "main.c", "x")
        _write(run_dir / "reproducers" / "F-001" / "bin" / "toy", "ELF")
        return exit_code

    run.calls = calls
    return run


# -- the whole matrix --------------------------------------------------------

def test_14_3_matching_scenario_passes_and_prints_the_gate_line(tmp_path, capsys):
    _target(tmp_path, [_scenario()])
    tool = _fake_tool()
    assert rm.main([], root=tmp_path, run=tool) == 0
    out = capsys.readouterr().out
    assert "toy/correct" in out and "exit 0  (expected 0 )" in out and "PASS" in out
    assert out.strip().endswith("1/1 scenarios matched")
    config, patch, _ = tool.calls[0]
    assert config.name == "zaraban.yaml" and patch.name == "correct.patch"


def test_14_3_wrong_exit_code_fails(tmp_path, capsys):
    _target(tmp_path, [_scenario()])
    assert rm.main([], root=tmp_path, run=_fake_tool(exit_code=30, errors=["TOOL_INTERNAL"])) == 1
    out = capsys.readouterr().out
    assert "FAIL" in out and "exit 30, expected 0" in out and "tool error TOOL_INTERNAL" in out
    assert "0/1 scenarios matched" in out


def test_14_3_wrong_findings_fail_even_with_the_right_exit(tmp_path, capsys):
    _target(tmp_path, [_scenario(expect_findings=[
        {"category": "INCOMPLETE_FIX", "tests": ["exploit_primary", "exploit_secondary"]}])])
    assert rm.main([], root=tmp_path, run=_fake_tool()) == 1
    out = capsys.readouterr().out
    assert "findings BAD" in out and "findings differ" in out


def test_14_3_patch_and_version_dir_must_agree(tmp_path, capsys):
    _target(tmp_path, [_scenario()], version_text=FIXED_MAIN.replace("64", "65"))
    assert rm.main([], root=tmp_path, run=_fake_tool()) == 1
    assert "content differs: src/main.c" in capsys.readouterr().out


def test_14_3_unknown_target_is_an_error(tmp_path):
    _target(tmp_path, [_scenario()])
    assert rm.main(["nope"], root=tmp_path, run=_fake_tool()) == 1


def test_14_3_underscore_directories_are_not_targets(tmp_path, capsys):
    _target(tmp_path, [_scenario()])
    _write(tmp_path / "targets" / "_template" / "scenarios.yaml",
           yaml.safe_dump([_scenario(patch="patches/missing.patch")]))
    tool = _fake_tool()
    assert rm.main([], root=tmp_path, run=tool) == 0
    assert len(tool.calls) == 1 and "_template" not in capsys.readouterr().out
    assert rm.main(["_template"], root=tmp_path, run=tool) == 1


def test_14_3_save_copies_the_run_without_work_and_build_binaries(tmp_path):
    _target(tmp_path, [_scenario()])
    assert rm.main(["--save"], root=tmp_path, run=_fake_tool()) == 0
    saved = tmp_path / "results" / "toy" / "correct"
    assert (saved / "report.json").is_file() and (saved / "summary.txt").is_file()
    assert (saved / "builds" / "base-release" / "build.log").is_file()
    assert not (saved / "builds" / "base-release" / "bin").exists()
    assert not (saved / "work").exists()
    assert (saved / "reproducers" / "F-001" / "bin" / "toy").is_file()  # bundles keep theirs


# -- pieces --------------------------------------------------------------------

def test_14_3_findings_compared_in_id_order_and_regression_tests_ignored():
    report = {"findings": [
        {"category": "FUNCTIONAL_REGRESSION", "tests": [{"test": "valid_set", "kind": "valid"}]},
        {"category": "FIXED", "tests": [{"test": "exploit_secondary", "kind": "security"},
                                        {"test": "exploit_primary", "kind": "security"},
                                        {"test": "reg-exploit_primary-fa19c82b", "kind": "regression"}]}]}
    want = [{"category": "FUNCTIONAL_REGRESSION", "tests": ["valid_set"]}, FIXED]
    assert rm.compare_findings(want, report) == []
    assert rm.compare_findings(list(reversed(want)), report) != []


def test_14_3_scenario_without_required_keys_is_rejected(tmp_path):
    t = _target(tmp_path, [{"name": "x"}])
    with pytest.raises(ValueError, match="lacks patch, expect_exit"):
        rm.load_scenarios(t)


def test_14_3_check_version_dir_reports_missing_files(tmp_path):
    t = _target(tmp_path, [_scenario()])
    (t / "versions" / "patch_correct" / "src" / "extra.c").write_text("x")
    problems = rm.check_version_dir(t, t / "patches" / "correct.patch", t / "versions" / "patch_correct")
    assert problems == ["correct.patch and patch_correct/ differ: only in version_dir: src/extra.c"]
    assert rm.check_version_dir(t, t / "patches" / "correct.patch", t / "nope") == [
        f"version_dir does not exist: {t / 'nope'}"]
