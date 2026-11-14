"""End-to-end tests for Zaraban on targets/test_token_parser (SPEC §2, §8.9, §12, §13).

Each test runs the real tool through ``cli.main``: four real builds, real
runs, real findings. Expected results on token_parser (§8.9):

- correct patch    -> exit 0  PASS            FIXED
- incomplete patch -> exit 10 VULN_REMAINS    INCOMPLETE_FIX
- regression patch -> exit 20 FUNC_REGRESSION FUNCTIONAL_REGRESSION, FIXED
- bad config / patch that does not apply -> exit 30

On a Linux host, ASan needs ``vm.mmap_rnd_bits=28`` (issue #002, set in CI),
or the tests can be run with ASLR off (``setarch -R``).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from zaraban import cli

TEST_TARGET_DIR = Path("targets/test_token_parser")
TEST_TARGET_CONFIG = TEST_TARGET_DIR / "zaraban.yaml"
PATCHES = {name: TEST_TARGET_DIR / f"patches/{name}.patch"
           for name in ("correct", "incomplete", "regression")}
RUN_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{8}$")

REQUIRED_REPORT_KEYS = [
    "schema_version", "tool", "run_id", "started_at", "duration_s", "target", "versions",
    "environment", "settings", "builds", "hardening", "execution_logs", "findings",
    "regression_added", "status", "warnings", "errors",
]

# §8.9: exit code, exit name, finding categories in finding id order.
EXPECTED = {
    "correct": (0, "PASS", ["FIXED"]),
    "incomplete": (10, "VULN_REMAINS", ["INCOMPLETE_FIX"]),
    "regression": (20, "FUNC_REGRESSION", ["FUNCTIONAL_REGRESSION", "FIXED"]),
}


def run_tool(tmp_path: Path, patch: Path) -> tuple[int, Path]:
    """Run the CLI into ``tmp_path/out``; return the exit code and the run dir."""
    out = tmp_path / "out"
    rc = cli.main(["-c", str(TEST_TARGET_CONFIG), "--patch", str(patch), "--out", str(out),
                   "--no-promote"])
    runs = list((out / "token_parser").iterdir())
    assert len(runs) == 1, runs
    return rc, runs[0]


def read_report(run_dir: Path) -> dict:
    return json.loads((run_dir / "report.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Bad input: exit 30
# ---------------------------------------------------------------------------

def test_e2e_bad_config_missing_file(tmp_path):
    assert cli.main(["-c", str(tmp_path / "nonexistent.yaml"),
                     "--patch", str(PATCHES["correct"])]) == 30


def test_e2e_bad_config_missing_patch(tmp_path):
    assert cli.main(["-c", str(TEST_TARGET_CONFIG)]) == 30


def test_e2e_bad_config_invalid_schema(tmp_path):
    bad_cfg = tmp_path / "bad.yaml"
    bad_cfg.write_text("invalid_key: true\nname: 12345\n")
    assert cli.main(["-c", str(bad_cfg), "--patch", str(PATCHES["correct"])]) == 30


def test_e2e_patch_that_does_not_apply_still_writes_report(tmp_path):
    bad = tmp_path / "bad.patch"
    bad.write_text("--- a/src/nope.c\n+++ b/src/nope.c\n@@ -1 +1 @@\n-x\n+y\n")
    rc, run_dir = run_tool(tmp_path, bad)
    assert rc == 30
    rep = read_report(run_dir)
    assert [e["code"] for e in rep["errors"]] == ["PATCH_APPLY_FAILED"]
    assert (run_dir / "summary.txt").is_file()


# ---------------------------------------------------------------------------
# The three token_parser scenarios (§8.9)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scenario", ["correct", "incomplete", "regression"])
def test_e2e_scenario(tmp_path, scenario):
    rc, run_dir = run_tool(tmp_path, PATCHES[scenario])
    code, name, categories = EXPECTED[scenario]
    rep = read_report(run_dir)

    assert rc == code, rep["status"]["reason"]
    assert rep["status"]["exit_code"] == code
    assert rep["status"]["exit_name"] == name
    assert [f["category"] for f in rep["findings"]] == categories
    assert rep["errors"] == []

    checks = rep["status"]["checks"]
    assert all(checks.values()), checks


def test_e2e_run_directory_layout(tmp_path):
    """§12.1: out/<target>/<run id>/ with inputs, builds, runs, reproducers,
    and every path in the JSON files pointing at a real file (§12.2)."""
    rc, run_dir = run_tool(tmp_path, PATCHES["incomplete"])
    rep = read_report(run_dir)

    assert RUN_ID.match(run_dir.name) and rep["run_id"] == run_dir.name
    assert run_dir.name.endswith(rep["versions"]["diff"]["sha256"][:8])
    assert (run_dir / "inputs/config.yaml").read_bytes() == TEST_TARGET_CONFIG.read_bytes()
    assert (run_dir / "inputs/patch.diff").read_bytes() == PATCHES["incomplete"].read_bytes()
    assert rep["target"]["config"] == "inputs/config.yaml"
    assert rep["versions"]["diff"]["path"] == "inputs/patch.diff"
    assert not (run_dir / "work").exists()  # deleted without --keep-work
    assert not (run_dir / "errors.log").exists()

    for build, entry in rep["builds"].items():
        assert (run_dir / entry["details"]).is_file()
        assert (run_dir / f"builds/{build}/build.log").is_file()

    # One record, stdout and stderr per test, build and repeat, at the paths the
    # records give (§12.3).
    repeats = rep["settings"]["repeats"]
    for build, tests in rep["execution_logs"].items():
        for test, entry in tests.items():
            runs = run_dir / entry["runs"]
            for n in range(1, repeats + 1):
                record = json.loads((runs / f"{n}.json").read_text())
                assert (run_dir / record["stdout"]["path"]).is_file()
                assert (run_dir / record["stderr"]["path"]).is_file()
    assert not [p for p in run_dir.glob("runs/*/*/*") if p.is_dir()]  # nothing nested

    for f in rep["findings"]:
        for path in f["evidence"]:
            assert (run_dir / path).exists(), path
        if f["reproducer"]:
            assert (run_dir / f["reproducer"] / "reproduce.sh").is_file()


def test_e2e_report_json_schema(tmp_path):
    """§12.4: all top-level keys, settings and environment."""
    rc, run_dir = run_tool(tmp_path, PATCHES["correct"])
    rep = read_report(run_dir)
    assert list(rep) == REQUIRED_REPORT_KEYS
    assert rep["schema_version"] == 1
    assert rep["tool"]["name"] == "zaraban"
    assert rep["target"]["name"] == "token_parser"
    assert set(rep["settings"]) == {"repeats", "limits", "sanitizer_options"}
    assert set(rep["execution_logs"]) == {"base-release", "base-sanitized",
                                          "patch-release", "patch-sanitized"}
    # Warnings are not duplicated.
    codes = [(w["code"], w["message"]) for w in rep["warnings"]]
    assert len(codes) == len(set(codes))


def test_e2e_two_runs_keep_both_reports(tmp_path):
    out = tmp_path / "out"
    for _ in range(2):
        cli.main(["-c", str(TEST_TARGET_CONFIG), "--patch", str(PATCHES["correct"]),
                  "--out", str(out), "--no-promote"])
    runs = sorted((out / "token_parser").iterdir())
    assert len(runs) == 2
    assert all((r / "report.json").is_file() for r in runs)
