"""Unit tests for the report writer (SPEC §12).

Everything the report needs is built by hand from the frozen models.py types,
so this runs without Member B or C finished.
"""

import json

from zaraban import report as report_mod
from zaraban.models import (
    BUILD_ORDER,
    Category,
    Checks,
    DiffInfo,
    EnvironmentInfo,
    Finding,
    FindingTest,
    Issue,
    TestKind,
    VersionInfo,
    WarningCode,
)
from zaraban.status import compute_status


# -- fixtures ----------------------------------------------------------------

def _versions() -> dict:
    base = VersionInfo("directory", "src/base", "abc123", "0" * 64)
    patch = VersionInfo("diff", "fix.patch", None, "1" * 64, strip_level=1)
    diff = DiffInfo(path="out/patch.diff", sha256="2" * 64, files=["src/main.c"], hunks=1)
    return {"base": base, "patch": patch, "diff": diff}


def _environment() -> EnvironmentInfo:
    return EnvironmentInfo(os="Ubuntu 22.04", kernel="6.x", arch="x86_64",
                           docker_image="zaraban:latest", python="3.10",
                           gcc="11", clang="14", llvm_symbolizer="14")


def _builds() -> dict:
    # Minimal per-build dicts, as builder.py's BuildRecord serializes to.
    return {name: {"build": name.value, "status": "ok"} for name in BUILD_ORDER}


def _finding(fid: str, category: Category, *tests: str) -> Finding:
    return Finding(id=fid, category=category,
                   tests=[FindingTest(test=t, kind=TestKind.SECURITY, results={}) for t in tests])


def _assemble(findings=None, warnings=None, errors=None, checks=None):
    status = compute_status(findings or [], checks or Checks(*([True] * 7)))
    return report_mod.assemble_report(
        run_id="run-0001",
        started_at="2026-11-13T00:00:00Z",
        duration_s=12.3456789,
        target_name="token_parser",
        config_path="targets/target1_sample/zaraban.yaml",
        config_sha256="f" * 64,
        versions=_versions(),
        environment=_environment(),
        settings={"repeats": 3, "limits": {"timeout_seconds": 2.0, "memory_limit_mb": 128}},
        builds=_builds(),
        status=status,
        findings=findings,
        warnings=warnings,
        errors=errors,
    )


# -- assembling (§12.4) ------------------------------------------------------

def test_12_assemble_fills_tool_and_target():
    r = _assemble()
    assert r.tool == {"name": "zaraban", "version": report_mod.__version__}
    assert r.target["name"] == "token_parser"
    assert r.duration_s == 12.3457  # rounded to 4 places
    # Optional pieces default to empty, not None (§12.1).
    assert r.findings == [] and r.warnings == [] and r.errors == []
    assert r.execution_logs == {} and r.regression_added == []


# -- writing report.json (§12.1, §12.2) --------------------------------------

def test_12_1_writes_report_json_and_summary(tmp_path):
    r = _assemble(findings=[_finding("F-001", Category.INCOMPLETE_FIX, "exploit_primary")])
    report_path, summary_path = report_mod.write(r, tmp_path / "out")
    assert report_path.name == "report.json"
    assert summary_path.name == "summary.txt"

    data = json.loads(report_path.read_text(encoding="utf-8"))
    # schema_version is first; the top-level keys are present and in order.
    keys = list(data)
    assert keys[0] == "schema_version"
    assert keys[1] == "tool"
    assert "status" in keys and "findings" in keys and "versions" in keys


def test_12_2_build_name_keys_serialize_to_strings(tmp_path):
    r = _assemble()
    report_path, _ = report_mod.write(r, tmp_path / "out")
    data = json.loads(report_path.read_text(encoding="utf-8"))
    # dict[BuildName, ...] becomes dict[str, ...] in JSON.
    assert "base-release" in data["builds"]
    assert data["versions"]["base"]["form"] == "directory"
    assert data["versions"]["diff"]["hunks"] == 1


def test_12_2_enums_become_values(tmp_path):
    r = _assemble(findings=[_finding("F-003", Category.FUNCTIONAL_REGRESSION, "valid_set")])
    data = json.loads((report_mod.write(r, tmp_path / "out")[0]).read_text())
    assert data["findings"][0]["category"] == "FUNCTIONAL_REGRESSION"
    assert data["status"]["exit_code"] == 20  # IntEnum -> int


# -- the human summary (§12.1) -----------------------------------------------

def test_12_1_summary_leads_with_the_verdict():
    r = _assemble(findings=[_finding("F-001", Category.INCOMPLETE_FIX, "exploit_primary")])
    text = report_mod.human_summary(r)
    assert "Result: VULN_REMAINS (exit 10)" in text
    assert "token_parser" in text.splitlines()[0]
    assert "F-001  INCOMPLETE_FIX  tests: exploit_primary" in text
    assert "Builds: 4/4 ok" in text


def test_12_1_summary_lists_warnings_and_pass():
    warns = [Issue(WarningCode.NO_DEBUG_INFO.value, "sanitized binary has no debug info")]
    r = _assemble(warnings=warns)
    text = report_mod.human_summary(r)
    assert "Result: PASS (exit 0)" in text
    assert "Warnings: 1" in text
    assert "[NO_DEBUG_INFO]" in text


def test_12_summary_is_written_to_disk(tmp_path):
    r = _assemble()
    _, summary_path = report_mod.write(r, tmp_path / "out")
    assert "Full report: report.json" in summary_path.read_text(encoding="utf-8")
