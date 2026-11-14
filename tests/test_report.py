"""Unit tests for the report writer (SPEC §12).

Everything the report needs is built by hand from the frozen models.py types,
so this runs without Member B or C finished. The fake run is the
``incomplete.patch`` scenario of the §12.5 example.
"""

import json

from zaraban import report as report_mod
from zaraban.models import (
    BUILD_ORDER,
    BinaryInfo,
    BuildName,
    BuildRecord,
    Bundle,
    Category,
    Checks,
    DiffInfo,
    EnvironmentInfo,
    ErrorCode,
    ErrorType,
    Finding,
    FindingTest,
    HardeningChange,
    HardeningChangeKind,
    HardeningReport,
    HardeningResult,
    Issue,
    Link,
    LinkLevel,
    OnPatch,
    ProtectionResult,
    Relro,
    Replay,
    TestKind,
    Version,
    VersionInfo,
    WarningCode,
)
from zaraban.status import compute_status

SIG = "STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main"

# The top-level fields of report.json, in the order of §12.4.
REPORT_KEYS = ["schema_version", "tool", "run_id", "started_at", "duration_s", "target",
               "versions", "environment", "settings", "builds", "hardening",
               "execution_logs", "findings", "regression_added", "status",
               "warnings", "errors"]


# -- fixtures ----------------------------------------------------------------

def _versions() -> dict:
    base = VersionInfo("directory", "targets/target1_sample", "c76e9ca", "0" * 64)
    patch = VersionInfo("diff", "targets/target1_sample/patches/incomplete.patch", "c76e9ca",
                        "1" * 64, strip_level=2)
    diff = DiffInfo(path="inputs/patch.diff", sha256="2" * 64, files=["src/main.c"], hunks=1)
    return {"base": base, "patch": patch, "diff": diff}


def _environment() -> EnvironmentInfo:
    return EnvironmentInfo(os="Ubuntu 22.04", kernel="6.x", arch="x86_64",
                           docker_image="zaraban:latest", python="3.10",
                           gcc="11", clang="14", llvm_symbolizer="/usr/bin/llvm-symbolizer")


def _builds(failed=None) -> dict:
    recs = {}
    for name in BUILD_ORDER:
        recs[name] = BuildRecord(build=name, status="failed" if name is failed else "ok",
                                 cmd="make", env={}, cwd="work", exit_code=0, duration_s=1.0,
                                 log=f"builds/{name.value}/build.log",
                                 binary=BinaryInfo(f"builds/{name.value}/bin/token_parser", 10,
                                                   "a" * 64))
    return report_mod.build_entries(recs)


def _hardening(changes=()) -> HardeningReport:
    def result(relro=Relro.FULL):
        return HardeningResult(nx=ProtectionResult(True, "GNU_STACK RW"),
                               pie=ProtectionResult(True, "ET_DYN"),
                               relro=ProtectionResult(relro, "BIND_NOW"),
                               canary=ProtectionResult(True, "__stack_chk_fail"))
    patch = result(Relro.PARTIAL) if changes else result()
    return HardeningReport(base=result(), patch=patch, changes=list(changes))


def _execution_logs(n_tests=9, flaky=()) -> dict:
    return {b: {f"t{i}": {"kind": "valid", "flaky": f"t{i}" in flaky} for i in range(n_tests)}
            for b in BUILD_ORDER}


def _incomplete_fix() -> Finding:
    return Finding(
        id="F-001", category=Category.INCOMPLETE_FIX, signature=SIG,
        error_type=ErrorType.STACK_BUFFER_OVERFLOW,
        tests=[FindingTest("exploit_primary", TestKind.SECURITY, {}, on_patch=OnPatch.BLOCKED),
               FindingTest("exploit_secondary", TestKind.SECURITY, {}, on_patch=OnPatch.REACHES)],
        release={"base": "CRASH FORTIFY SIGABRT", "patch": "CRASH FORTIFY SIGABRT"},
        sanitized={"base": "CRASH ASAN SIGABRT", "patch": "CRASH ASAN SIGABRT"},
        link=Link(LinkLevel.IN_CHANGED_HUNK, side=Version.PATCH, file="src/main.c",
                  function="handle_set_command", line=37, frame=1, hunk="@@ -21,14 +21,19 @@"),
        reproducer="reproducers/F-001/")


def _bundle() -> Bundle:
    return Bundle(finding="F-001", source_test="exploit_secondary",
                  build=BuildName.PATCH_SANITIZED, path="reproducers/F-001", original_size=94,
                  minimized_size=69, minimize_runs=41, minimize_limit_hit=False,
                  replayed_input="min",
                  replays=[Replay(i, True, "SIGABRT", None, None, [], 0.02) for i in (1, 2, 3)],
                  stable=True)


def _fixed() -> Finding:
    return Finding(id="F-001", category=Category.FIXED, signature=SIG,
                   tests=[FindingTest("exploit_primary", TestKind.SECURITY, {},
                                      on_patch=OnPatch.BLOCKED)])


def _assemble(findings=None, warnings=None, errors=None, checks=None, hardening=None,
              builds=None, logs=None):
    findings = findings if findings is not None else [_fixed()]
    status = compute_status(findings, checks or Checks(*([True] * 7)), errors=errors)
    return report_mod.assemble_report(
        run_id="20261111-183002-3f2a91c0",
        started_at="2026-11-11T18:30:02Z",
        duration_s=12.3456789,
        target_name="token_parser",
        config_path="inputs/config.yaml",
        config_sha256="f" * 64,
        versions=_versions(),
        environment=_environment(),
        settings={"repeats": 3, "limits": {"timeout_seconds": 2.0, "memory_limit_mb": 128}},
        builds=builds or _builds(),
        status=status,
        execution_logs=logs if logs is not None else _execution_logs(),
        hardening=hardening if hardening is not None else _hardening(),
        findings=findings,
        warnings=warnings,
        errors=errors,
    )


# -- assembling (§12.4) ------------------------------------------------------

def test_12_4_assemble_fills_tool_and_target():
    r = _assemble()
    assert r.tool == {"name": "zaraban", "version": report_mod.__version__}
    assert r.target == {"name": "token_parser", "config": "inputs/config.yaml",
                        "config_sha256": "f" * 64}
    assert r.duration_s == 12.3457
    assert r.warnings == [] and r.errors == [] and r.regression_added == []


def test_12_4_build_entries_have_status_hash_and_details():
    b = _builds()
    assert b[BuildName.BASE_RELEASE] == {"status": "ok", "binary_sha256": "a" * 64,
                                         "details": "builds/base-release/build.json"}


# -- writing report.json (§12.1, §12.2, §12.4) -------------------------------

def test_12_4_report_json_has_exactly_the_fields_in_order(tmp_path):
    report_path, summary_path = report_mod.write(_assemble(), tmp_path / "run")
    assert report_path.name == "report.json" and summary_path.name == "summary.txt"
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert list(data) == REPORT_KEYS
    assert data["schema_version"] == 1


def test_12_2_enums_and_build_names_become_plain_values(tmp_path):
    r = _assemble(findings=[_incomplete_fix()])
    data = json.loads(report_mod.write(r, tmp_path)[0].read_text())
    assert "base-release" in data["builds"]
    assert data["versions"]["patch"]["strip_level"] == 2
    assert data["findings"][0]["category"] == "INCOMPLETE_FIX"
    assert data["findings"][0]["tests"][1]["on_patch"] == "reaches"
    assert data["status"]["exit_code"] == 10 and data["status"]["exit_name"] == "VULN_REMAINS"
    assert data["hardening"]["base"]["relro"]["value"] == "full"


def test_12_2_missing_values_are_null_not_omitted(tmp_path):
    r = _assemble()
    r.hardening = None
    data = json.loads(report_mod.write(r, tmp_path)[0].read_text())
    assert "hardening" in data and data["hardening"] is None
    assert data["findings"][0]["link"] is None


# -- summary.txt (§12.5) -----------------------------------------------------

def test_12_5_summary_matches_the_spec_layout(tmp_path):
    r = _assemble(findings=[_incomplete_fix()])
    text = report_mod.human_summary(r, [_bundle()],
                                    "out/token_parser/20261111-183002-3f2a91c0/report.json")
    assert text == (
        "ZARABAN 0.2.0  token_parser  run 20261111-183002-3f2a91c0\n"
        "base:  targets/target1_sample (directory)\n"
        "patch: targets/target1_sample/patches/incomplete.patch (diff, -p2)\n"
        "\n"
        "BUILDS     base-release ok · base-sanitized ok · patch-release ok · patch-sanitized ok\n"
        "HARDENING  NX on→on · PIE on→on · RELRO full→full · canary on→on   (no changes)\n"
        "TESTS      9 tests × 4 builds × 3 repeats   flaky: 0\n"
        "\n"
        "FINDINGS\n"
        f"  F-001 INCOMPLETE_FIX  {SIG}\n"
        "        tests:     exploit_primary blocked · exploit_secondary reaches\n"
        "        release:   FORTIFY/SIGABRT → FORTIFY/SIGABRT\n"
        "        sanitized: ASAN/SIGABRT → ASAN/SIGABRT\n"
        "        link:      IN_CHANGED_HUNK  src/main.c:37 handle_set_command (patch side)\n"
        "        bundle:    reproducers/F-001  94 → 69 bytes, replay 3/3\n"
        "\n"
        "RESULT     exit 10  VULN_REMAINS\n"
        "report:    out/token_parser/20261111-183002-3f2a91c0/report.json\n"
    )


def test_12_5_summary_counts_flaky_results():
    r = _assemble(logs=_execution_logs(n_tests=5, flaky={"t1"}))
    assert "TESTS      5 tests × 4 builds × 3 repeats   flaky: 4" in report_mod.human_summary(r)


def test_12_5_summary_shows_hardening_downgrade_and_failed_build():
    change = HardeningChange("relro", Relro.FULL, Relro.PARTIAL, HardeningChangeKind.DOWNGRADE)
    r = _assemble(hardening=_hardening([change]), builds=_builds(failed=BuildName.PATCH_RELEASE))
    text = report_mod.human_summary(r)
    assert "RELRO full→partial" in text and "(downgrade: relro)" in text
    assert "patch-release failed" in text


def test_12_5_summary_with_no_findings_warnings_and_errors():
    err = Issue(ErrorCode.BUILD_FAILED.value, "patch-sanitized did not build")
    warn = Issue(WarningCode.NO_DEBUG_INFO.value, "no debug info")
    r = _assemble(findings=[], warnings=[warn], errors=[err])
    text = report_mod.human_summary(r)
    assert "FINDINGS\n  (none)" in text
    assert "WARNINGS   NO_DEBUG_INFO" in text
    assert "ERROR      BUILD_FAILED: patch-sanitized did not build" in text
    assert "RESULT     exit 30  BUILD_OR_CONFIG_ERROR" in text


def test_12_5_summary_keeps_a_space_after_the_longest_label():
    f = _incomplete_fix()
    f.regression_test = "regression/reg-x-12345678.yaml"
    text = report_mod.human_summary(_assemble(findings=[f]))
    assert "        regression: regression/reg-x-12345678.yaml" in text
    assert "        tests:     " in text  # the other rows keep their alignment


def test_12_5_summary_shows_each_warning_with_its_message():
    warns = [Issue(WarningCode.NO_DEBUG_INFO.value, "no debug info")] + [
        Issue(WarningCode.OUTPUT_TRUNCATED.value, f"repeat {i}: cut") for i in range(1, 6)]
    text = report_mod.human_summary(_assemble(findings=[], warnings=warns))
    assert ("WARNINGS   NO_DEBUG_INFO: no debug info\n"
            "           OUTPUT_TRUNCATED: repeat 1: cut\n"
            "           OUTPUT_TRUNCATED: repeat 2: cut\n"
            "           OUTPUT_TRUNCATED: repeat 3: cut\n"
            "           OUTPUT_TRUNCATED: ... and 2 more (see report.json)\n") in text


def test_12_5_summary_lists_the_problems_of_an_error():
    err = Issue(ErrorCode.PATCH_APPLY_FAILED.value, "the patch does not apply",
                {"problems": ["-p0: no such file", "-p1: patch failed: src/main.c:12"]})
    text = report_mod.human_summary(_assemble(findings=[], errors=[err]))
    assert ("ERROR      PATCH_APPLY_FAILED: the patch does not apply\n"
            "             - -p0: no such file\n"
            "             - -p1: patch failed: src/main.c:12\n") in text


def test_12_5_summary_marks_an_unstable_bundle():
    b = _bundle()
    b.stable = False
    b.replays[1].reproduced = False
    r = _assemble(findings=[_incomplete_fix()])
    assert "replay 2/3, UNSTABLE" in report_mod.human_summary(r, [b])


def test_12_5_pass_summary_and_file_on_disk(tmp_path):
    report_path, summary_path = report_mod.write(_assemble(), tmp_path)
    text = summary_path.read_text(encoding="utf-8")
    assert "RESULT     exit 0  PASS" in text
    assert text.rstrip().endswith(str(report_path))
