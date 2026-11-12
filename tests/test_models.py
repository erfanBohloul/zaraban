"""Unit tests for zaraban/models.py: names, orders and JSON form that other
modules and report.json rely on."""

import json

import pytest

from zaraban.models import (
    BUILD_ORDER,
    EXIT_PRIORITY,
    Analysis,
    BuildName,
    BuildRecord,
    BinaryInfo,
    Checks,
    Condition,
    ConditionName,
    ErrorCode,
    ExitCode,
    Frame,
    HardeningChange,
    HardeningChangeKind,
    Hunk,
    Outcome,
    Profile,
    TestCase,
    TestKind,
    Version,
    ZarabanError,
    dump_json,
    finding_id,
    to_jsonable,
)


def test_6_1_build_order_and_names():
    assert [b.value for b in BUILD_ORDER] == [
        "base-release", "base-sanitized", "patch-release", "patch-sanitized",
    ]
    assert BuildName.PATCH_SANITIZED.version is Version.PATCH
    assert BuildName.BASE_RELEASE.profile is Profile.RELEASE
    assert BuildName.of(Version.BASE, Profile.SANITIZED) is BuildName.BASE_SANITIZED


def test_13_1_exit_codes_match_course_spec():
    assert {c.name: c.value for c in ExitCode} == {
        "PASS": 0, "VULN_REMAINS": 10, "FUNC_REGRESSION": 20,
        "BUILD_OR_CONFIG_ERROR": 30, "INCONCLUSIVE": 40,
    }
    assert [int(c) for c in EXIT_PRIORITY] == [30, 10, 20, 40, 0]


def test_13_3_new_issue_shares_code_10():
    assert ConditionName.NEW_ISSUE.code is ExitCode.VULN_REMAINS
    assert Condition(ConditionName.FUNC_REGRESSION, "x").code == 20


def test_13_2_checks_all_ok():
    assert not Checks().all_ok
    assert Checks(*([True] * 7)).all_ok


def test_7_4_app_frames_skip_runtime():
    a = Analysis(
        outcome=Outcome.CRASH,
        frames=[
            Frame(0, "__interceptor_strcpy", None, None, runtime=True),
            Frame(1, "handle_set_command", "src/main.c", 37, runtime=False),
        ],
    )
    assert a.is_crash
    assert [f.function for f in a.app_frames] == ["handle_set_command"]


def test_9_2_hunk_contains_uses_the_right_side():
    h = Hunk("src/main.c", "@@ -21,14 +21,19 @@", 21, 34, 21, 39)
    assert h.contains(Version.PATCH, "src/main.c", 37)
    assert not h.contains(Version.BASE, "src/main.c", 37)
    assert not h.contains(Version.PATCH, "src/other.c", 37)


def test_8_8_finding_ids():
    assert finding_id(1) == "F-001"
    assert finding_id(42) == "F-042"


def test_12_2_json_form(tmp_path):
    rec = BuildRecord(
        build=BuildName.PATCH_RELEASE, status="ok", cmd="make release",
        env={"PATH": "/usr/bin"}, cwd="work/patch-release", exit_code=0,
        duration_s=1.5, log="builds/patch-release/build.log",
        binary=BinaryInfo("builds/patch-release/bin/t", 1234, "ab" * 32),
    )
    data = to_jsonable(rec)
    assert list(data)[0] == "schema_version"          # always first
    assert data["build"] == "patch-release"           # enums as values
    assert data["sanitizers_verified"] is None         # None kept, not omitted
    assert data["binary"]["size"] == 1234

    dump_json(rec, tmp_path / "builds" / "build.json")
    assert json.loads((tmp_path / "builds" / "build.json").read_text())["status"] == "ok"


def test_12_2_bytes_never_in_json():
    tc = TestCase("t", TestKind.VALID, b"\x00\x01", ".bin")
    assert "input_bytes" not in to_jsonable(tc)       # input lives in its own file
    with pytest.raises(TypeError):
        to_jsonable({"stdout": b"raw"})


def test_12_4_hardening_change_keys():
    c = HardeningChange("relro", "full", "partial", HardeningChangeKind.DOWNGRADE)
    assert to_jsonable(c) == {"protection": "relro", "from": "full", "to": "partial", "kind": "downgrade"}


def test_12_6_error_carries_code():
    e = ZarabanError(ErrorCode.PATCH_APPLY_FAILED, "no strip level applies", {"diff": "x.patch"})
    assert str(e) == "PATCH_APPLY_FAILED: no strip level applies"
    assert to_jsonable(e.to_issue())["code"] == "PATCH_APPLY_FAILED"
