"""Unit tests for regression-test generation and promotion (SPEC §10.6)."""

import hashlib

import yaml

from zaraban.models import (
    BuildName,
    Bundle,
    Category,
    ErrorType,
    Finding,
    RegressionStatus,
    Replay,
    TestKind,
    WarningCode,
)
from zaraban.regression import add_regression, regression_name
from zaraban.reproducer import RunOutcome

SIG = "STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main"
DATA = b"SET x=AAAA"
SHA = hashlib.sha256(DATA).hexdigest()
NAME = f"reg-exploit_secondary-{SHA[:8]}"


def crash(sig=SIG):
    return lambda data: RunOutcome(True, sig, signal="SIGABRT",
                                   error_type=ErrorType.STACK_BUFFER_OVERFLOW)


def clean(data):
    return RunOutcome(False, None, exit_code=0)


def bundle(stable=True, fid="F-001"):
    replays = [Replay(i, stable, "SIGABRT", None, None, [], 0.01) for i in (1, 2, 3)]
    return Bundle(finding=fid, source_test="exploit_secondary", build=BuildName.PATCH_SANITIZED,
                  path=f"reproducers/{fid}", original_size=94, minimized_size=len(DATA),
                  minimize_runs=10, minimize_limit_hit=False, replayed_input="min",
                  replays=replays, stable=stable)


def _call(tmp_path, *, category=Category.INCOMPLETE_FIX, stable=True, promote=True,
          data=DATA, run_base=None, source_kind=TestKind.SECURITY, finding=None):
    f = finding or Finding(id="F-001", category=category, tests=[], signature=SIG,
                           error_type=ErrorType.STACK_BUFFER_OVERFLOW)
    rt, warnings = add_regression(
        finding=f, bundle=bundle(stable), input_bytes=data, input_ext=".txt",
        source_kind=source_kind, signature=SIG, run_base=run_base or crash(),
        run_id="20261111-183002-3f2a91c0", base_version="c76e9ca", base_binary_sha256="e" * 64,
        out_dir=tmp_path / "out", regression_dir=tmp_path / "target_regression",
        promote=promote)
    return rt, warnings, f


# -- files and names (§10.6) -------------------------------------------------

def test_10_6_name_is_source_test_and_sha8():
    assert regression_name("exploit_secondary", DATA) == NAME


def test_10_6_stable_bundle_is_added_and_promoted(tmp_path):
    rt, warnings, f = _call(tmp_path)
    assert warnings == []
    assert rt.status is RegressionStatus.ADDED
    assert rt.name == NAME and rt.from_finding == "F-001" and rt.input_sha256 == SHA
    assert rt.path == f"regression/{NAME}.yaml"
    assert rt.promoted_to == str(tmp_path / "target_regression")
    assert f.regression_test == rt.path
    for d in (tmp_path / "out" / "regression", tmp_path / "target_regression"):
        assert (d / f"{NAME}.txt").read_bytes() == DATA
        assert (d / f"{NAME}.yaml").is_file()


def test_10_6_yaml_records_expectation_and_proof(tmp_path):
    _call(tmp_path)
    spec = yaml.safe_load((tmp_path / "out" / "regression" / f"{NAME}.yaml").read_text())
    assert list(spec) == ["name", "input_file", "expect_base_crash", "signature",
                          "created_by", "created_on"]
    assert spec["name"] == NAME and spec["input_file"] == f"{NAME}.txt"
    assert spec["expect_base_crash"] is True and spec["signature"] == SIG
    assert spec["created_by"] == {"tool_version": "0.2.0", "run_id": "20261111-183002-3f2a91c0",
                                  "finding": "F-001", "source_test": "exploit_secondary"}
    assert spec["created_on"] == {"base_version": "c76e9ca", "base_binary_sha256": "e" * 64}


def test_10_6_no_promote_writes_only_the_run_output(tmp_path):
    rt, warnings, _ = _call(tmp_path, promote=False)
    assert warnings == []
    assert rt.status is RegressionStatus.ADDED and rt.promoted_to is None
    assert (tmp_path / "out" / "regression" / f"{NAME}.yaml").is_file()
    assert not (tmp_path / "target_regression").exists()


# -- which bundles get a test ------------------------------------------------

def test_10_6_unstable_bundle_gets_no_test(tmp_path):
    assert _call(tmp_path, stable=False)[:2] == (None, [])
    assert not (tmp_path / "out").exists()


def test_10_6_input_from_a_regression_test_is_never_added_again(tmp_path):
    assert _call(tmp_path, source_kind=TestKind.REGRESSION)[:2] == (None, [])


def test_10_1_functional_and_inconclusive_findings_get_no_test(tmp_path):
    for cat in (Category.FUNCTIONAL_REGRESSION, Category.INCONCLUSIVE):
        assert _call(tmp_path, category=cat)[:2] == (None, [])


# -- verification on base (§10.6) --------------------------------------------

def test_10_6_fixed_and_incomplete_fix_must_crash_on_base_with_the_signature(tmp_path):
    for cat in (Category.FIXED, Category.INCOMPLETE_FIX):
        rt, warnings, f = _call(tmp_path / cat.value, category=cat, run_base=crash("SEGV @ other"))
        assert rt.status is RegressionStatus.NOT_ADDED and rt.promoted_to is None
        assert [w.code for w in warnings] == [WarningCode.REGRESSION_NOT_ADDED.value]
        assert f.regression_test is None
        assert not (tmp_path / cat.value / "target_regression").exists()


def test_10_6_base_without_crash_fails_for_incomplete_fix(tmp_path):
    rt, warnings, _ = _call(tmp_path, run_base=clean)
    assert rt.status is RegressionStatus.NOT_ADDED
    assert "no crash" in warnings[0].message


def test_10_6_new_issue_must_not_crash_on_base(tmp_path):
    rt, warnings, _ = _call(tmp_path, category=Category.NEW_ISSUE, run_base=clean)
    assert rt.status is RegressionStatus.ADDED and warnings == []
    spec = yaml.safe_load((tmp_path / "out" / "regression" / f"{NAME}.yaml").read_text())
    assert spec["expect_base_crash"] is False

    rt, warnings, _ = _call(tmp_path / "again", category=Category.NEW_ISSUE, run_base=crash())
    assert rt.status is RegressionStatus.NOT_ADDED
    assert warnings[0].code == WarningCode.REGRESSION_NOT_ADDED.value


# -- duplicates (§10.6) ------------------------------------------------------

def test_10_6_same_bytes_already_present_is_not_added_again(tmp_path):
    _call(tmp_path)
    calls = []
    rt, warnings, f = _call(tmp_path, run_base=lambda d: calls.append(d) or crash()(d))
    assert rt.status is RegressionStatus.ALREADY_PRESENT and warnings == []
    assert rt.path == str(tmp_path / "target_regression" / f"{NAME}.yaml")
    assert calls == []  # nothing run, nothing written
    assert f.regression_test is None


def test_10_6_same_bytes_under_another_name_is_a_duplicate(tmp_path):
    reg = tmp_path / "target_regression"
    reg.mkdir()
    (reg / "reg-exploit_primary-00000000.txt").write_bytes(DATA)
    rt, _, _ = _call(tmp_path)
    assert rt.status is RegressionStatus.ALREADY_PRESENT


def test_10_6_different_inputs_for_the_same_error_are_both_kept(tmp_path):
    rt1, _, _ = _call(tmp_path)
    rt2, _, _ = _call(tmp_path, data=b"SET y=BBBBAAAA")
    assert rt1.status is rt2.status is RegressionStatus.ADDED
    assert rt1.name != rt2.name
    yamls = sorted(p.name for p in (tmp_path / "target_regression").glob("*.yaml"))
    assert len(yamls) == 2
