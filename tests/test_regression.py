"""Unit tests for regression-test generation and promotion (SPEC §10.6)."""

import hashlib
import json

from zaraban.models import RegressionStatus, WarningCode
from zaraban.regression import add_regression


def _call(tmp_path, *, stable=True, promote=True, data=b"SET x=AAAA", finding="F-001",
          signature="HEAP_BUFFER_OVERFLOW @ boom"):
    return add_regression(
        finding_id=finding, source_test="exploit_primary", input_bytes=data,
        signature=signature, stable=stable,
        out_dir=tmp_path / "out", regression_dir=tmp_path / "target_regression",
        promote=promote,
    )


# -- a stable reproducer becomes a promoted test (§10.6) ---------------------

def test_10_6_stable_reproducer_is_added_and_promoted(tmp_path):
    rt, warnings = _call(tmp_path)
    assert warnings == []
    assert rt.status is RegressionStatus.ADDED
    assert rt.name == "regression_F-001"
    assert rt.input_sha256 == hashlib.sha256(b"SET x=AAAA").hexdigest()

    # Written into the run output...
    run_dir = tmp_path / "out" / "regression" / "regression_F-001"
    assert (run_dir / "input.bin").read_bytes() == b"SET x=AAAA"
    # ...and promoted into the target's regression dir.
    target_dir = tmp_path / "target_regression" / "regression_F-001"
    assert rt.promoted_to == str(target_dir)
    assert (target_dir / "input.bin").read_bytes() == b"SET x=AAAA"


def test_10_6_meta_records_the_oracle(tmp_path):
    rt, _ = _call(tmp_path)
    meta = json.loads((tmp_path / "out" / "regression" / rt.name / "meta.json").read_text())
    assert meta["expect_base_crash"] is True
    assert meta["expected_signature"] == "HEAP_BUFFER_OVERFLOW @ boom"
    assert meta["from_finding"] == "F-001"
    assert meta["input_sha256"] == rt.input_sha256


# -- idempotence: a second run finds it already there ------------------------

def test_10_6_identical_test_already_present(tmp_path):
    _call(tmp_path)                 # first run promotes it
    rt, warnings = _call(tmp_path)  # second run, same input
    assert warnings == []
    assert rt.status is RegressionStatus.ALREADY_PRESENT
    assert rt.promoted_to.endswith("regression_F-001")


# -- --no-promote: generated but not copied into the target (§3) -------------

def test_10_6_no_promote_writes_run_output_only(tmp_path):
    rt, warnings = _call(tmp_path, promote=False)
    assert warnings == []
    assert rt.status is RegressionStatus.NOT_ADDED
    assert rt.promoted_to is None
    # In the run output...
    assert (tmp_path / "out" / "regression" / rt.name / "input.bin").exists()
    # ...but NOT promoted into the target.
    assert not (tmp_path / "target_regression" / rt.name).exists()


# -- an unstable reproducer makes no test, only a warning (§10.6) ------------

def test_10_6_unstable_reproducer_is_not_added(tmp_path):
    rt, warnings = _call(tmp_path, stable=False)
    assert rt.status is RegressionStatus.NOT_ADDED
    assert rt.promoted_to is None
    assert any(w.code == WarningCode.REGRESSION_NOT_ADDED.value for w in warnings)
    # Nothing was written anywhere.
    assert not (tmp_path / "out" / "regression").exists()
    assert not (tmp_path / "target_regression").exists()


# -- binary inputs are preserved exactly -------------------------------------

def test_10_6_binary_input_preserved(tmp_path):
    data = b"\x00\x01\x02AAAA\xff"
    rt, _ = _call(tmp_path, data=data)
    assert (tmp_path / "target_regression" / rt.name / "input.bin").read_bytes() == data
    assert rt.input_sha256 == hashlib.sha256(data).hexdigest()
