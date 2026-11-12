"""Regression tests from reproducers (SPEC §10.6).

A confirmed, stable reproducer becomes a regression test so the fixed bug
cannot silently come back: the minimized crashing input is saved with the
expectation that the **base** version crashes with its signature and the
**patched** version does not. The test is written into the run's output, and —
unless ``--no-promote`` — copied into the target's ``regression_dir``
(``tests/regression/``) so future runs replay it automatically (§5.1, §10.6).

This module only writes files and records a
:class:`~zaraban.models.RegressionTest`. It does not run anything; the next
run picks the promoted tests up through the config loader (§10).
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Optional

from .models import (
    Issue,
    RegressionStatus,
    RegressionTest,
    WarningCode,
)

INPUT_FILE = "input.bin"
META_FILE = "meta.json"


def add_regression(
    *,
    finding_id: str,
    source_test: str,
    input_bytes: bytes,
    signature: Optional[str],
    stable: bool,
    out_dir: str | Path,
    regression_dir: str | Path,
    promote: bool = True,
) -> tuple[RegressionTest, list[Issue]]:
    """Make a regression test from one reproducer and (optionally) promote it.

    Only a **stable** reproducer is turned into a test (§10.6); an unstable one
    is skipped with a ``REGRESSION_NOT_ADDED`` warning. Returns the
    :class:`RegressionTest` record and any warnings.
    """
    name = f"regression_{finding_id}"
    sha = hashlib.sha256(input_bytes).hexdigest()
    run_rel = f"regression/{name}"

    if not stable:
        warning = Issue(
            WarningCode.REGRESSION_NOT_ADDED.value,
            f"{finding_id}: reproducer was not stable, so no regression test was created",
            {"finding": finding_id})
        return RegressionTest(name=name, from_finding=finding_id, path=run_rel,
                              input_sha256=sha, status=RegressionStatus.NOT_ADDED,
                              promoted_to=None), [warning]

    # Write the test into the run output (always), as input + metadata.
    run_test_dir = Path(out_dir) / "regression" / name
    _write_test(run_test_dir, name, finding_id, source_test, input_bytes, signature, sha)

    if not promote:
        # Generated but deliberately not copied into the target (§3: --no-promote).
        return RegressionTest(name=name, from_finding=finding_id, path=run_rel,
                              input_sha256=sha, status=RegressionStatus.NOT_ADDED,
                              promoted_to=None), []

    target_dir = Path(regression_dir) / name
    existing = target_dir / INPUT_FILE
    if existing.is_file() and _sha256_file(existing) == sha:
        # An identical test is already promoted (e.g. from an earlier run).
        return RegressionTest(name=name, from_finding=finding_id, path=run_rel,
                              input_sha256=sha, status=RegressionStatus.ALREADY_PRESENT,
                              promoted_to=str(target_dir)), []

    _write_test(target_dir, name, finding_id, source_test, input_bytes, signature, sha)
    return RegressionTest(name=name, from_finding=finding_id, path=run_rel,
                          input_sha256=sha, status=RegressionStatus.ADDED,
                          promoted_to=str(target_dir)), []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_test(dest: Path, name: str, finding_id: str, source_test: str,
                input_bytes: bytes, signature: Optional[str], sha: str) -> None:
    """Write one regression test directory: the input and a metadata file.

    The metadata records the oracle a regression run checks (§10.6): the base
    must crash with ``expected_signature``; the patch must not.
    """
    dest.mkdir(parents=True, exist_ok=True)
    (dest / INPUT_FILE).write_bytes(input_bytes)
    meta = {
        "name": name,
        "from_finding": finding_id,
        "source_test": source_test,
        "input_file": INPUT_FILE,
        "input_sha256": sha,
        "expect_base_crash": True,
        "expected_signature": signature,
    }
    (dest / META_FILE).write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n",
                                  encoding="utf-8")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
