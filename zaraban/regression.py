"""Regression tests from reproducer bundles (SPEC §10.6).

Section 3.3 of the course spec requires the minimized input to be added
automatically to the project's regression suite. For every bundle with a
stable replay (§10.4) this module:

1. skips it when the input came from a regression test, or when the same bytes
   (SHA-256) are already in ``regression_dir`` (status ``already_present``);
2. runs the input once on ``base-sanitized``: ``FIXED`` and ``INCOMPLETE_FIX``
   inputs must crash there with the finding's signature, ``NEW_ISSUE`` inputs
   must not crash. If the check fails, nothing is added and the warning
   ``REGRESSION_NOT_ADDED`` is recorded (status ``not_added``);
3. writes two files, ``reg-<source test>-<sha8><ext>`` (the input, byte for
   byte) and ``reg-<source test>-<sha8>.yaml`` (what the test expects), to
   ``regression/`` in the run's output and, unless ``--no-promote``, to the
   target's ``regression_dir``.

The program is run through an injected ``run_base`` callable, as in
:mod:`zaraban.reproducer`, so this module does not depend on the runner.
Loading the promoted tests in later runs belongs to the config loader.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable, Optional

import yaml

from . import __version__
from .models import (
    Bundle,
    Category,
    Finding,
    Issue,
    RegressionStatus,
    RegressionTest,
    TestKind,
    WarningCode,
)
from .reproducer import RunOutcome

RunFn = Callable[[bytes], RunOutcome]

# Categories whose input must crash on base with the finding's signature.
_EXPECT_BASE_CRASH = {Category.FIXED: True, Category.INCOMPLETE_FIX: True,
                      Category.NEW_ISSUE: False}


def regression_name(source_test: str, input_bytes: bytes) -> str:
    """``reg-exploit_secondary-3f2a91c0``: the source test and the first 8 hex
    digits of the input's SHA-256 (§10.6)."""
    return f"reg-{source_test}-{hashlib.sha256(input_bytes).hexdigest()[:8]}"


def add_regression(
    *,
    finding: Finding,
    bundle: Bundle,
    input_bytes: bytes,
    input_ext: str,
    source_kind: TestKind,
    signature: Optional[str],
    run_base: RunFn,
    run_id: str,
    base_version: Optional[str],
    base_binary_sha256: Optional[str],
    out_dir: str | Path,
    regression_dir: str | Path,
    promote: bool = True,
) -> tuple[Optional[RegressionTest], list[Issue]]:
    """Turn one bundle into a regression test (§10.6).

    ``input_bytes`` is the bundle's replayed input (minimized, or the original
    when the minimized one was unstable); ``signature`` is the bundle's
    expected signature. ``run_base`` runs an input once on ``base-sanitized``
    with the source test's command and environment.

    Returns ``(None, [])`` when no test is considered (unstable bundle, input
    from a regression test, category without regression test); otherwise the
    :class:`RegressionTest` entry for ``regression_added`` and any warnings.
    On ``added`` the finding's ``regression_test`` is set.
    """
    expect_crash = _EXPECT_BASE_CRASH.get(finding.category)
    if expect_crash is None or not bundle.stable or source_kind is TestKind.REGRESSION:
        return None, []

    sha = hashlib.sha256(input_bytes).hexdigest()
    name = regression_name(bundle.source_test, input_bytes)
    run_rel = f"regression/{name}.yaml"
    regression_dir = Path(regression_dir)

    def record(status: RegressionStatus, path: str = run_rel,
               promoted_to: Optional[str] = None) -> RegressionTest:
        return RegressionTest(name=name, from_finding=finding.id, path=path, input_sha256=sha,
                              status=status, promoted_to=promoted_to)

    existing = _find_same_input(regression_dir, sha)
    if existing is not None:
        return record(RegressionStatus.ALREADY_PRESENT, path=str(existing),
                      promoted_to=str(regression_dir)), []

    outcome = run_base(input_bytes)
    if expect_crash:
        ok = outcome.crashed and (outcome.signature == signature if signature is not None
                                  else outcome.error_type == finding.error_type)
        want = f"a crash with {signature or finding.error_type}"
    else:
        ok = not outcome.crashed
        want = "no crash"
    if not ok:
        got = outcome.signature or ("a crash without signature" if outcome.crashed
                                    else f"no crash (exit {outcome.exit_code})")
        return record(RegressionStatus.NOT_ADDED), [Issue(
            WarningCode.REGRESSION_NOT_ADDED.value,
            f"{finding.id}: the input of {name} was expected to give {want} on "
            f"base-sanitized, but gave {got}; no regression test was added",
            {"finding": finding.id, "test": name, "expected": want, "got": got,
             "bundle": bundle.path})]

    spec = {
        "name": name,
        "input_file": f"{name}{input_ext}",
        "expect_base_crash": expect_crash,
        "signature": signature,
        "created_by": {"tool_version": __version__, "run_id": run_id,
                       "finding": finding.id, "source_test": bundle.source_test},
        "created_on": {"base_version": base_version, "base_binary_sha256": base_binary_sha256},
    }
    _write_test(Path(out_dir) / "regression", name, input_ext, input_bytes, spec)
    promoted_to = None
    if promote:
        _write_test(regression_dir, name, input_ext, input_bytes, spec)
        promoted_to = str(regression_dir)
    finding.regression_test = run_rel
    return record(RegressionStatus.ADDED, promoted_to=promoted_to), []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_same_input(regression_dir: Path, sha: str) -> Optional[Path]:
    """The ``.yaml`` of a test in ``regression_dir`` whose input has the same
    bytes, or ``None`` (§10.6: duplicates are compared by SHA-256)."""
    if not regression_dir.is_dir():
        return None
    for path in sorted(regression_dir.iterdir()):
        if not path.is_file() or path.suffix in (".yaml", ".yml"):
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() == sha:
            return path.with_suffix(".yaml")
    return None


def _write_test(dest: Path, name: str, input_ext: str, data: bytes, spec: dict) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / f"{name}{input_ext}").write_bytes(data)
    (dest / f"{name}.yaml").write_text(
        yaml.safe_dump(spec, sort_keys=False, allow_unicode=True, default_flow_style=False),
        encoding="utf-8")
