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

In later runs (Task 2.3), :func:`load_tests` reads every ``.yaml`` in
``regression_dir`` back as a test of kind ``regression``, validated like the
config (§4.5), and :func:`base_clean_warnings` records ``REGRESSION_BASE_CLEAN``
for a test that no longer crashes on base (§8.6).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

import yaml
from pydantic import ValidationError

from . import __version__
from .config import MAX_INPUT_BYTES, Name, _format_errors, _read_yaml, _Strict
from .models import (
    BuildName,
    Bundle,
    Category,
    ErrorCode,
    Finding,
    InputMethod,
    Issue,
    Outcome,
    RegressionStatus,
    RegressionTest,
    Results,
    TestCase,
    TestKind,
    WarningCode,
    ZarabanError,
)
from .reproducer import RunOutcome

if TYPE_CHECKING:
    from .config import Target

RunFn = Callable[[bytes], RunOutcome]

# Categories whose input must crash on base with the finding's signature.
_EXPECT_BASE_CRASH = {Category.FIXED: True, Category.INCOMPLETE_FIX: True,
                      Category.NEW_ISSUE: False}


def target_regression_dir(target: "Target") -> Path:
    """The target's ``regression_dir``; config paths are relative to the
    config file's directory (§4.1)."""
    return target.config_dir / target.spec.regression_dir


def load_tests(target: "Target") -> list[TestCase]:
    """The regression tests in the target's ``regression_dir``, as tests of
    kind ``regression``, run after all other tests (§7.1, §10.6).

    Raises ``CONFIG_INVALID`` (exit 30) listing every problem of every file,
    like the config itself (§4.5). A missing ``regression_dir`` means no tests,
    and so does a target without a config directory (a test double).
    """
    if getattr(target, "config_dir", None) is None or getattr(target, "spec", None) is None:
        return []
    method = getattr(target, "input_method", InputMethod.STDIN)
    return read_tests(target_regression_dir(target), InputMethod(method), target.all_tests())


# The YAML schema of a regression test file (§10.6); unknown keys are errors.
class _CreatedBy(_Strict):
    tool_version: str
    run_id: str
    finding: str
    source_test: str


class _CreatedOn(_Strict):
    base_version: Optional[str] = None
    base_binary_sha256: Optional[str] = None


class _RegressionSpec(_Strict):
    name: Name
    input_file: str
    expect_base_crash: bool
    signature: Optional[str] = None
    created_by: _CreatedBy
    created_on: _CreatedOn


def read_tests(regression_dir: str | Path, input_method: InputMethod,
               config_tests: list[TestCase]) -> list[TestCase]:
    """Every ``*.yaml`` in ``regression_dir``, in file-name order, as a
    :class:`TestCase` of kind ``regression``.

    ``input_file`` is relative to ``regression_dir`` and must stay inside it.
    A test takes the ``args`` of its source test when that test is still in
    the config, so it runs with the same command line (§10.6); otherwise none.
    Names must be unique across the config tests and the regression tests.
    """
    regression_dir = Path(regression_dir)
    if not regression_dir.is_dir():
        return []
    root = regression_dir.resolve()
    by_name = {t.name: t for t in config_tests}
    tests: list[TestCase] = []
    problems: list[str] = []

    for path in sorted(regression_dir.glob("*.yaml")):
        where = f"{regression_dir.name}/{path.name}"
        try:
            raw = _read_yaml(path)
        except ZarabanError as exc:
            problems.extend(exc.details.get("problems", [exc.message]))
            continue
        try:
            spec = _RegressionSpec.model_validate(raw)
        except ValidationError as exc:
            problems.extend(f"{where}: {p}" for p in _format_errors(exc))
            continue

        if spec.name in by_name:
            problems.append(f"{where}: test name {spec.name!r} is already used by "
                            f"{'another regression test' if by_name[spec.name].kind is TestKind.REGRESSION else 'a config test'}")
            continue

        fpath = (regression_dir / spec.input_file).resolve()
        if root not in fpath.parents:
            problems.append(f"{where}: input_file must be inside {regression_dir.name}/: "
                            f"{spec.input_file}")
            continue
        if not fpath.is_file():
            problems.append(f"{where}: input_file does not exist: {spec.input_file}")
            continue
        try:
            data = fpath.read_bytes()
        except OSError as exc:
            problems.append(f"{where}: input_file cannot be read: {spec.input_file} "
                            f"({exc.strerror or exc})")
            continue
        if len(data) > MAX_INPUT_BYTES:
            problems.append(f"{where}: input_file is larger than 1 MB")
            continue
        if input_method is InputMethod.ARGS and b"\x00" in data:
            problems.append(f"{where}: input_method is 'args' but the input contains a NUL byte")
            continue

        source = by_name.get(spec.created_by.source_test)
        test = TestCase(
            name=spec.name,
            kind=TestKind.REGRESSION,
            input_bytes=data,
            input_ext=fpath.suffix,
            args=list(source.args) if source is not None else [],
            description=(f"{spec.created_by.finding} of run {spec.created_by.run_id}, "
                         f"from {spec.created_by.source_test}"),
            source_path=f"{regression_dir.name}/{spec.input_file}",
            expect_base_crash=spec.expect_base_crash,
            expected_signature=spec.signature,
        )
        tests.append(test)
        by_name[test.name] = test

    if problems:
        raise ZarabanError(ErrorCode.CONFIG_INVALID,
                           f"{len(problems)} problem(s) in the regression tests of {regression_dir}",
                           {"problems": problems})
    return tests


def base_clean_warnings(tests: list[TestCase], results: Results) -> list[Issue]:
    """``REGRESSION_BASE_CLEAN`` for each regression test that should crash on
    base but does not crash on ``base-sanitized`` (§8.6).

    In CI, base is often a commit that already holds an earlier fix, so this is
    a warning, not a finding, and it never changes the exit code. The test still
    runs on patch, where a crash is judged by the normal rules (§8.2). A flaky
    base result is left to its INCONCLUSIVE finding (§8.5).
    """
    warnings: list[Issue] = []
    for t in tests:
        if t.kind is not TestKind.REGRESSION or not t.expect_base_crash:
            continue
        r = results.get(t.name, {}).get(BuildName.BASE_SANITIZED)
        if r is None or r.flaky or r.outcome is Outcome.CRASH:
            continue
        warnings.append(Issue(
            WarningCode.REGRESSION_BASE_CLEAN.value,
            f"{t.name} no longer crashes on base-sanitized ({r.outcome.value}); "
            f"base may already contain an earlier fix",
            {"test": t.name, "expected_signature": t.expected_signature,
             "outcome": r.outcome.value}))
    return warnings


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
