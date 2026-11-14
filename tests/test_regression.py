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


# -- loading in later runs (§10.6) ---------------------------------

import pytest  # noqa: E402

from zaraban.models import (  # noqa: E402
    Analysis,
    CombinedResult,
    ErrorCode,
    InputInfo,
    InputMethod,
    OracleResult,
    Outcome,
    RunRecord,
    StreamInfo,
    TestCase,
    ZarabanError,
)
from zaraban.regression import base_clean_warnings, load_tests, read_tests  # noqa: E402

CONFIG_TESTS = [
    TestCase("valid_ping", TestKind.VALID, b"PING", ".txt"),
    TestCase("exploit_secondary", TestKind.SECURITY, b"SET " + b"A" * 80, ".txt",
             args=["--strict", "{input_file}"]),
]


def _promoted(tmp_path, **kw):
    """The regression_dir as a first run leaves it: one promoted test."""
    _call(tmp_path, **kw)
    return tmp_path / "target_regression"


def _problems(exc_info):
    assert exc_info.value.code is ErrorCode.CONFIG_INVALID
    return exc_info.value.details["problems"]


def test_2_3_promoted_test_loads_back_as_a_regression_test(tmp_path):
    reg = _promoted(tmp_path)
    [t] = read_tests(reg, InputMethod.FILE, CONFIG_TESTS)
    assert t.name == NAME and t.kind is TestKind.REGRESSION
    assert t.input_bytes == DATA and t.input_ext == ".txt"
    assert t.expect_base_crash is True and t.expected_signature == SIG
    assert t.args == ["--strict", "{input_file}"]  # the source test's command line
    assert t.source_path == f"target_regression/{NAME}.txt"
    assert "F-001" in t.description and "exploit_secondary" in t.description
    assert not t.has_oracle  # judged by the crash rules only (§8.2, §8.6)


def test_2_3_new_issue_test_expects_no_base_crash(tmp_path):
    reg = _promoted(tmp_path, category=Category.NEW_ISSUE, run_base=clean)
    [t] = read_tests(reg, InputMethod.FILE, CONFIG_TESTS)
    assert t.expect_base_crash is False


def test_2_3_source_test_gone_from_config_runs_without_args(tmp_path):
    reg = _promoted(tmp_path)
    [t] = read_tests(reg, InputMethod.FILE, CONFIG_TESTS[:1])
    assert t.args == []


def test_2_3_missing_or_empty_dir_gives_no_tests(tmp_path):
    assert read_tests(tmp_path / "nope", InputMethod.FILE, CONFIG_TESTS) == []
    (tmp_path / "empty").mkdir()
    assert read_tests(tmp_path / "empty", InputMethod.FILE, CONFIG_TESTS) == []


def test_2_3_tests_load_in_file_name_order(tmp_path):
    _call(tmp_path, data=b"SET y=BBBB")
    reg = _promoted(tmp_path)
    names = [t.name for t in read_tests(reg, InputMethod.FILE, CONFIG_TESTS)]
    assert names == sorted(names) and len(names) == 2


def test_2_3_load_tests_reads_the_targets_regression_dir(tmp_path):
    from types import SimpleNamespace
    reg = tmp_path / "tests" / "regression"
    _call(tmp_path)
    reg.parent.mkdir()
    (tmp_path / "target_regression").rename(reg)
    target = SimpleNamespace(config_dir=tmp_path,
                             spec=SimpleNamespace(regression_dir="tests/regression"),
                             input_method=InputMethod.FILE, all_tests=lambda: list(CONFIG_TESTS))
    assert [t.name for t in load_tests(target)] == [NAME]
    # A test double without a config directory has no regression tests.
    assert load_tests(SimpleNamespace(all_tests=lambda: [])) == []


def test_2_3_name_used_by_a_config_test_is_invalid(tmp_path):
    reg = _promoted(tmp_path)
    clash = CONFIG_TESTS + [TestCase(NAME, TestKind.VALID, b"x", ".txt")]
    with pytest.raises(ZarabanError) as e:
        read_tests(reg, InputMethod.FILE, clash)
    assert any("already used by a test in the config" in p for p in _problems(e))


def test_2_3_same_name_in_two_files_is_invalid(tmp_path):
    reg = _promoted(tmp_path)
    text = (reg / f"{NAME}.yaml").read_text()
    (reg / "zz-copy.yaml").write_text(text)
    with pytest.raises(ZarabanError) as e:
        read_tests(reg, InputMethod.FILE, CONFIG_TESTS)
    assert any("zz-copy.yaml" in p and "another regression test" in p for p in _problems(e))


def test_2_3_every_problem_of_every_file_is_reported(tmp_path):
    reg = _promoted(tmp_path)
    spec = yaml.safe_load((reg / f"{NAME}.yaml").read_text())
    (reg / "a-bad-yaml.yaml").write_text("name: [unclosed\n")
    (reg / "b-unknown-key.yaml").write_text(yaml.safe_dump({**spec, "name": "b", "oops": 1}))
    (reg / "c-no-input.yaml").write_text(
        yaml.safe_dump({**spec, "name": "c", "input_file": "missing.txt"}))
    (reg / "d-escape.yaml").write_text(
        yaml.safe_dump({**spec, "name": "d", "input_file": "../out/regression/x.txt"}))
    bad = {k: v for k, v in spec.items() if k not in ("expect_base_crash", "created_by")}
    (reg / "e-missing-fields.yaml").write_text(yaml.safe_dump({**bad, "name": "e"}))
    (reg / "f-bad-name.yaml").write_text(yaml.safe_dump({**spec, "name": "has space"}))

    with pytest.raises(ZarabanError) as e:
        read_tests(reg, InputMethod.FILE, CONFIG_TESTS)
    problems = _problems(e)
    text = "\n".join(problems)
    assert "a-bad-yaml.yaml" in text and "YAML" in text
    assert "b-unknown-key.yaml: unknown key 'oops'" in text
    assert "c-no-input.yaml: input_file" in text and "does not exist" in text
    assert "d-escape.yaml: input_file" in text and "points outside" in text
    assert "e-missing-fields.yaml: expect_base_crash" in text
    assert "e-missing-fields.yaml: created_by" in text
    assert "f-bad-name.yaml: name" in text


def test_2_3_args_input_with_nul_is_invalid(tmp_path):
    reg = _promoted(tmp_path, data=b"SET \x00x")
    with pytest.raises(ZarabanError) as e:
        read_tests(reg, InputMethod.ARGS, CONFIG_TESTS)
    assert any("NUL byte" in p for p in _problems(e))
    assert len(read_tests(reg, InputMethod.FILE, CONFIG_TESTS)) == 1


# -- REGRESSION_BASE_CLEAN (§8.6) --------------------------------------------

def _combined(test, build, crashed, flaky=False):
    a = Analysis(Outcome.CRASH if crashed else Outcome.NORMAL,
                 signature=SIG if crashed else None)
    rec = RunRecord(test=test, kind=TestKind.REGRESSION, build=build, repeat=1, cmd=[], env={},
                    cwd="", input=InputInfo(InputMethod.FILE, "input.txt", 1, "0" * 64),
                    exit_code=None if crashed else 0, signal="SIGABRT" if crashed else None,
                    timed_out=False, limit_hit=None, duration_s=0.0,
                    stdout=StreamInfo("1.stdout", 0, "a" * 64), stderr=StreamInfo("1.stderr", 0, "b" * 64),
                    analysis=a, oracle=OracleResult(False, None))
    return CombinedResult(test, TestKind.REGRESSION, build, [rec], flaky)


def _reg(name, expect_crash=True):
    return TestCase(name, TestKind.REGRESSION, DATA, ".txt", expect_base_crash=expect_crash,
                    expected_signature=SIG if expect_crash else None)


def test_8_6_regression_test_clean_on_base_is_a_warning(tmp_path):
    tests = [_reg("reg-a"), _reg("reg-b"), _reg("reg-c", expect_crash=False), _reg("reg-d"),
             CONFIG_TESTS[1]]
    results = {
        "reg-a": {BuildName.BASE_SANITIZED: _combined("reg-a", BuildName.BASE_SANITIZED, False)},
        "reg-b": {BuildName.BASE_SANITIZED: _combined("reg-b", BuildName.BASE_SANITIZED, True)},
        "reg-c": {BuildName.BASE_SANITIZED: _combined("reg-c", BuildName.BASE_SANITIZED, False)},
        "reg-d": {BuildName.BASE_SANITIZED: _combined("reg-d", BuildName.BASE_SANITIZED, False,
                                                      flaky=True)},
        "exploit_secondary": {BuildName.BASE_SANITIZED: _combined(
            "exploit_secondary", BuildName.BASE_SANITIZED, False)},
    }
    warnings = base_clean_warnings(tests, results)
    # reg-a only: reg-b crashes as expected, reg-c expects no crash, reg-d is
    # flaky (its own INCONCLUSIVE finding), exploit_secondary is not a regression test.
    assert [(w.code, w.details["test"]) for w in warnings] == [
        (WarningCode.REGRESSION_BASE_CLEAN.value, "reg-a")]
    assert warnings[0].details["expected_signature"] == SIG
