"""Unit tests for the execution trace (SPEC §9.4).

The three heavy steps (build, run, export) are injected, so nothing here needs
clang or LLVM: the parsing and the changed-line intersection are tested with a
fixture lcov dump, and the orchestration with fakes.
"""

from pathlib import Path

from types import SimpleNamespace

from zaraban import coverage
from zaraban.coverage import RunSpec, TraceResult
from zaraban.models import InputMethod, Issue, LinkLevel, TestKind, TestCase, Version, WarningCode


# -- fixtures ----------------------------------------------------------------

LCOV = """\
TN:
SF:/w/patch-coverage/src/main.c
DA:21,1
DA:24,3
DA:25,0
DA:27,3
DA:40,0
LF:5
LH:3
end_of_record
SF:/w/patch-coverage/src/util.c
DA:10,0
end_of_record
"""


def a_test() -> TestCase:
    return TestCase(name="valid_set", kind=TestKind.VALID, input_bytes=b"SET x=1",
                    input_ext=".txt", args=["{input_file}"])


def a_spec() -> RunSpec:
    return RunSpec(binary_rel="token_parser", input_method=InputMethod.FILE)


# -- parse_lcov --------------------------------------------------------------

def test_parse_lcov_reads_sf_and_da():
    cov = coverage.parse_lcov(LCOV)
    assert set(cov) == {"/w/patch-coverage/src/main.c", "/w/patch-coverage/src/util.c"}
    assert cov["/w/patch-coverage/src/main.c"] == {21: 1, 24: 3, 25: 0, 27: 3, 40: 0}
    assert cov["/w/patch-coverage/src/util.c"] == {10: 0}


def test_parse_lcov_ignores_junk_lines():
    cov = coverage.parse_lcov("SF:x.c\nFN:1,foo\nDA:7,2\nDA:bad\nend_of_record\n")
    assert cov == {"x.c": {7: 2}}


# -- select_executed ---------------------------------------------------------

def test_select_executed_keeps_only_changed_lines_that_ran():
    cov = coverage.parse_lcov(LCOV)
    # changed lines on the patch side of src/main.c: 24, 25, 27, 40
    changed = {"src/main.c": {24, 25, 27, 40}}
    assert coverage.select_executed(cov, changed) == {"src/main.c": [24, 27]}


def test_select_executed_matches_absolute_build_paths():
    cov = {"/tmp/work/patch-coverage/src/main.c": {5: 1}}
    assert coverage.select_executed(cov, {"src/main.c": {5}}) == {"src/main.c": [5]}


def test_select_executed_drops_file_with_no_executed_line():
    cov = coverage.parse_lcov(LCOV)
    assert coverage.select_executed(cov, {"src/util.c": {10}}) == {}


# -- trace orchestration (fakes) ---------------------------------------------

def _fake_build(binary="/w/patch-coverage/token_parser"):
    return lambda tree, cmd, dest, rel: Path(binary)


def _fake_run_writes_profile(ok=True):
    def run(binary, test, spec, profraw, run_dir):
        if not ok:
            return False
        Path(profraw).parent.mkdir(parents=True, exist_ok=True)
        Path(profraw).write_bytes(b"\x00")
        return True
    return run


def test_trace_happy_path_reports_executed_changed_lines(tmp_path):
    out = coverage.trace(
        version_tree=tmp_path / "tree", coverage_cmd="make coverage",
        test=a_test(), changed={"src/main.c": {24, 25, 27, 40}},
        work_dir=tmp_path, spec=a_spec(), label="patch-coverage",
        build=_fake_build(), run=_fake_run_writes_profile(), export=lambda b, p, t: LCOV,
    )
    assert out.available
    assert out.executed_changed_lines == [24, 27]
    assert out.per_file == {"src/main.c": [24, 27]}
    assert out.warning is None


def test_trace_no_coverage_cmd_is_unavailable(tmp_path):
    out = coverage.trace(tmp_path, None, a_test(), {"src/main.c": {24}}, tmp_path, a_spec())
    assert not out.available
    assert out.warning is not None and out.warning.code == WarningCode.TRACE_UNAVAILABLE.value


def test_trace_build_failure_is_unavailable(tmp_path):
    out = coverage.trace(
        tmp_path, "make coverage", a_test(), {"src/main.c": {24}}, tmp_path, a_spec(),
        build=lambda tree, cmd, dest, rel: None,
    )
    assert not out.available
    assert out.warning.code == WarningCode.TRACE_UNAVAILABLE.value


def test_trace_run_without_profile_is_unavailable(tmp_path):
    out = coverage.trace(
        tmp_path, "make coverage", a_test(), {"src/main.c": {24}}, tmp_path, a_spec(),
        build=_fake_build(), run=_fake_run_writes_profile(ok=False), export=lambda b, p, t: LCOV,
    )
    assert not out.available
    assert out.warning.code == WarningCode.TRACE_UNAVAILABLE.value


def test_trace_export_failure_is_unavailable(tmp_path):
    out = coverage.trace(
        tmp_path, "make coverage", a_test(), {"src/main.c": {24}}, tmp_path, a_spec(),
        build=_fake_build(), run=_fake_run_writes_profile(), export=lambda b, p, t: None,
    )
    assert not out.available
    assert out.warning.code == WarningCode.TRACE_UNAVAILABLE.value


def test_trace_ran_but_no_changed_line_executed_is_available_without_warning(tmp_path):
    # changed line 40 never ran (DA:40,0) -> trace is available, result empty, no warning.
    out = coverage.trace(
        tmp_path, "make coverage", a_test(), {"src/main.c": {40}}, tmp_path, a_spec(),
        build=_fake_build(), run=_fake_run_writes_profile(), export=lambda b, p, t: LCOV,
    )
    assert out.available
    assert out.executed_changed_lines == []
    assert out.warning is None


# -- the real run step runs the binary and honours LLVM_PROFILE_FILE ----------

def test_run_for_profile_runs_the_binary_and_writes_the_profile(tmp_path):
    # A stand-in for an instrumented binary: a shell script that consumes stdin
    # and writes the file named by LLVM_PROFILE_FILE, exactly as a real coverage
    # binary flushes its profile on exit. Exercises the real run_for_profile:
    # command invocation, stdin feeding, and profile-env propagation.
    prog = tmp_path / "prog.sh"
    prog.write_text('#!/bin/sh\ncat > /dev/null\n: > "$LLVM_PROFILE_FILE"\n')
    prog.chmod(0o755)
    spec = RunSpec(binary_rel="prog.sh", input_method=InputMethod.STDIN)
    test = TestCase(name="t", kind=TestKind.VALID, input_bytes=b"hello")
    profraw = tmp_path / "run" / "trace.profraw"
    assert coverage.run_for_profile(prog, test, spec, profraw, tmp_path / "rundir") is True
    assert profraw.exists()


# -- execution_traces: pick which findings to trace and collect the results --

def _finding(fid, level, side, tests, comparative=None):
    link = SimpleNamespace(level=level, side=side, comparative_tests=comparative or [])
    return SimpleNamespace(id=fid, link=link,
                           tests=[SimpleNamespace(test=t) for t in tests])


def test_execution_traces_only_traces_undetermined_findings_with_a_side(tmp_path):
    seen = []

    def fake_trace(target, tree, test, changed, work_dir, *, label):
        seen.append(label)
        return TraceResult(True, executed_changed_lines=[24, 27],
                           per_file={"src/main.c": [24, 27]})

    findings = [
        _finding("F-001", LinkLevel.UNDETERMINED, Version.PATCH, ["valid_set"]),        # traced
        _finding("F-002", LinkLevel.IN_CHANGED_HUNK, Version.PATCH, ["exploit"]),       # has evidence
        _finding("F-003", LinkLevel.UNDETERMINED, None, ["other"]),                     # no side
    ]
    traces, warns = coverage.execution_traces(
        findings, {"valid_set": a_test()},
        {Version.PATCH: {"src/main.c": {24, 25, 27}}}, {Version.PATCH: tmp_path},
        target=None, work_dir=tmp_path, trace_fn=fake_trace)

    assert traces == {"F-001": [24, 27]}
    assert warns == []
    assert seen == ["patch-coverage"]                # only the UNDETERMINED, with-a-side finding


def test_execution_traces_prefers_the_comparative_test(tmp_path):
    picked = {}

    def fake_trace(target, tree, test, changed, work_dir, *, label):
        picked["test"] = test.name
        return TraceResult(True, executed_changed_lines=[5])

    f = _finding("F-001", LinkLevel.UNDETERMINED, Version.PATCH,
                 ["first_test"], comparative=["valid_set"])
    coverage.execution_traces(
        f and [f], {"valid_set": a_test(), "first_test": a_test()},
        {Version.PATCH: {"src/main.c": {5}}}, {Version.PATCH: tmp_path},
        None, tmp_path, trace_fn=fake_trace)
    assert picked["test"] == "valid_set"


def test_execution_traces_collects_unavailable_warning(tmp_path):
    def fake_trace(target, tree, test, changed, work_dir, *, label):
        return TraceResult(False, warning=Issue(WarningCode.TRACE_UNAVAILABLE.value, "no trace"))

    findings = [_finding("F-001", LinkLevel.UNDETERMINED, Version.PATCH, ["valid_set"])]
    traces, warns = coverage.execution_traces(
        findings, {"valid_set": a_test()},
        {Version.PATCH: {"a.c": {1}}}, {Version.PATCH: tmp_path},
        None, tmp_path, trace_fn=fake_trace)
    assert traces == {}
    assert len(warns) == 1 and warns[0].code == WarningCode.TRACE_UNAVAILABLE.value


def test_execution_traces_reports_one_warning_per_reason(tmp_path):
    def fake_trace(target, tree, test, changed, work_dir, *, label):
        return TraceResult(False, warning=Issue(WarningCode.TRACE_UNAVAILABLE.value, "same reason"))

    findings = [_finding("F-001", LinkLevel.UNDETERMINED, Version.PATCH, ["valid_set"]),
                _finding("F-002", LinkLevel.UNDETERMINED, Version.PATCH, ["valid_set"])]
    _, warns = coverage.execution_traces(
        findings, {"valid_set": a_test()},
        {Version.PATCH: {"a.c": {1}}}, {Version.PATCH: tmp_path},
        None, tmp_path, trace_fn=fake_trace)
    assert len(warns) == 1


def test_run_trace_target_without_coverage_cmd_is_unavailable(tmp_path):
    # A target whose config has no build.coverage_cmd (or no build section at
    # all, as in hand-built test targets) must not raise.
    target = SimpleNamespace(spec=SimpleNamespace(name="t"))
    out = coverage.run_trace(target, tmp_path, a_test(), {"src/main.c": {1}}, tmp_path)
    assert not out.available
    assert out.warning.code == WarningCode.TRACE_UNAVAILABLE.value
