"""Unit tests for reproducer bundles and ddmin (SPEC §10.1–§10.3).

The program is an injected ``run`` function, so these are deterministic and
need no compiler: a fake runner "crashes" whenever the input still contains a
trigger substring, which is exactly what minimization must preserve.
"""

from zaraban.models import (
    Analysis,
    BuildName,
    ErrorType,
    Frame,
    InputInfo,
    OracleResult,
    Outcome,
    RunRecord,
    StreamInfo,
    TestKind,
    WarningCode,
)
from zaraban.reproducer import RunOutcome, ddmin, reproduce


# -- a deterministic fake runner ---------------------------------------------

def crasher(trigger: bytes, signature: str = "HEAP_BUFFER_OVERFLOW @ boom"):
    """Return a run() that crashes (with a fixed signature) iff ``trigger`` is
    a substring of the input. Models.py's signature string stands in for the
    real error-type + top-frames signature."""
    def run(data: bytes) -> RunOutcome:
        if trigger in data:
            return RunOutcome(crashed=True, signature=signature, signal="SIGABRT",
                              exit_code=None, error_type=ErrorType.HEAP_BUFFER_OVERFLOW,
                              top_functions=["boom", "parse"], duration_s=0.01)
        return RunOutcome(crashed=False, signature=None, exit_code=0, duration_s=0.01)
    return run


# -- ddmin (§10.2) -----------------------------------------------------------

def test_10_2_ddmin_shrinks_to_the_trigger():
    data = b"xxxxxBUGxxxxxxxxxx"
    interesting = lambda b: b"BUG" in b
    out, calls, limit_hit = ddmin(data, interesting, limit=1000)
    assert b"BUG" in out
    assert len(out) < len(data)
    assert not limit_hit
    assert calls > 0


def test_10_2_ddmin_keeps_minimum_when_already_minimal():
    out, _, _ = ddmin(b"BUG", lambda b: b"BUG" in b, limit=1000)
    assert b"BUG" in out


def test_10_2_ddmin_reports_limit_hit():
    # A tiny budget is exhausted before ddmin finishes.
    data = b"A" * 64 + b"BUG" + b"A" * 64
    _, calls, limit_hit = ddmin(data, lambda b: b"BUG" in b, limit=3)
    assert limit_hit
    assert calls <= 3


# -- reproduce(): minimize + replay (§10.1, §10.3) ---------------------------

def test_10_minimizes_and_replays_stable(tmp_path):
    original = b"PREFIX____SET x=AAAAAAAAAAAAAAAA____SUFFIX"
    bundle, warnings = reproduce(
        finding_id="F-001", source_test="exploit_primary",
        build=BuildName.PATCH_SANITIZED, input_bytes=original,
        run=crasher(b"AAAA"), out_dir=tmp_path, repeats=3,
    )
    assert warnings == []
    assert bundle.finding == "F-001"
    assert bundle.original_size == len(original)
    assert bundle.minimized_size is not None and bundle.minimized_size < bundle.original_size
    assert bundle.replayed_input == "min"
    assert bundle.stable
    assert len(bundle.replays) == 3
    assert all(r.reproduced for r in bundle.replays)
    assert bundle.replays[0].error_type is ErrorType.HEAP_BUFFER_OVERFLOW


def test_10_3_bundle_files_written(tmp_path):
    bundle, _ = reproduce(
        finding_id="F-001", source_test="t", build=BuildName.PATCH_SANITIZED,
        input_bytes=b"junk AAAA junk", run=crasher(b"AAAA"), out_dir=tmp_path,
    )
    d = tmp_path / "reproducers" / "F-001"
    assert (d / "input.orig").read_bytes() == b"junk AAAA junk"
    assert (d / "input.min").exists()
    assert b"AAAA" in (d / "input.min").read_bytes()
    assert (d / "replay.sh").exists()
    assert bundle.path == "reproducers/F-001"


def test_10_minimize_limit_warns(tmp_path):
    original = b"B" * 50 + b"AAAA" + b"B" * 50
    bundle, warnings = reproduce(
        finding_id="F-002", source_test="t", build=BuildName.PATCH_SANITIZED,
        input_bytes=original, run=crasher(b"AAAA"), out_dir=tmp_path,
        minimize_limit=2,
    )
    assert bundle.minimize_limit_hit
    assert any(w.code == WarningCode.MINIMIZE_LIMIT.value for w in warnings)


def test_10_no_minimization_when_disabled(tmp_path):
    bundle, _ = reproduce(
        finding_id="F-003", source_test="t", build=BuildName.PATCH_SANITIZED,
        input_bytes=b"xx AAAA xx", run=crasher(b"AAAA"), out_dir=tmp_path,
        minimize=False,
    )
    assert bundle.minimized_size is None
    assert bundle.minimize_runs == 0
    assert bundle.replayed_input == "orig"
    assert bundle.stable


# -- non-reproducing input (§10.1) -------------------------------------------

def test_10_1_input_that_does_not_crash_is_unstable(tmp_path):
    bundle, warnings = reproduce(
        finding_id="F-004", source_test="t", build=BuildName.BASE_SANITIZED,
        input_bytes=b"totally benign", run=crasher(b"AAAA"), out_dir=tmp_path,
    )
    assert not bundle.stable
    assert bundle.minimized_size is None
    assert bundle.replays[0].reproduced is False
    assert (tmp_path / "reproducers" / "F-004" / "input.orig").exists()


def test_10_flaky_crash_is_not_stable(tmp_path):
    # Reproduces on the first (signature-setting) run and during minimization,
    # but then alternates on replay -> not stable.
    calls = {"n": 0}

    def flaky(data: bytes) -> RunOutcome:
        calls["n"] += 1
        # Crash while establishing the target and during ddmin; on replay, every
        # other run is clean.
        crash = b"AAAA" in data and calls["n"] % 2 == 1
        if crash:
            return RunOutcome(True, "SEGV @ f", signal="SIGSEGV", duration_s=0.01)
        return RunOutcome(False, None, exit_code=0, duration_s=0.01)

    bundle, _ = reproduce(
        finding_id="F-005", source_test="t", build=BuildName.PATCH_SANITIZED,
        input_bytes=b"zz AAAA zz", run=flaky, out_dir=tmp_path, minimize=False, repeats=4,
    )
    assert not bundle.stable
    assert not all(r.reproduced for r in bundle.replays)


# -- the RunRecord adapter ---------------------------------------------------

def test_10_runoutcome_from_record():
    analysis = Analysis(
        outcome=Outcome.CRASH, error_type=ErrorType.HEAP_BUFFER_OVERFLOW,
        signature="HEAP_BUFFER_OVERFLOW @ boom < parse",
        frames=[
            Frame(0, "__asan_memcpy", None, None, runtime=True),
            Frame(1, "boom", "src/main.c", 42, runtime=False),
            Frame(2, "parse", "src/main.c", 10, runtime=False),
        ],
    )
    rec = RunRecord(
        test="t", kind=TestKind.SECURITY, build=BuildName.PATCH_SANITIZED, repeat=1,
        cmd=["./prog"], env={}, cwd=".",
        input=InputInfo(method=None, name=None, size=4, sha256="0" * 64),
        exit_code=None, signal="SIGABRT", timed_out=False, limit_hit=None, duration_s=0.5,
        stdout=StreamInfo("o", 0, "0" * 64), stderr=StreamInfo("e", 0, "0" * 64),
        analysis=analysis, oracle=OracleResult(False, None),
    )
    o = RunOutcome.from_record(rec)
    assert o.crashed and o.signature.startswith("HEAP_BUFFER_OVERFLOW")
    assert o.top_functions == ["boom", "parse"]  # runtime frame dropped
    assert o.signal == "SIGABRT" and o.duration_s == 0.5
