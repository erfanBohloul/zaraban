"""Unit tests for run analysis (SPEC §7.4).

The fixtures in tests/fixtures/stderr are real: each was produced by a small C
program compiled like a target build and run with the tool's environment
(tests/fixtures/stderr/generate.py). Together they cover every row of the
outcome table and of the error-type table.
"""

import json
from pathlib import Path

import pytest

from zaraban.analysis import analyse, frames, is_memory_limit, outcome
from zaraban.models import Detection, ErrorType, LimitKind, Outcome

FIXTURES = Path(__file__).parent / "fixtures" / "stderr"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text())
ROOT = MANIFEST["source_root"]

D, E, O = Detection, ErrorType, Outcome
APP = "bug < caller < main"

# fixture: (outcome, detection, error type, signature functions or None)
EXPECTED = {
    "asan_stack_buffer_overflow": (O.CRASH, D.ASAN, E.STACK_BUFFER_OVERFLOW, APP),
    "asan_heap_buffer_overflow": (O.CRASH, D.ASAN, E.HEAP_BUFFER_OVERFLOW, APP),
    "asan_global_buffer_overflow": (O.CRASH, D.ASAN, E.GLOBAL_BUFFER_OVERFLOW, APP),
    "asan_heap_use_after_free": (O.CRASH, D.ASAN, E.USE_AFTER_FREE, APP),
    "asan_stack_use_after_scope": (O.CRASH, D.ASAN, E.USE_AFTER_SCOPE, APP),
    "asan_stack_overflow": (O.CRASH, D.ASAN, E.STACK_EXHAUSTION, "recurse < recurse < recurse"),
    "asan_double_free": (O.CRASH, D.ASAN, E.DOUBLE_FREE, APP),
    "asan_invalid_free": (O.CRASH, D.ASAN, E.INVALID_FREE, APP),
    "asan_null_deref": (O.CRASH, D.ASAN, E.NULL_DEREF, APP),
    "asan_segv": (O.CRASH, D.ASAN, E.SEGV, APP),
    "ubsan_div_zero": (O.CRASH, D.UBSAN, E.DIV_BY_ZERO, APP),
    "ubsan_integer_overflow": (O.CRASH, D.UBSAN, E.INTEGER_OVERFLOW, APP),
    "ubsan_index_out_of_bounds": (O.CRASH, D.UBSAN, E.OUT_OF_BOUNDS_INDEX, APP),
    "ubsan_null_pointer": (O.CRASH, D.UBSAN, E.NULL_DEREF, APP),
    "ubsan_shift": (O.CRASH, D.UBSAN, E.UB_OTHER, APP),
    "canary_stack_smashing": (O.CRASH, D.STACK_CANARY, E.STACK_BUFFER_OVERFLOW, None),
    "fortify_buffer_overflow": (O.CRASH, D.FORTIFY, E.BUFFER_OVERFLOW, None),
    "glibc_double_free": (O.CRASH, D.ALLOCATOR_CHECK, E.DOUBLE_FREE, None),
    "glibc_invalid_pointer": (O.CRASH, D.ALLOCATOR_CHECK, E.INVALID_FREE, None),
    "glibc_heap_corruption": (O.CRASH, D.ALLOCATOR_CHECK, E.HEAP_CORRUPTION, None),
    "signal_segv": (O.CRASH, D.SIGNAL, E.SEGV, None),
    "signal_fpe": (O.CRASH, D.SIGNAL, E.DIV_BY_ZERO, None),
    "signal_abort": (O.CRASH, D.SIGNAL, E.ABORT, None),
    "normal_exit_3": (O.NORMAL, None, None, None),
}


def load(name: str):
    meta = MANIFEST["fixtures"][name]
    return (FIXTURES / f"{name}.stderr").read_text(errors="replace"), meta


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_7_4_real_fixture(name):
    stderr, meta = load(name)
    a = analyse(stderr, exit_code=meta["exit_code"], sig=meta["signal"], source_root=ROOT)
    want_outcome, want_detection, want_type, want_funcs = EXPECTED[name]
    assert a.outcome is want_outcome
    assert a.detection is want_detection
    assert a.error_type is want_type
    assert a.signature == (f"{want_type.value} @ {want_funcs}" if want_funcs else None)


def test_7_4_fixtures_cover_every_error_type_and_outcome():
    covered = {v[2] for v in EXPECTED.values()} | {ErrorType.UNKNOWN}  # UNKNOWN: below
    assert covered - {None} == set(ErrorType)
    assert {v[1] for v in EXPECTED.values()} - {None} == set(Detection)
    assert set(EXPECTED) | {"asan_allocation_too_big"} == set(MANIFEST["fixtures"])


def test_7_4_other_signal_is_unknown():
    a = analyse("", sig="SIGILL")
    assert (a.outcome, a.detection, a.error_type) == (O.CRASH, D.SIGNAL, E.UNKNOWN)


# -- the order of the rules --------------------------------------------------

def test_7_4_rule_1_timeout_wins_over_everything():
    stderr, meta = load("asan_heap_buffer_overflow")
    assert outcome(stderr, meta["signal"], timed_out=True) == (O.TIMEOUT, None)


def test_7_4_rule_2_resource_limits():
    assert outcome("", "SIGXCPU") == (O.RESOURCE_LIMIT, None)
    assert outcome("", "SIGKILL", limit_hit=LimitKind.CPU) == (O.RESOURCE_LIMIT, None)


def test_7_4_rule_2_asan_allocation_over_the_memory_limit():
    stderr, meta = load("asan_allocation_too_big")
    assert is_memory_limit(stderr)
    a = analyse(stderr, sig=meta["signal"], limit_hit=LimitKind.MEMORY)
    assert a.outcome is O.RESOURCE_LIMIT and a.signature is None
    for name in EXPECTED:  # no real crash looks like a memory limit
        assert not is_memory_limit(load(name)[0]), name


def test_7_4_rule_4_ubsan_report_without_stop_is_not_a_crash():
    stderr, _ = load("ubsan_div_zero")
    assert outcome(stderr, None) == (O.NORMAL, None)


def test_7_4_rule_9_nonzero_exit_is_never_a_crash():
    a = analyse("error: bad input\n", exit_code=3)
    assert a.outcome is O.NORMAL and a.error_type is None and a.frames == []


# -- stack traces and signatures ---------------------------------------------

def test_7_4_frames_are_relative_to_the_source_root():
    stderr, _ = load("asan_heap_buffer_overflow")
    fr = frames(stderr, ROOT)
    assert (fr[0].index, fr[0].function, fr[0].file, fr[0].line) == \
        (0, "bug", "src/asan_heap_buffer_overflow.c", 8)
    assert not fr[0].runtime


def test_7_4_only_the_first_stack_is_parsed():
    # A use-after-free report also prints where the memory was freed and
    # allocated; those stacks must not leak into the frames.
    stderr, _ = load("asan_heap_use_after_free")
    assert "freed by thread" in stderr
    fr = frames(stderr, ROOT)
    assert [f.index for f in fr] == list(range(len(fr)))
    assert "free" not in [f.function for f in fr]


def test_7_4_asan_interceptors_are_runtime_frames():
    stderr, _ = load("asan_double_free")
    fr = frames(stderr, ROOT)
    assert fr[0].function == "free" and fr[0].runtime
    stderr, _ = load("asan_allocation_too_big")
    assert frames(stderr, ROOT)[0].runtime  # __interceptor_malloc


def test_7_4_signature_ignores_line_numbers():
    stderr, meta = load("asan_heap_buffer_overflow")
    moved = stderr.replace(".c:8:", ".c:99:")
    assert analyse(stderr, sig="SIGABRT").signature == analyse(moved, sig="SIGABRT").signature


def test_7_4_no_function_names_means_no_signature():
    stderr = ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018\n"
              "    #0 0x4011d6  (/w/prog+0x4011d6)\n    #1 0x401200  (/w/prog+0x401200)\n")
    a = analyse(stderr, sig="SIGABRT")
    assert a.error_type is E.HEAP_BUFFER_OVERFLOW and a.signature is None


def test_7_4_summary_is_the_first_report_line():
    stderr, meta = load("asan_heap_buffer_overflow")
    a = analyse(stderr, sig=meta["signal"])
    assert "ERROR: AddressSanitizer: heap-buffer-overflow" in a.summary
    stderr, meta = load("ubsan_shift")
    assert "runtime error: shift exponent 40" in analyse(stderr, sig=meta["signal"]).summary


def test_7_4_c_startup_code_is_not_part_of_the_signature():
    # A shallow stack: the frame below main is libc's _start (crt1.o), linked
    # into the program, which must not become the third signature function.
    stderr = ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018\n"
              "    #0 0x4011d6 in bug /w/x.c:3:5\n"
              "    #1 0x401200 in main /w/x.c:9:5\n"
              "    #2 0x7f00 in __libc_start_call_main (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f)\n"
              "    #3 0x7f01 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29e3f)\n"
              "    #4 0x401100 in _start (/w/prog+0x401100)\n")
    assert analyse(stderr, sig="SIGABRT").signature == "HEAP_BUFFER_OVERFLOW @ bug < main"
