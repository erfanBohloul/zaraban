"""Unit tests for reproducer bundles and ddmin (SPEC §10.1–§10.5).

Most tests inject a fake ``run`` that "crashes" whenever the input still
contains a trigger, which is exactly what minimization must preserve. The last
tests build a real AddressSanitizer binary and run the generated
``reproduce.sh`` on it (skipped when clang is not available).
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from zaraban.models import (
    Analysis,
    BinaryInfo,
    BuildName,
    BuildRecord,
    BuildSummary,
    Category,
    DiffInfo,
    Detection,
    EnvironmentInfo,
    ErrorType,
    Finding,
    FindingTest,
    Frame,
    InputInfo,
    InputMethod,
    OracleResult,
    Outcome,
    RunRecord,
    StreamInfo,
    TestKind,
    VersionInfo,
    WarningCode,
)
from zaraban.reproducer import (
    RunOutcome,
    apply_bundle,
    bundle_build,
    ddmin,
    reproduce,
    source_test,
)

SIG = "HEAP_BUFFER_OVERFLOW @ boom < parse < main"


# -- fixtures ----------------------------------------------------------------

def crasher(trigger: bytes, signature: str = SIG):
    """A run() that crashes with ``signature`` iff ``trigger`` is in the input."""
    def run(data: bytes) -> RunOutcome:
        if trigger in data:
            return RunOutcome(crashed=True, signature=signature, signal="SIGABRT",
                              error_type=ErrorType.HEAP_BUFFER_OVERFLOW,
                              detection=Detection.ASAN,
                              top_functions=["boom", "parse", "main"], duration_s=0.01)
        return RunOutcome(crashed=False, signature=None, exit_code=0, duration_s=0.01)
    return run


def run_record(signature=SIG, error_type=ErrorType.HEAP_BUFFER_OVERFLOW,
               detection=Detection.ASAN, method=InputMethod.FILE, cmd=None,
               cwd="/run/exploit_primary", build=BuildName.PATCH_SANITIZED,
               env=None, signal="SIGABRT") -> RunRecord:
    return RunRecord(
        test="exploit_primary", kind=TestKind.SECURITY, build=build, repeat=1,
        cmd=cmd or ["/out/builds/patch-sanitized/bin/prog", "input.txt"],
        env=env or {"PATH": "/usr/bin:/bin", "ASAN_OPTIONS": "abort_on_error=1"},
        cwd=cwd,
        input=InputInfo(method=method, name="input.txt" if method is InputMethod.FILE else None,
                        size=10, sha256="0" * 64),
        exit_code=None, signal=signal, timed_out=False, limit_hit=None, duration_s=0.01,
        stdout=StreamInfo("o", 0, "0" * 64), stderr=StreamInfo("e", 0, "0" * 64),
        analysis=Analysis(outcome=Outcome.CRASH, detection=detection, error_type=error_type,
                          signature=signature),
        oracle=OracleResult(False, None),
    )


def build_record(run_dir: Path, build=BuildName.PATCH_SANITIZED, binary: Path = None) -> BuildRecord:
    if binary is None:
        binary = run_dir / "builds" / build.value / "bin" / "prog"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"\x7fELF fake binary")
    rel = os.path.relpath(binary, run_dir)
    return BuildRecord(build=build, status="ok", cmd="make sanitized",
                       env={"PATH": "/usr/bin:/bin", "LANG": "C"}, cwd="work/patch",
                       exit_code=0, duration_s=1.0, log=f"builds/{build.value}/build.log",
                       binary=BinaryInfo(rel, binary.stat().st_size, "0" * 64),
                       sanitizers_verified=True)


def versions():
    return {"base": VersionInfo("directory", "src", "c76e9ca", "a" * 64),
            "patch": VersionInfo("diff", "fix.patch", "c76e9ca", "b" * 64, strip_level=1),
            "diff": DiffInfo("inputs/patch.diff", "d" * 64, ["src/main.c"], 1)}


def environment():
    return EnvironmentInfo("Ubuntu 22.04", "6.8", "x86_64", "zaraban:latest", "3.10",
                           "gcc 11", "clang 14", "/usr/bin/llvm-symbolizer")


def a_finding(category=Category.INCOMPLETE_FIX, fid="F-001") -> Finding:
    crash = BuildSummary(Outcome.CRASH, Detection.ASAN, "SIGABRT")
    clean = BuildSummary(Outcome.NORMAL, exit_code=1)
    return Finding(id=fid, category=category, signature=SIG,
                   error_type=ErrorType.HEAP_BUFFER_OVERFLOW, tests=[
                       FindingTest("exploit_primary", TestKind.SECURITY,
                                   {BuildName.BASE_SANITIZED: crash,
                                    BuildName.PATCH_SANITIZED: clean}),
                       FindingTest("exploit_secondary", TestKind.SECURITY,
                                   {BuildName.BASE_SANITIZED: crash,
                                    BuildName.PATCH_SANITIZED: crash}),
                   ])


def make(tmp_path, data, run, *, source=None, finding=None, **kw):
    return reproduce(finding=finding or a_finding(), source=source or run_record(),
                     input_bytes=data, input_ext=".txt", build=build_record(tmp_path),
                     run_dir=tmp_path, run=run, versions=versions(),
                     environment=environment(), **kw)


# -- which findings get a bundle (§10.1) -------------------------------------

def test_10_1_bundle_build_per_category():
    assert bundle_build(Category.FIXED) is BuildName.BASE_SANITIZED
    assert bundle_build(Category.INCOMPLETE_FIX) is BuildName.PATCH_SANITIZED
    assert bundle_build(Category.NEW_ISSUE) is BuildName.PATCH_SANITIZED
    assert bundle_build(Category.FUNCTIONAL_REGRESSION) is None
    assert bundle_build(Category.INCONCLUSIVE) is None


def test_10_1_source_test_is_first_test_crashing_on_the_bundle_build():
    # exploit_primary is blocked on patch, so the patch bundle uses exploit_secondary.
    assert source_test(a_finding(Category.INCOMPLETE_FIX)) == "exploit_secondary"
    # A FIXED bundle is on base, where exploit_primary (first in order) crashes.
    assert source_test(a_finding(Category.FIXED)) == "exploit_primary"
    assert source_test(a_finding(Category.FUNCTIONAL_REGRESSION)) is None


# -- ddmin (§10.2) -----------------------------------------------------------

def test_10_2_ddmin_finds_the_trigger():
    out, calls, limit_hit = ddmin(b"xxAAAAyy", lambda b: b"AAAA" in b)
    assert out == b"AAAA"
    assert not limit_hit and calls > 0


def test_10_2_ddmin_result_is_1_minimal():
    pred = lambda b: b.count(b"A") >= 3 and b"Z" in b
    out, _, hit = ddmin(b"qAwAeArZt" * 3, pred)
    assert not hit and pred(out)
    for i in range(len(out)):
        assert not pred(out[:i] + out[i + 1:])


def test_10_2_ddmin_stops_at_the_run_budget():
    data = b"A" * 64 + b"BUG" + b"A" * 64
    out, calls, limit_hit = ddmin(data, lambda b: b"BUG" in b, max_runs=3)
    assert limit_hit and calls == 3
    assert b"BUG" in out  # the smallest accepted input so far


def test_10_2_ddmin_stops_at_the_time_budget():
    ticks = iter(range(1000))
    data = b"A" * 64 + b"BUG" + b"A" * 64
    _, calls, limit_hit = ddmin(data, lambda b: b"BUG" in b, max_seconds=5,
                                clock=lambda: next(ticks))
    assert limit_hit and calls <= 6


def test_10_2_default_budget_is_500_runs_or_120_seconds():
    from zaraban import reproducer
    assert reproducer.MAX_RUNS == 500 and reproducer.MAX_SECONDS == 120


def test_10_2_a_different_crash_is_not_accepted(tmp_path):
    # Shorter inputs crash too, but with another signature: they must be rejected.
    def run(data):
        if b"AAAA" in data and len(data) > 12:
            return crasher(b"AAAA")(data)
        if b"AAAA" in data:
            return RunOutcome(True, "SEGV @ other < main", signal="SIGSEGV")
        return RunOutcome(False, None, exit_code=1)  # non-zero exit is not a crash
    data = b"0123AAAA456789"
    bundle, _ = make(tmp_path, data, run)
    assert bundle.minimized_size > 12


# -- the bundle (§10.3) ------------------------------------------------------

def test_10_3_bundle_files(tmp_path):
    original = b"PREFIX____SET x=AAAAAAAAAAAAAAAA____SUFFIX"
    bundle, warnings = make(tmp_path, original, crasher(b"AAAA"))
    d = tmp_path / "reproducers" / "F-001"
    assert warnings == []
    assert bundle.path == "reproducers/F-001"
    assert (d / "input.orig.txt").read_bytes() == original
    assert (d / "input.min.txt").read_bytes() == b"AAAA"
    assert (d / "bin" / "prog").read_bytes() == b"\x7fELF fake binary"
    for name in ("metadata.json", "replays.json", "minimize.log", "reproduce.sh"):
        assert (d / name).is_file(), name
    assert os.access(d / "reproduce.sh", os.X_OK)


def test_10_3_metadata_has_everything_needed(tmp_path):
    original = b"junk AAAA junk"
    bundle, _ = make(tmp_path, original, crasher(b"AAAA"))
    m = json.loads((tmp_path / "reproducers/F-001/metadata.json").read_text())
    assert m["schema_version"] == 1
    assert m["finding"] == "F-001" and m["source_test"] == "exploit_primary"
    assert m["version"] == "patch" and m["build"] == "patch-sanitized"
    assert m["git_commit"] == "c76e9ca" and m["tree_sha256"] == "b" * 64
    assert m["diff_sha256"] == "d" * 64
    import hashlib
    assert m["binary_sha256"] == hashlib.sha256(b"\x7fELF fake binary").hexdigest()
    assert m["build_settings"] == {"cmd": "make sanitized",
                                   "env": {"PATH": "/usr/bin:/bin", "LANG": "C"},
                                   "compilers": {"gcc": "gcc 11", "clang": "clang 14"}}
    assert m["run_env"]["ASAN_OPTIONS"] == "abort_on_error=1"
    assert m["cmd"][1] == "input.txt" and m["bundle_cmd"] == ["bin/prog", "input.txt"]
    assert m["input_method"] == "file" and m["input_name"] == "input.txt"
    assert m["expected"] == {"signature": SIG, "error_type": "HEAP_BUFFER_OVERFLOW",
                             "detection": "ASAN"}
    assert m["sizes"] == {"original": len(original), "minimized": 4,
                          "minimize_runs": bundle.minimize_runs}


def test_10_3_absolute_input_path_is_made_relative(tmp_path):
    src = run_record(cmd=["/out/bin/prog", "-f", "/run/exploit_primary/input.txt"])
    make(tmp_path, b"xAAAAx", crasher(b"AAAA"), source=src)
    m = json.loads((tmp_path / "reproducers/F-001/metadata.json").read_text())
    assert m["bundle_cmd"] == ["bin/prog", "-f", "input.txt"]


def test_10_3_minimize_log_lists_each_step(tmp_path):
    bundle, _ = make(tmp_path, b"xxAAAAyy", crasher(b"AAAA"))
    lines = (tmp_path / "reproducers/F-001/minimize.log").read_text().splitlines()
    assert lines[0].split() == ["step", "size", "accepted"]
    assert "(original)" in lines[1]
    assert len(lines) == 2 + bundle.minimize_runs


def test_10_2_minimize_limit_warns(tmp_path):
    bundle, warnings = make(tmp_path, b"B" * 50 + b"AAAA" + b"B" * 50, crasher(b"AAAA"),
                            max_runs=2)
    assert bundle.minimize_limit_hit
    assert [w.code for w in warnings] == [WarningCode.MINIMIZE_LIMIT.value]


def test_10_2_no_signature_skips_minimization(tmp_path):
    src = run_record(signature=None, error_type=ErrorType.SEGV, detection=Detection.SIGNAL,
                     signal="SIGSEGV")

    def run(data):
        return RunOutcome(True, None, signal="SIGSEGV", error_type=ErrorType.SEGV,
                          detection=Detection.SIGNAL)
    bundle, _ = make(tmp_path, b"xx AAAA xx", run, source=src, finding=a_finding(Category.FIXED))
    d = tmp_path / "reproducers/F-001"
    assert bundle.minimized_size is None and bundle.minimize_runs == 0
    assert bundle.replayed_input == "orig"
    assert bundle.stable  # same error type and detection on every replay
    assert not (d / "input.min.txt").exists()
    assert "skipped" in (d / "minimize.log").read_text()


# -- replays (§10.4) ---------------------------------------------------------

def test_10_4_stable_minimized_input_is_replayed_three_times(tmp_path):
    bundle, _ = make(tmp_path, b"xxAAAAyy", crasher(b"AAAA"))
    assert bundle.replayed_input == "min" and bundle.stable
    assert [r.n for r in bundle.replays] == [1, 2, 3]
    assert all(r.reproduced for r in bundle.replays)
    r = json.loads((tmp_path / "reproducers/F-001/replays.json").read_text())
    assert r["input"] == "min" and r["stable"] is True and len(r["replays"]) == 3


def test_10_4_unstable_minimized_input_falls_back_to_the_original(tmp_path):
    original = b"xxAAAAyy"
    state = {"replaying": False, "n": 0}
    base = crasher(b"AAAA")

    def run(data):
        if data == b"AAAA" and state["replaying"]:
            state["n"] += 1
            if state["n"] % 2 == 0:  # the minimized input is flaky on replay
                return RunOutcome(False, None, exit_code=0)
        return base(data)

    # ddmin first, then mark that replays have started.
    import zaraban.reproducer as rp
    real_replay = rp._replay

    def replay(*a, **k):
        state["replaying"] = True
        return real_replay(*a, **k)
    rp._replay = replay
    try:
        bundle, _ = make(tmp_path, original, run)
    finally:
        rp._replay = real_replay
    assert bundle.stable and bundle.replayed_input == "orig"
    r = json.loads((tmp_path / "reproducers/F-001/replays.json").read_text())
    assert r["minimized_input_unstable"] is True
    assert [a["input"] for a in r["attempts"]] == ["min", "orig"]
    m = json.loads((tmp_path / "reproducers/F-001/metadata.json").read_text())
    assert m["replayed_input"] == "orig" and m["minimized_input_unstable"] is True


def test_10_4_unstable_bundle_makes_the_finding_inconclusive(tmp_path):
    calls = {"n": 0}

    def flaky(data):
        calls["n"] += 1
        return crasher(b"AAAA")(data) if calls["n"] % 2 else RunOutcome(False, None, exit_code=0)
    f = a_finding()
    bundle, _ = make(tmp_path, b"AAAA", flaky, finding=f)
    assert not bundle.stable
    assert (tmp_path / "reproducers/F-001").is_dir()  # kept
    apply_bundle(f, bundle)
    assert f.category is Category.INCONCLUSIVE
    assert f.reproducer == "reproducers/F-001/"
    assert "unstable" in f.notes


def test_10_4_stable_bundle_keeps_the_category(tmp_path):
    f = a_finding()
    bundle, _ = make(tmp_path, b"xAAAAx", crasher(b"AAAA"), finding=f)
    apply_bundle(f, bundle)
    assert f.category is Category.INCOMPLETE_FIX and f.reproducer == "reproducers/F-001/"


# -- the RunRecord adapter ---------------------------------------------------

def test_10_runoutcome_from_record():
    rec = run_record()
    rec.analysis.frames = [
        Frame(0, "__asan_memcpy", None, None, runtime=True),
        Frame(1, "boom", "src/main.c", 42, runtime=False),
        Frame(2, "parse", "src/main.c", 10, runtime=False),
        Frame(3, "main", "src/main.c", 3, runtime=False),
        Frame(4, "start", None, None, runtime=False),
    ]
    o = RunOutcome.from_record(rec)
    assert o.crashed and o.signature == SIG
    assert o.top_functions == ["boom", "parse", "main"]
    assert o.detection is Detection.ASAN and o.signal == "SIGABRT"


# -- reproduce.sh on a real AddressSanitizer binary (§10.5) ------------------

PROGRAM = r"""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
__attribute__((noinline)) static void boom(const char *s) {
    char *b = malloc(4); memcpy(b, s, 8); printf("%c\n", b[0]); free(b);
}
__attribute__((noinline)) static void parse(const char *s, size_t n) {
    const char *p = memmem(s, n, "BUG", 3); if (p) boom(p);
}
int main(int argc, char **argv) {
    static char buf[4096]; FILE *f = fopen(argv[1], "rb");
    if (!f) return 2;
    size_t n = fread(buf, 1, sizeof buf - 8, f); fclose(f);
    parse(buf, n); puts("ok"); return 0;
}
"""

_FRAME = re.compile(r"^\s*#\d+ 0x[0-9a-f]+ in (\S+)", re.M)


@pytest.fixture(scope="module")
def asan_binary(tmp_path_factory):
    if shutil.which("clang") is None:
        pytest.skip("clang is not installed")
    d = tmp_path_factory.mktemp("asan")
    (d / "prog.c").write_text(PROGRAM)
    subprocess.run(["clang", "-O0", "-g", "-fsanitize=address", "-o", str(d / "prog"),
                    str(d / "prog.c")], check=True)
    # On hosts with vm.mmap_rnd_bits=32, clang 14's ASan itself sometimes dies
    # with SIGSEGV before reporting (README, "Troubleshooting"). Replays there are
    # rightly unstable, so these tests can only run on a fixed host.
    (d / "input.txt").write_bytes(b"BUG")
    for _ in range(10):
        p = subprocess.run([str(d / "prog"), "input.txt"], cwd=d, capture_output=True,
                           env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0"})
        if b"ERROR: AddressSanitizer" not in p.stderr:
            pytest.skip("ASan is unreliable on this host (vm.mmap_rnd_bits=32, "
                        "see the README, Troubleshooting)")
    return d / "prog"


def real_run(binary: Path, env: dict):
    """A tiny stand-in for the runner and analysis (§5.3, §7.4)."""
    def run(data: bytes) -> RunOutcome:
        with tempfile.TemporaryDirectory() as cwd:
            Path(cwd, "input.txt").write_bytes(data)
            p = subprocess.run([str(binary), "input.txt"], cwd=cwd, env=env,
                               capture_output=True, timeout=20)
        err = p.stderr.decode(errors="replace")
        if "ERROR: AddressSanitizer: heap-buffer-overflow" not in err:
            return RunOutcome(False, None, exit_code=p.returncode)
        funcs = [f for f in _FRAME.findall(err)
                 if not f.startswith(("__asan", "__interceptor", "__sanitizer"))][:3]
        return RunOutcome(True, "HEAP_BUFFER_OVERFLOW @ " + " < ".join(funcs),
                          signal="SIGABRT", error_type=ErrorType.HEAP_BUFFER_OVERFLOW,
                          detection=Detection.ASAN, top_functions=funcs)
    return run


def _sh(bundle_dir: Path, *args):
    # Run from an unrelated directory: the script must only use paths relative to itself.
    return subprocess.run(["bash", str(bundle_dir / "reproduce.sh"), *args],
                          cwd="/", capture_output=True, text=True, timeout=60)


@pytest.fixture
def real_bundle(tmp_path, asan_binary):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=1:disable_coredump=1"}
    sym = shutil.which("llvm-symbolizer")
    if sym:
        env["ASAN_SYMBOLIZER_PATH"] = sym
    run = real_run(asan_binary, env)
    first = run(b"hello BUG there")
    assert first.crashed and first.top_functions[:2] == ["boom", "parse"]
    src = run_record(signature=first.signature, env=env,
                     cmd=[str(asan_binary), "input.txt"], cwd=str(tmp_path))
    bundle, _ = reproduce(finding=a_finding(), source=src, input_bytes=b"hello BUG there",
                          input_ext=".txt", build=build_record(tmp_path, binary=asan_binary),
                          run_dir=tmp_path, run=run, versions=versions())
    return bundle, tmp_path / bundle.path


def test_10_5_reproduce_sh_reproduces_the_minimized_input(real_bundle):
    bundle, d = real_bundle
    assert bundle.stable and bundle.replayed_input == "min"
    assert (d / "input.min.txt").read_bytes() == b"BUG"
    p = _sh(d)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "REPRODUCED" in p.stdout and "heap-buffer-overflow" in p.stderr


def test_10_5_reproduce_sh_orig_replays_the_original(real_bundle):
    _, d = real_bundle
    p = _sh(d, "orig")
    assert p.returncode == 0, p.stdout + p.stderr


def test_10_5_reproduce_sh_reports_not_reproduced(real_bundle):
    _, d = real_bundle
    (d / "input.min.txt").write_bytes(b"harmless")
    p = _sh(d)
    assert p.returncode == 1 and "NOT REPRODUCED" in p.stdout


def test_10_5_reproduce_sh_stops_on_binary_hash_mismatch(real_bundle):
    _, d = real_bundle
    with open(d / "bin" / "prog", "ab") as f:
        f.write(b"\0")
    p = _sh(d)
    assert p.returncode == 2 and "hash mismatch" in p.stderr
