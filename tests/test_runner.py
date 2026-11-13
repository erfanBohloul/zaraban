"""Unit tests for the runner (SPEC §5.3, §7.1–§7.3, §7.5, §12.1, §12.3).

Every test runs a real program: small C programs compiled once per module,
and the real token_parser target loaded through its zaraban.yaml.
"""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from zaraban.config import Target
from zaraban.models import (
    BuildName,
    Detection,
    ErrorCode,
    ErrorType,
    InputMethod,
    LimitKind,
    Outcome,
    TestCase,
    TestKind,
    WarningCode,
    ZarabanError,
)
from zaraban.runner import RunSettings, combine, output_warnings, run_once, run_test

REPO = Path(__file__).resolve().parents[1]
TARGET = REPO / "targets" / "target1_sample"
REL, SAN = BuildName.PATCH_RELEASE, BuildName.PATCH_SANITIZED

PROGRAMS = {
    # prints argv[1..] (one per line), then stdin as hex, then the cwd entries
    "probe": r"""
#include <dirent.h>
#include <stdio.h>
#include <string.h>
extern char **environ;
int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        printf("arg:");
        for (unsigned char *p = (unsigned char *)argv[i]; *p; p++) printf("%02x", *p);
        printf("\n");
    }
    int c; printf("stdin:");
    while ((c = getchar()) != EOF) printf("%02x", c);
    printf("\n");
    DIR *d = opendir("."); struct dirent *e;
    while ((e = readdir(d))) if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
        printf("cwd:%s\n", e->d_name);
    for (char **v = environ; *v; v++) printf("env:%s\n", *v);
    return 0;
}""",
    "sleeper": r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (fork() == 0) { sleep(2); FILE *f = fopen(argv[1], "w"); if (f) fclose(f); return 0; }
    sleep(10); return 0;
}""",
    "spinner": r"""
#include <pthread.h>
#include <signal.h>
#include <string.h>
void *spin(void *a) { for (;;); return a; }
int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "ignore")) signal(SIGXCPU, SIG_IGN);
    pthread_t t[8]; for (int i = 0; i < 8; i++) pthread_create(&t[i], 0, spin, 0);
    for (;;);
}""",
    "hog": r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = malloc(512u << 20);
    if (!p) { puts("allocation failed"); return 2; }
    memset(p, 1, 512u << 20); puts("allocated"); return 0;
}""",
    "chatty": r"""
#include <stdio.h>
int main(void) { for (int i = 0; i < 300000; i++) fputs("0123456789\n", stdout); return 0; }""",
    "heap_overflow": r"""
#include <stdlib.h>
__attribute__((noinline)) void bug(char *p, int n) { p[n] = 'A'; }
int main(int argc, char **argv) { char *p = malloc(8); bug(p, argc + 7); free(p); return 0; }""",
}


@pytest.fixture(scope="module")
def bins(tmp_path_factory):
    if shutil.which("gcc") is None or shutil.which("clang") is None:
        pytest.skip("gcc/clang not installed")
    d = tmp_path_factory.mktemp("bins")
    out = {}
    for name, src in PROGRAMS.items():
        (d / f"{name}.c").write_text(src)
        out[name] = d / name
        subprocess.run(["gcc", "-O0", "-pthread", "-o", str(out[name]), str(d / f"{name}.c")],
                       check=True)
    out["heap_overflow_asan"] = d / "heap_overflow_asan"
    subprocess.run(["clang", "-g", "-O0", "-fsanitize=address", "-o",
                    str(out["heap_overflow_asan"]), str(d / "heap_overflow.c")], check=True)
    out["hog_asan"] = d / "hog_asan"
    subprocess.run(["clang", "-g", "-O0", "-fsanitize=address", "-o", str(out["hog_asan"]),
                    str(d / "hog.c")], check=True)
    return out


def case(name="t", data=b"", ext=".txt", args=(), **kw) -> TestCase:
    return TestCase(name=name, kind=TestKind.VALID, input_bytes=data, input_ext=ext,
                    args=list(args), **kw)


def lines(rec, out_dir, prefix):
    text = (Path(out_dir) / rec.stdout.path).read_text()
    return [ln[len(prefix):] for ln in text.splitlines() if ln.startswith(prefix)]


# -- settings come from the real config (§4, §7.2) ---------------------------

def test_7_2_settings_from_a_loaded_config(tmp_path):
    cfg = tmp_path / "zaraban.yaml"
    cfg.write_text("""name: probe
input_method: args
file_arg_placeholder: "@@"
env: {LANG: C, MY_VAR: from_config, ASAN_OPTIONS: "verbosity=0"}
limits: {timeout_seconds: 0.5, memory_limit_mb: 64}
build: {binary_path: p, release_cmd: make, sanitized_cmd: make s}
valid_tests: [{name: v, input_data: x}]
security_tests: [{name: s, input_data: y}]
""")
    target, _ = Target.load(cfg)
    s = RunSettings.from_target(target)
    assert s.input_method is InputMethod.ARGS and s.file_arg_placeholder == "@@"
    assert (s.timeout_seconds, s.memory_limit_mb, s.cpu_seconds) == (0.5, 64, 2)
    rel = s.env_for(False)
    assert rel == {"PATH": s.path, "LANG": "C", "MY_VAR": "from_config",
                   "ASAN_OPTIONS": "verbosity=0"}
    san = s.env_for(True)
    # The config's sanitizer options come first, so the tool's win (§7.2).
    assert san["ASAN_OPTIONS"].startswith("verbosity=0:abort_on_error=1:")
    assert san["ASAN_OPTIONS"].endswith("max_allocation_size_mb=64")
    assert san["UBSAN_OPTIONS"] == ("halt_on_error=1:abort_on_error=1:print_stacktrace=1:"
                                    "symbolize=1")


def test_7_3_cpu_limit_is_timeout_rounded_up_plus_one():
    assert RunSettings(timeout_seconds=2.0).cpu_seconds == 3
    assert RunSettings(timeout_seconds=2.5).cpu_seconds == 4


def test_7_2_missing_symbolizer_warns():
    s = RunSettings(symbolizer=None)
    assert [w.code for w in s.warnings()] == [WarningCode.NO_SYMBOLIZER.value]
    assert "ASAN_SYMBOLIZER_PATH" not in s.env_for(True)
    assert RunSettings(symbolizer="/usr/bin/llvm-symbolizer").warnings() == []


def test_7_2_program_gets_only_path_config_env_and_sanitizer_options(bins, tmp_path):
    os.environ["ZARABAN_HOST_ONLY"] = "leak"
    try:
        s = RunSettings(env={"MY_VAR": "1"})
        rec = run_once(bins["probe"], case(), s, SAN, 1, tmp_path)
    finally:
        del os.environ["ZARABAN_HOST_ONLY"]
    names = {e.split("=", 1)[0] for e in lines(rec, tmp_path, "env:")}
    assert names == set(rec.env) == {"PATH", "MY_VAR", "ASAN_OPTIONS", "UBSAN_OPTIONS",
                                     "ASAN_SYMBOLIZER_PATH"} - (
        set() if s.symbolizer else {"ASAN_SYMBOLIZER_PATH"})


# -- input methods (§5.3) ----------------------------------------------------

def test_5_3_stdin_gets_the_bytes_and_end_of_file(bins, tmp_path):
    data = b"line1\nline2"  # no trailing newline is added
    rec = run_once(bins["probe"], case(data=data), RunSettings(), REL, 1, tmp_path)
    assert lines(rec, tmp_path, "stdin:") == [data.hex()]
    assert rec.input.method is InputMethod.STDIN and rec.input.name is None
    assert lines(rec, tmp_path, "cwd:") == []  # empty working directory (§7.2)


def test_5_3_file_replaces_the_placeholder(bins, tmp_path):
    s = RunSettings(input_method=InputMethod.FILE)
    rec = run_once(bins["probe"], case(data=b"{}", ext=".json", args=["-f", "{input_file}"]),
                   s, REL, 1, tmp_path)
    assert lines(rec, tmp_path, "arg:") == [b"-f".hex(), b"input.json".hex()]
    assert lines(rec, tmp_path, "cwd:") == ["input.json"]
    assert rec.cmd[1:] == ["-f", "input.json"] and rec.input.name == "input.json"
    assert lines(rec, tmp_path, "stdin:") == [""]


def test_5_3_file_is_the_last_argument_without_placeholder(bins, tmp_path):
    s = RunSettings(input_method=InputMethod.FILE)
    rec = run_once(bins["probe"], case(args=["-v"]), s, REL, 1, tmp_path)
    assert lines(rec, tmp_path, "arg:") == [b"-v".hex(), b"input.txt".hex()]


def test_5_3_args_input_is_passed_byte_for_byte(bins, tmp_path):
    s = RunSettings(input_method=InputMethod.ARGS)
    data = b"A\xff\x01B"
    rec = run_once(bins["probe"], case(data=data, args=["-x"]), s, REL, 1, tmp_path)
    assert lines(rec, tmp_path, "arg:") == [b"-x".hex(), data.hex()]
    json.loads((tmp_path / "runs/t/patch-release/1.json").read_text())  # still valid JSON


def test_5_3_args_input_with_nul_is_a_config_error(bins, tmp_path):
    s = RunSettings(input_method=InputMethod.ARGS)
    with pytest.raises(ZarabanError) as e:
        run_once(bins["probe"], case(data=b"a\0b"), s, REL, 1, tmp_path)
    assert e.value.code is ErrorCode.CONFIG_INVALID


# -- files and records (§7.2, §12.1, §12.3) ----------------------------------

def test_12_1_each_repeat_has_its_own_files_and_a_fresh_directory(bins, tmp_path):
    s = RunSettings(input_method=InputMethod.FILE)
    result = run_test(bins["probe"], case(name="valid_x"), s, REL, 3, tmp_path)
    d = tmp_path / "runs" / "valid_x" / "patch-release"
    assert sorted(p.name for p in d.iterdir()) == [
        "1.json", "1.stderr", "1.stdout", "2.json", "2.stderr", "2.stdout",
        "3.json", "3.stderr", "3.stdout"]
    for rec in result.runs:
        assert lines(rec, tmp_path, "cwd:") == ["input.txt"]  # nothing left from earlier runs
        assert not Path(rec.cwd).exists()  # deleted after the run
    assert [r.repeat for r in result.runs] == [1, 2, 3] and not result.flaky


def test_12_3_run_record_fields(bins, tmp_path):
    rec = run_once(bins["probe"], case(name="v", data=b"hi"), RunSettings(), REL, 2, tmp_path)
    data = json.loads((tmp_path / "runs/v/patch-release/2.json").read_text())
    assert list(data)[0] == "schema_version"
    for key in ("test", "kind", "build", "repeat", "cmd", "env", "cwd", "input", "exit_code",
                "signal", "timed_out", "limit_hit", "duration_s", "stdout", "stderr",
                "analysis", "oracle"):
        assert key in data, key
    assert data["build"] == "patch-release" and data["repeat"] == 2
    assert data["input"]["size"] == 2 and len(data["input"]["sha256"]) == 64
    assert data["stdout"]["path"] == "runs/v/patch-release/2.stdout"
    assert (data["exit_code"], data["signal"]) == (0, None)
    assert data["cmd"][0] == str(bins["probe"].resolve())
    assert rec.stdout.bytes == (tmp_path / rec.stdout.path).stat().st_size


# -- limits (§7.3) -----------------------------------------------------------

def test_7_3_timeout_kills_the_whole_process_group(bins, tmp_path):
    marker = tmp_path / "child-survived"
    s = RunSettings(timeout_seconds=0.5)
    rec = run_once(bins["sleeper"], case(args=[str(marker)]), s, REL, 1, tmp_path)
    assert rec.timed_out and rec.analysis.outcome is Outcome.TIMEOUT
    assert rec.duration_s < 2
    time.sleep(2.5)
    assert not marker.exists()


@pytest.mark.skipif((os.cpu_count() or 1) < 2, reason="needs two CPUs to beat the wall clock")
@pytest.mark.parametrize("mode", ["", "ignore"])
def test_7_3_cpu_limit_is_resource_limit_cpu(bins, tmp_path, mode):
    # Eight busy threads use CPU time faster than the wall clock runs, so the
    # CPU limit (3 s) is hit before the timeout (2 s). "ignore" ignores SIGXCPU,
    # so the hard limit's SIGKILL ends it.
    s = RunSettings(timeout_seconds=2.0)
    rec = run_once(bins["spinner"], case(args=[mode] if mode else []), s, REL, 1, tmp_path)
    assert not rec.timed_out
    assert rec.signal == ("SIGKILL" if mode else "SIGXCPU")
    assert rec.limit_hit is LimitKind.CPU
    assert rec.analysis.outcome is Outcome.RESOURCE_LIMIT


def test_7_3_release_memory_limit_makes_allocations_fail(bins, tmp_path):
    s = RunSettings(memory_limit_mb=64)
    rec = run_once(bins["hog"], case(expected_exit_code=0), s, REL, 1, tmp_path)
    assert (tmp_path / rec.stdout.path).read_text() == "allocation failed\n"
    assert rec.analysis.outcome is Outcome.NORMAL and rec.limit_hit is None
    assert rec.oracle.passed is False  # judged by the normal rules


def test_7_3_sanitized_memory_limit_is_resource_limit_memory(bins, tmp_path):
    s = RunSettings(memory_limit_mb=64)
    rec = run_once(bins["hog_asan"], case(), s, SAN, 1, tmp_path)
    assert rec.limit_hit is LimitKind.MEMORY
    assert rec.analysis.outcome is Outcome.RESOURCE_LIMIT


def test_7_3_output_is_cut_at_1_mb_with_a_warning(bins, tmp_path):
    rec = run_once(bins["chatty"], case(), RunSettings(), REL, 1, tmp_path)
    assert rec.exit_code == 0
    assert rec.stdout.bytes == 1 << 20 and rec.stdout.truncated
    assert (tmp_path / rec.stdout.path).stat().st_size == 1 << 20
    assert not rec.stderr.truncated
    assert [w.code for w in output_warnings([rec])] == [WarningCode.OUTPUT_TRUNCATED.value]


# -- analysis and oracle on a real crash (§7.4, §5.4) -------------------------

def test_7_4_sanitized_crash_is_analysed(bins, tmp_path):
    rec = run_once(bins["heap_overflow_asan"], case(expected_exit_code=0), RunSettings(), SAN,
                   1, tmp_path, source_root=str(bins["heap_overflow_asan"].parent))
    a = rec.analysis
    assert (a.outcome, a.detection, a.error_type) == \
        (Outcome.CRASH, Detection.ASAN, ErrorType.HEAP_BUFFER_OVERFLOW)
    assert a.signature == "HEAP_BUFFER_OVERFLOW @ bug < main"
    assert a.frames[0].file == "heap_overflow.c"
    assert rec.signal == "SIGABRT" and rec.exit_code is None
    assert rec.oracle.passed is False and rec.oracle.reasons[0] == "ended with CRASH"


# -- combining repeats (§7.5) ------------------------------------------------

def test_7_5_differing_repeats_are_flaky(bins, tmp_path):
    result = run_test(bins["probe"], case(), RunSettings(), REL, 3, tmp_path)
    assert not result.flaky
    runs = result.runs
    runs[1].analysis.signature = "SEGV @ other"
    assert combine(runs).flaky
    runs[1].analysis.signature = runs[0].analysis.signature
    runs[2].oracle.passed = not runs[0].oracle.passed
    assert combine(runs).flaky


def test_7_5_combine_needs_runs():
    with pytest.raises(ValueError):
        combine([])


# -- the real token_parser target --------------------------------------------

@pytest.fixture(scope="module")
def token_parser(tmp_path_factory):
    if shutil.which("clang") is None or shutil.which("make") is None:
        pytest.skip("clang/make not installed")
    src = tmp_path_factory.mktemp("tp") / "src"
    shutil.copytree(TARGET, src)
    subprocess.run(["make", "-s", "sanitized"], cwd=src, check=True)
    target, _ = Target.load(src / "zaraban.yaml")
    return target, src


def test_target_token_parser_exploit_and_valid_test(token_parser, tmp_path):
    target, src = token_parser
    s = RunSettings.from_target(target)
    tests = {t.name: t for t in target.all_tests()}
    binary = src / target.spec.build.binary_path

    rec = run_once(binary, tests["exploit_primary"], s, BuildName.BASE_SANITIZED, 1, tmp_path,
                   source_root=str(src))
    a = rec.analysis
    assert (a.outcome, a.detection, a.error_type) == \
        (Outcome.CRASH, Detection.ASAN, ErrorType.STACK_BUFFER_OVERFLOW)
    assert a.signature.startswith("STACK_BUFFER_OVERFLOW @ handle_set_command")
    assert rec.cmd[1:] == ["input.txt"]
    assert any(f.file == "src/main.c" for f in a.frames)

    rec = run_once(binary, tests["valid_ping"], s, BuildName.BASE_SANITIZED, 1, tmp_path)
    assert rec.analysis.outcome is Outcome.NORMAL and rec.exit_code == 0
    assert rec.oracle.checked and rec.oracle.passed
