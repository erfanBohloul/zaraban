"""Record real standard-error fixtures for the analysis tests (SPEC §7.4).

Each program below triggers one row of the outcome and error-type tables. It
is compiled like a target build (sanitized: clang with ASan and UBSan; release:
gcc with stack protector and FORTIFY), run with the tool's run environment
(§7.2), and its standard error and termination are saved:

    <name>.stderr     standard error, byte for byte
    manifest.json     per fixture: build profile, signal, exit code

Run inside the project's Docker image, from the repository root:

    docker compose run --rm zaraban python3 tests/fixtures/stderr/generate.py

On hosts with vm.mmap_rnd_bits=32, ASan itself can crash; see the
README, "Troubleshooting".
"""

from __future__ import annotations

import json
import shutil
import signal
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))

from zaraban.runner import RunSettings  # noqa: E402

# Sources are compiled here, so frame paths are stable: /tmp/zaraban-fixtures/src/<name>.c
ROOT = Path("/tmp/zaraban-fixtures")

SANITIZED = ["clang", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g", "-O0"]
RELEASE = ["gcc", "-O2", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2"]

HEADER = """#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define NOINLINE __attribute__((noinline))
volatile int zero = 0, five = 5, big = 64, shift = 40, imax = INT_MAX;
"""

# name: (profile, body). Each body defines bug() called as main -> caller -> bug,
# so a signature has three application frames. Out-of-bounds writes go through a
# pointer: on a fixed-size array UBSan's bounds check would report them first.
PROGRAMS: dict[str, tuple[str, str]] = {
    "asan_stack_buffer_overflow": ("sanitized", """
NOINLINE void bug(void) { char buf[8]; char *p = buf; for (int i = 0; i < big; i++) p[i] = 'A'; puts(buf); }"""),
    "asan_heap_buffer_overflow": ("sanitized", """
NOINLINE void bug(void) { char *p = malloc(8); p[five + 3] = 'A'; free(p); }"""),
    "asan_global_buffer_overflow": ("sanitized", """
char g[8];
NOINLINE void bug(void) { char *p = g; p[five + 3] = 'A'; }"""),
    "asan_heap_use_after_free": ("sanitized", """
NOINLINE void bug(void) { char *p = malloc(8); free(p); p[0] = 'A'; }"""),
    "asan_stack_use_after_scope": ("sanitized", """
NOINLINE void bug(void) { volatile char *p; { char x[8]; p = x; } p[0] = 'A'; }"""),
    "asan_stack_overflow": ("sanitized", """
NOINLINE int recurse(int n) { volatile char pad[256]; pad[0] = (char)n; return recurse(n + 1) + pad[0]; }
NOINLINE void bug(void) { printf("%d\\n", recurse(0)); }"""),
    "asan_double_free": ("sanitized", """
NOINLINE void bug(void) { char *p = malloc(8); free(p); free(p); }"""),
    "asan_invalid_free": ("sanitized", """
NOINLINE void bug(void) { char x[8]; free(x + zero); }"""),
    "asan_null_deref": ("sanitized", """
NOINLINE void bug(void) { long *p = (long *)(8L + zero); printf("%ld\\n", *p); }"""),
    "asan_segv": ("sanitized", """
NOINLINE void bug(void) { int *p = (int *)(0xdead0000L + zero); *p = 1; }"""),
    "asan_allocation_too_big": ("sanitized", """
NOINLINE void bug(void) { char *p = malloc((size_t)big << 24); printf("%p\\n", (void *)p); }"""),
    "ubsan_div_zero": ("sanitized", """
NOINLINE void bug(void) { printf("%d\\n", five / zero); }"""),
    "ubsan_integer_overflow": ("sanitized", """
NOINLINE void bug(void) { printf("%d\\n", imax + five); }"""),
    "ubsan_index_out_of_bounds": ("sanitized", """
NOINLINE void bug(void) { int a[4] = {0}; printf("%d\\n", a[five]); }"""),
    "ubsan_null_pointer": ("sanitized", """
struct s { long a; long b; };
NOINLINE void bug(void) { struct s *p = (struct s *)(long)zero; printf("%ld\\n", p->b); }"""),
    "ubsan_shift": ("sanitized", """
NOINLINE void bug(void) { printf("%d\\n", 1 << shift); }"""),
    "canary_stack_smashing": ("release", """
NOINLINE void bug(void) { char buf[16]; for (int i = 0; i < big; i++) buf[i] = 'A'; puts(buf); }"""),
    "fortify_buffer_overflow": ("release", """
NOINLINE void bug(void) { char src[64]; memset(src, 'A', big - 1); src[big - 1] = 0;
                          char dst[8]; strcpy(dst, src); puts(dst); }"""),
    "glibc_double_free": ("release", """
NOINLINE void bug(void) { char *p = malloc(32); free(p); free(p + zero); }"""),
    "glibc_invalid_pointer": ("release", """
NOINLINE void bug(void) { char *p = malloc(32); free(p + 8 + zero); }"""),
    "glibc_heap_corruption": ("release", """
NOINLINE void bug(void) { char *volatile p = malloc(24);
                          for (int i = 0; i < 40 + zero; i++) p[i] = (char)0xff;
                          void *volatile q = malloc(100000); printf("%p\\n", q); }"""),
    "signal_segv": ("release", """
NOINLINE void bug(void) { int *p = (int *)(0xdead0000L + zero); *p = 1; }"""),
    "signal_fpe": ("release", """
NOINLINE void bug(void) { printf("%d\\n", five / zero); }"""),
    "signal_abort": ("release", """
NOINLINE void bug(void) { abort(); }"""),
    "normal_exit_3": ("release", """
NOINLINE void bug(void) { fputs("error: bad input\\n", stderr); exit(3); }"""),
}

MAIN = """
NOINLINE void caller(void) { bug(); }
int main(void) { caller(); return 0; }
"""


def main() -> int:
    for tool in ("gcc", "clang"):
        if shutil.which(tool) is None:
            print(f"{tool} not found; run this inside the project's Docker image")
            return 1
    shutil.rmtree(ROOT, ignore_errors=True)
    (ROOT / "src").mkdir(parents=True)
    settings = RunSettings(memory_limit_mb=256)
    manifest: dict[str, dict] = {}
    for name, (profile, body) in PROGRAMS.items():
        src = ROOT / "src" / f"{name}.c"
        src.write_text(HEADER + body + MAIN)
        exe = ROOT / name
        flags = SANITIZED if profile == "sanitized" else RELEASE
        subprocess.run([*flags, "-w", "-o", str(exe), str(src)], check=True, cwd=ROOT)
        p = subprocess.run([str(exe)], cwd=ROOT, env=settings.env_for(profile == "sanitized"),
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        (HERE / f"{name}.stderr").write_bytes(p.stderr)
        rc = p.returncode
        manifest[name] = {
            "profile": profile,
            "signal": signal.Signals(-rc).name if rc < 0 else None,
            "exit_code": rc if rc >= 0 else None,
        }
        print(f"{name:32} {profile:9} {manifest[name]['signal'] or rc}")
    (HERE / "manifest.json").write_text(json.dumps(
        {"source_root": str(ROOT), "fixtures": manifest}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
