#!/usr/bin/env bash
# Zaraban environment check: verifies, inside the container, every tool and
# behavior the pipeline relies on. Run it with:
#
#   docker compose run --rm zaraban bash scripts/verify_env.sh
#
# Exit code 0 = all checks passed. It writes only to a temporary directory.

set -u
PASS=0; FAIL=0; WARN=0
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
cd "$T"

ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; FAIL=$((FAIL+1)); }
warn() { printf '  \033[33mWARN\033[0m  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; WARN=$((WARN+1)); }
check(){ local name="$1"; shift; if out="$("$@" 2>&1)"; then ok "$name"; else bad "$name" "$(echo "$out" | tail -2)"; fi; }
section(){ printf '\n\033[1m%s\033[0m\n' "$1"; }

cat > ovf.c <<'EOF'
#include <stdio.h>
#include <string.h>
static void copy(const char *s) { char buf[16]; strcpy(buf, s); printf("%s\n", buf); }
int main(int argc, char **argv) { copy(argc > 1 ? argv[1] : "ok"); return 0; }
EOF
cat > uaf.c <<'EOF'
#include <stdlib.h>
int main(void) { int *p = malloc(4); free(p); return *p; }
EOF
cat > div.c <<'EOF'
int main(int argc, char **argv) { (void)argv; return 10 / (argc - 1); }
EOF
LONG=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

# ---------------------------------------------------------------------------
section "Container basics"
[ "$(id -u)" != "0" ] && ok "runs as non-root user ($(whoami))" || bad "runs as non-root user" "running as root"
[ "$(uname -m)" = "x86_64" ] && ok "architecture is x86_64" || bad "architecture is x86_64" "got $(uname -m)"
python3 -c 'import sys; assert sys.version_info >= (3, 10)' && ok "python >= 3.10 ($(python3 -V 2>&1))" || bad "python >= 3.10"
if python3 -c 'import socket; socket.create_connection(("1.1.1.1", 80), timeout=2)' 2>/dev/null; then
  warn "network is reachable" "expected none for the zaraban service (fine only in zaraban-online)"
else ok "no network access (isolated)"; fi
[ -w /workspace ] && ok "/workspace is writable" || bad "/workspace is writable" "rebuild with HOST_UID=\$(id -u) HOST_GID=\$(id -g) docker compose build"
[ "$(ulimit -c)" = "0" ] && ok "core dumps disabled" || warn "core dumps disabled" "ulimit -c is $(ulimit -c)"

section "Tools"
for t in gcc g++ clang make git cmake ctags llvm-symbolizer llvm-cov llvm-profdata gdb readelf checksec file; do
  command -v "$t" >/dev/null && ok "$t found" || bad "$t found"
done
ctags --version 2>/dev/null | grep -q "Universal Ctags" && ok "ctags is Universal Ctags" || bad "ctags is Universal Ctags"
check "python packages import (yaml pydantic elftools unidiff rich pytest)" \
  python3 -c 'import yaml, pydantic, elftools, unidiff, rich, pytest; assert pydantic.VERSION.startswith("2")'

# ---------------------------------------------------------------------------
section "Builds and hardening"
check "release build with hardening flags (gcc)" \
  gcc -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now ovf.c -o rel
check "sanitized build (clang ASan+UBSan)" \
  clang -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined ovf.c -o san
check "weak build for comparison (no canary, no PIE, no RELRO, exec stack)" \
  gcc -O0 -fno-stack-protector -no-pie -Wl,-z,norelro -z execstack ovf.c -o weak
check "pyelftools reads protections (NX/PIE/RELRO/canary differ as expected)" python3 - <<'EOF'
from elftools.elf.elffile import ELFFile
def info(p):
    with open(p, "rb") as f:
        e = ELFFile(f)
        seg = {s["p_type"]: s for s in e.iter_segments()}
        st = seg.get("PT_GNU_STACK")
        nx = st is not None and not (st["p_flags"] & 1)
        pie = e["e_type"] == "ET_DYN" and "PT_INTERP" in seg
        relro = "PT_GNU_RELRO" in seg
        syms = set()
        for n in (".dynsym", ".symtab"):
            s = e.get_section_by_name(n)
            if s: syms.update(x.name for x in s.iter_symbols())
        return nx, pie, relro, "__stack_chk_fail" in syms, "__asan_init" in syms
r, w, s = info("rel"), info("weak"), info("san")
assert r[:4] == (True, True, True, True), f"release: {r}"
assert w[:4] == (False, False, False, False), f"weak: {w}"
assert s[4] and not r[4], "ASan symbol check (profile verification) failed"
EOF
check "git apply with strip-level detection" bash -c '
  mkdir -p a/src b/src && echo "int x = 1;" > a/src/m.c && echo "int x = 2;" > b/src/m.c
  git diff --no-index a b > p.diff; cp -r a w && cd w
  for n in 0 1 2 3 4; do git apply --check -p$n ../p.diff 2>/dev/null && git apply -p$n ../p.diff && break; done
  grep -q "x = 2" src/m.c'

# ---------------------------------------------------------------------------
section "Running and crash detection"
out="$(./san "$LONG" 2>&1)"; rc=$?
echo "$out" | grep -q "ERROR: AddressSanitizer: stack-buffer-overflow" && ok "ASan reports stack-buffer-overflow" || bad "ASan reports stack-buffer-overflow" "$(echo "$out" | head -3)"
[ $rc -eq 134 ] && ok "ASan aborts with SIGABRT (abort_on_error=1)" || warn "ASan aborts with SIGABRT" "exit status $rc"
echo "$out" | grep -qE "#[0-9]+ 0x[0-9a-f]+ in copy .*ovf\.c:3" && ok "stack trace symbolized with file:line" || bad "stack trace symbolized with file:line" "check llvm-symbolizer"
out="$(./rel "$LONG" 2>&1)"; rc=$?
echo "$out" | grep -qE "buffer overflow detected|stack smashing detected" && [ $rc -eq 134 ] \
  && ok "release build stops the overflow (fortify/canary, SIGABRT)" || bad "release build stops the overflow" "exit $rc: $out"
clang -g -fsanitize=address uaf.c -o uaf 2>/dev/null && ./uaf 2>&1 | grep -q "heap-use-after-free" \
  && ok "ASan reports heap-use-after-free" || bad "ASan reports heap-use-after-free"
clang -g -fsanitize=undefined -fno-sanitize-recover=all div.c -o div 2>/dev/null && ./div 2>&1 | grep -q "division by zero" \
  && ok "UBSan reports division by zero" || bad "UBSan reports division by zero"
check "subprocess limits: timeout kills process group, RLIMIT_CPU gives SIGXCPU" python3 - <<'EOF'
import os, resource, signal, subprocess
p = subprocess.Popen(["sh", "-c", "sleep 30 & wait"], start_new_session=True)
try:
    p.wait(timeout=0.5); raise SystemExit("did not time out")
except subprocess.TimeoutExpired:
    os.killpg(p.pid, signal.SIGKILL); p.wait()
assert p.returncode == -signal.SIGKILL
def lim(): resource.setrlimit(resource.RLIMIT_CPU, (1, 1))
q = subprocess.run(["sh", "-c", "while :; do :; done"], preexec_fn=lim, timeout=10)
assert q.returncode in (-signal.SIGXCPU, -signal.SIGKILL), q.returncode
EOF

# ---------------------------------------------------------------------------
section "Diff parsing, changed functions, execution trace"
check "unidiff parses hunks" python3 - <<'EOF'
from unidiff import PatchSet
d = """--- a/src/m.c\n+++ b/src/m.c\n@@ -1,3 +1,4 @@\n int a;\n-int b;\n+int b2;\n+int c;\n int d;\n"""
h = PatchSet(d)[0][0]
assert (h.source_start, h.target_start, h.target_length) == (1, 1, 4)
assert [l.target_line_no for l in h if l.is_added] == [2, 3]
EOF
check "ctags gives function start and end lines" bash -c \
  'ctags --output-format=json --fields=+ne --kinds-C=f -o - ovf.c | grep -q "\"name\": \"copy\".*\"end\": 3"'
check "coverage trace (clang -O0 + llvm-profdata + llvm-cov lcov)" bash -c '
  clang -O0 -g -fprofile-instr-generate -fcoverage-mapping ovf.c -o cov &&
  LLVM_PROFILE_FILE=run.profraw ./cov hi >/dev/null &&
  llvm-profdata merge -sparse run.profraw -o run.profdata &&
  llvm-cov export ./cov -instr-profile=run.profdata -format=lcov | grep -q "^DA:3,1"'
gcc -O0 -g ovf.c -o dbg 2>/dev/null
if timeout 20 gdb -q -batch -ex "break copy" -ex run -ex bt --args ./dbg hi 2>&1 | grep -q "Breakpoint 1, copy"; then
  ok "gdb can trace a program (ptrace allowed)"
else warn "gdb can trace a program" "only needed if you use the gdb trace; check cap_add SYS_PTRACE"; fi

# ---------------------------------------------------------------------------
section "Minimization and bundles"
check "sha256sum and env -i available for reproduce.sh" bash -c 'sha256sum san >/dev/null && env -i PATH=/usr/bin:/bin ./rel hi >/dev/null'

# ---------------------------------------------------------------------------
section "Project files"
cd /workspace
for f in pyproject.toml Dockerfile docker-compose.yml .dockerignore zaraban/__init__.py zaraban/models.py; do
  [ -f "$f" ] && ok "$f present" || bad "$f present"
done
[ -f .env ] && { git check-ignore -q .env 2>/dev/null && ok ".env is git-ignored" || warn ".env is git-ignored" "add .env to .gitignore"; }
if [ -d tests ]; then
  out="$(python3 -m pytest -q -p no:cacheprovider tests 2>&1)" && ok "unit tests pass ($(echo "$out" | tail -1))" || bad "unit tests pass" "$(echo "$out" | tail -3)"
fi

# ---------------------------------------------------------------------------
printf '\n\033[1mResult: %d passed, %d failed, %d warnings\033[0m\n' "$PASS" "$FAIL" "$WARN"
[ "$FAIL" -eq 0 ]
