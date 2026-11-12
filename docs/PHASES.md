# Zaraban implementation guide: phases, tasks and samples

This guide explains each phase of the plan in the README: what it is for,
which tasks it contains, who does each task, what the result must look like,
and a sample of each result. Section numbers such as §7.4 refer to
`docs/SPEC.md`. "PDF" means the course spec, `project1_spec.pdf`.

> **About the samples.** Code samples show the shape of a correct solution,
> and are meant to be adapted, not pasted blindly. Line numbers, addresses and
> PoC bytes in sample outputs are **illustrative**. Real values come from
> running the real targets in Phase 0.

Members:

| Member | Module |
|---|---|
| **A** | Orchestrator, builds, hardening, CI |
| **B** | Runner and crash analysis |
| **C** | Findings and patch linking |
| **D** | Reproducibility and reporting |

---

## Overview

| Phase | Purpose | Main result | Gate to move on |
|---|---|---|---|
| 0. Foundation | Agree on what to build and on the shared types; prove the targets work | `models.py`, Docker image, two reproduced CVEs, target proposal | Models merged, image builds, both PoCs crash under ASan |
| 1. Modules | Each member builds and unit-tests their module alone | Four tested modules | `pytest` green, one test per SPEC rule |
| 2. Integration | Connect the modules into one pipeline, prove it on `token_parser` | Working end-to-end tool | `token_parser` gives exits 0, 10, 20 with the right findings |
| 3. Real targets | Prepare cJSON and md4c with four versions, tests and oracles | Two complete target directories | `run_matrix.py` passes all six scenarios |
| 4. CI and defense | Automate, document, rehearse unseen patches | CI pipeline, docs, drill results | CI green, drill verdicts correct, fresh-clone run works |

Why this order: Phase 0 removes the two biggest risks early (shared types that
change late, and targets that do not reproduce). Phase 1 lets four people work
in parallel without waiting on each other. Phase 2 uses the small toy target,
so integration bugs are easy to see. Phase 3 only starts when the tool is
known to work.

---

## Phase 0: Foundation

**Goal:** everyone agrees on the SPEC and the data types, the Docker image has
every tool the pipeline needs, and both real targets are proven to crash under
ASan.

### Task 0.1: Approve the SPEC (all)

**What to do:** read `docs/SPEC.md` and `SPEC_REVIEW.md` together. Decide on
each review point and edit the SPEC.

**Sample decisions to record in SPEC.md:**

```markdown
§14.2 (new paragraph)
At least one target must be a real project, not a toy (PDF §4). Both delivered
targets are real: cJSON (CVE-2019-11835) and md4c (CVE-2021-30027).
`token_parser` is a development fixture and is not delivered.

§8.2 (new rule, "same bug")
Two crash groups whose error type and frame 0 (function and file) are equal
describe the same bug. They are merged into one finding; the worst case
decides the category. The finding notes that the call paths differ.

§9.4 (changed)
The execution trace uses an extra `-O0` build with clang source-based coverage
instead of gdb breakpoints.
```

**Done when:** the SPEC branch is merged into `main` with these decisions.

### Task 0.2: Shared data types in `zaraban/models.py` (all; A writes it)

**What to do:** write the types that pass between modules, with no logic.
Every later task imports from this file. Field names follow §12.3 so the JSON
report is a direct dump of these objects.

**Sample:**

```python
# zaraban/models.py
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Outcome(str, Enum):
    NORMAL = "NORMAL"
    CRASH = "CRASH"
    TIMEOUT = "TIMEOUT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"


class Detection(str, Enum):
    ASAN = "ASAN"
    UBSAN = "UBSAN"
    STACK_CANARY = "STACK_CANARY"
    FORTIFY = "FORTIFY"
    ALLOCATOR_CHECK = "ALLOCATOR_CHECK"
    SIGNAL = "SIGNAL"


class Category(str, Enum):
    FIXED = "FIXED"
    INCOMPLETE_FIX = "INCOMPLETE_FIX"
    NEW_ISSUE = "NEW_ISSUE"
    FUNCTIONAL_REGRESSION = "FUNCTIONAL_REGRESSION"
    INCONCLUSIVE = "INCONCLUSIVE"


BUILDS = ("base-release", "base-sanitized", "patch-release", "patch-sanitized")


@dataclass
class TestCase:
    name: str
    kind: str                      # valid | boundary | invalid | security | regression
    input_bytes: Optional[bytes]
    input_ext: str                 # ".txt", ".json", ...
    args: list[str] = field(default_factory=list)
    expected_exit_code: Optional[int] = None
    expected_output: Optional[str] = None
    output_match: str = "contains"
    expected_signature: Optional[str] = None   # regression tests only


@dataclass
class BuildRecord:
    build: str                     # one of BUILDS
    status: str                    # ok | failed
    cmd: str
    env: dict[str, str]
    exit_code: int
    duration_s: float
    log: str                       # path relative to the run dir
    binary_path: Optional[str]
    binary_sha256: Optional[str]
    sanitizers_verified: Optional[bool]


@dataclass
class Frame:
    index: int
    function: Optional[str]
    file: Optional[str]            # relative to the source root, e.g. src/main.c
    line: Optional[int]
    runtime: bool


@dataclass
class Analysis:
    outcome: Outcome
    detection: Optional[Detection]
    error_type: Optional[str]
    summary: Optional[str]
    frames: list[Frame]
    signature: Optional[str]


@dataclass
class RunRecord:
    test: str
    kind: str
    build: str
    repeat: int
    cmd: list[str]
    env: dict[str, str]
    exit_code: Optional[int]
    signal: Optional[str]
    timed_out: bool
    limit_hit: Optional[str]       # cpu | memory | None
    duration_s: float
    stdout_path: str
    stderr_path: str
    analysis: Analysis
    oracle_checked: bool
    oracle_passed: Optional[bool]
    oracle_reasons: list[str]


@dataclass
class CombinedResult:              # the repeats of one test on one build, §7.5
    test: str
    kind: str
    build: str
    first: RunRecord
    flaky: bool
    runs: list[RunRecord]


@dataclass
class Link:
    level: str                     # IN_CHANGED_HUNK ... UNDETERMINED
    side: Optional[str]            # base | patch
    file: Optional[str]
    function: Optional[str]
    line: Optional[int]
    frame: Optional[int]
    hunk: Optional[str]
    executed_changed_lines: Optional[list[int]]
    comparative_tests: list[str]
    explanation: str


@dataclass
class Finding:
    id: str                        # F-001
    category: Category
    signature: Optional[str]
    error_type: Optional[str]
    tests: list[dict]              # per test: kind, on_patch, results per build
    link: Optional[Link] = None
    reproducer: Optional[str] = None
    regression_test: Optional[str] = None
    notes: str = ""


@dataclass
class Condition:
    code: int
    name: str
    reason: str
    findings: list[str]
    tests: list[str]
```

**Done when:** merged, and every member has said in the PR that the types
they produce or consume are right.

### Task 0.3: Docker image and compose file (A)

**What to do:** add the tools the SPEC needs (§14.5): clang and llvm (for
sanitizers, `llvm-symbolizer` and coverage), `universal-ctags`, gdb, git. Run
as a non-root user. Set container limits and turn off networking.

**Sample `Dockerfile`:**

```dockerfile
FROM --platform=linux/amd64 ubuntu:22.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential clang llvm gdb binutils universal-ctags git cmake \
      python3 python3-pip ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt   # pyyaml pydantic unidiff pyelftools rich pytest

RUN useradd -m -u 1000 zaraban
USER zaraban
WORKDIR /workspace
```

**Sample `docker-compose.yml`:**

```yaml
services:
  zaraban:
    build: .
    platform: linux/amd64
    volumes:
      - .:/workspace
    working_dir: /workspace
    network_mode: none
    mem_limit: 2g
    cpus: 2
    pids_limit: 256
    # cap_add: [SYS_PTRACE]   # only if you keep the gdb-based trace
```

**Check:**

```bash
docker compose build
docker compose run --rm zaraban sh -c 'clang --version && llvm-symbolizer --version && ctags --version | head -1 && whoami'
# expected: versions printed, last line "zaraban"
```

**Done when:** the image builds and the check prints every tool and
`zaraban`.

### Task 0.4: Reproduce both CVEs under ASan (A+B: cJSON, C+D: md4c)

**What to do:** before writing any target files, prove the bug is real and
crashes under ASan in our image. Find the exact vulnerable version, the
upstream fix commit and the PoC input. The PoC usually comes from the CVE's
linked GitHub issue or from a test added in the fix commit.

**Sample steps for cJSON (inside the container):**

```bash
git clone https://github.com/DaveGamble/cJSON.git ./tmp/cjson && cd ./tmp/cjson
git checkout v1.7.10                      # last version before the fix
git log --oneline v1.7.10..v1.7.11        # find the fix commit for CVE-2019-11835

# a tiny driver that reads a file and calls the vulnerable function
cat > /tmp/drv.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"
int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "rb"); fseek(f, 0, SEEK_END); long n = ftell(f); rewind(f);
    char *buf = malloc(n + 1); fread(buf, 1, n, f); buf[n] = 0; fclose(f);
    cJSON_Minify(buf); puts(buf); free(buf); return 0;
}
EOF
clang -O1 -g -fsanitize=address,undefined -I. cJSON.c /tmp/drv.c -o /tmp/drv
/tmp/drv poc.json                          # poc.json from the issue or the fix commit's test
```

**What a successful reproduction looks like (illustrative):**

```
==4211==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000f3
WRITE of size 1 at 0x6020000000f3 thread T0
    #0 0x4c5e21 in cJSON_Minify /tmp/cjson/cJSON.c:2871:13
    #1 0x4c6a10 in main /tmp/drv.c:8:5
SUMMARY: AddressSanitizer: heap-buffer-overflow /tmp/cjson/cJSON.c:2871:13 in cJSON_Minify
```

Then check out the fix commit, rebuild, and confirm the same PoC no longer
crashes.

**Sample for md4c:** check out the last tag before the fix (0.4.7), build
`md2html` with the same clang flags, and run `./md2html < poc.md`.

**Write down for each target** (it goes into the proposal and `ORACLE.md`):

| Item | Example value to fill |
|---|---|
| Upstream repo | `https://github.com/DaveGamble/cJSON` |
| Vulnerable version | `v1.7.10`, commit `<hash>` |
| Fix commit | `<hash>`, "fix out-of-bounds write in cJSON_Minify" |
| PoC | `poc.json`, N bytes, source: issue #NNN |
| ASan result on base | `heap-buffer-overflow` in `cJSON_Minify` |
| Result on fix | no crash, output `...` |

**If a CVE does not reproduce** within a day, switch to the backup listed in
the README instead of fighting it.

**Done when:** both tables are filled and both PoCs crash on base and not on
the fix.

### Task 0.5: Send the target proposal to the instructor (all; one person sends)

The PDF requires targets, patches and oracles to be approved at the design
stage. Send a short proposal.

**Sample:**

```text
Group <n>: Zaraban, target proposal

Target 1: cJSON (DaveGamble/cJSON), real library
  Vulnerability: CVE-2019-11835, heap out-of-bounds write in cJSON_Minify
  Base: v1.7.10. Correct patch: upstream fix <hash> (v1.7.11).
  Incomplete patch: blocks the public PoC only; a second input still overflows.
  Regression patch: removes the overflow but wrongly rejects valid JSON
    containing "/*" inside a string.
  Oracle: cJSON's own test inputs and expected outputs, plus RFC 8259.

Target 2: md4c (mity/md4c), real library, official md2html CLI
  Vulnerability: CVE-2021-30027, heap out-of-bounds read in md_analyze_line
  Base: 0.4.7. Correct patch: upstream fix <hash> (0.4.8).
  Incomplete and regression patches: as above, designed by us.
  Oracle: CommonMark spec examples bundled with md4c (test/*.txt).
```

**Gate for Phase 0:** `models.py` merged, image builds, both PoCs reproduced,
proposal sent.

---

## Phase 1: Modules in isolation

**Goal:** each member builds their module and proves every SPEC rule with
unit tests. Modules talk only through the types in `models.py`, so nobody
waits for anyone else. Use **fixtures** (saved files, fake records) instead
of real pipeline output.

Folder layout:

```
zaraban/cli.py  config.py  sources.py  builder.py  hardening.py   (A)
zaraban/runner.py  analysis.py  oracle.py                         (B)
zaraban/diffinfo.py  findings.py  linking.py                      (C)
zaraban/minimize.py  bundle.py  regression.py  status.py  report.py   (D)
tests/fixtures/                                                   (shared)
```

### Member A: CLI, config, sources, builds, hardening

#### A1. CLI that never exits with 2 (§3.1, §3.3)

Python's `argparse` exits with code `2` on bad arguments. The SPEC requires
`30`.

```python
# zaraban/cli.py
import argparse, sys

class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"ARGUMENT_INVALID: {message}", file=sys.stderr)
        sys.exit(30)

def parse(argv=None):
    p = Parser(prog="zaraban")
    p.add_argument("-c", "--config", required=True)
    p.add_argument("--patch")
    p.add_argument("--base")
    p.add_argument("--out", default="out")
    p.add_argument("--no-promote", action="store_true")
    p.add_argument("--keep-work", action="store_true")
    p.add_argument("--check-config", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)
    if not a.check_config and not a.patch:
        p.error("--patch is required unless --check-config is given")
    return a
```

Test:

```python
def test_3_3_bad_argument_exits_30():
    with pytest.raises(SystemExit) as e:
        parse(["--config"])          # missing value
    assert e.value.code == 30
```

#### A2. Strict config validation (§4.5)

Use pydantic with `extra="forbid"`, so a typo such as `expected_exitcode` is
an error instead of being ignored. Collect all errors, not only the first.

```python
# zaraban/config.py
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing import Literal, Optional
import re

NAME = re.compile(r"^[A-Za-z0-9_-]+$")

class Test(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    description: Optional[str] = None
    input_file: Optional[str] = None
    input_data: Optional[str] = None
    args: list[str] = []
    expected_exit_code: Optional[int] = None
    expected_output: Optional[str] = None
    output_match: Literal["contains", "exact"] = "contains"

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        if not NAME.match(v):
            raise ValueError("only letters, digits, _ and - are allowed")
        return v

    @model_validator(mode="after")
    def _one_input(self):
        if self.input_file and self.input_data is not None:
            raise ValueError("a test has at most one of input_file and input_data")
        return self

class Build(BaseModel):
    model_config = ConfigDict(extra="forbid")
    binary_path: str
    release_cmd: str
    sanitized_cmd: str
    clean_cmd: Optional[str] = None

class Limits(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timeout_seconds: float = Field(3.0, gt=0)
    memory_limit_mb: int = Field(256, gt=0)

class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    base_dir: str = "."
    input_method: Literal["file", "stdin", "args"] = "stdin"
    file_arg_placeholder: str = "{input_file}"
    repeats: int = Field(3, ge=1)
    env: dict[str, str] = {}
    regression_dir: str = "tests/regression"
    build: Build
    limits: Limits = Limits()
    valid_tests: list[Test] = Field(min_length=1)
    boundary_tests: list[Test] = []
    invalid_tests: list[Test] = []
    security_tests: list[Test] = Field(min_length=1)
```

After pydantic, a second pass checks what pydantic cannot: duplicate test
names, files that do not exist, the removed keys `patch_dir` and `diff_file`.

Sample error output of `--check-config`:

```text
CONFIG_INVALID: 3 problems in targets/cjson/zaraban.yaml
  valid_tests[2].expected_exitcode: unknown key (did you mean expected_exit_code?)
  security_tests[0].input_file: tests/exploits/poc.json does not exist
  test name "valid-1" is used twice
exit 30
```

#### A3. Source preparation and strip level (§3.2)

When `--patch` is a diff file, copy the base tree and try strip levels 0 to 4.

```python
# zaraban/sources.py
import shutil, subprocess

def apply_diff(base_dir, diff_path, dest):
    shutil.copytree(base_dir, dest, ignore=shutil.ignore_patterns(".git", "out"))
    for p in range(5):
        check = subprocess.run(["git", "apply", "--check", f"-p{p}", diff_path],
                               cwd=dest, capture_output=True)
        if check.returncode == 0:
            subprocess.run(["git", "apply", f"-p{p}", diff_path], cwd=dest, check=True)
            return p                    # recorded in the report
    raise ToolError("PATCH_APPLY_FAILED", details={"diff": diff_path})
```

Test with two fixture diffs: one made by `git diff` (needs `-p1`), one made
with paths from the repo root (needs `-p3`).

#### A4. Four isolated builds and profile checks (§6)

```python
# zaraban/builder.py (core loop)
MIN_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "LANG": "C"}

def build_one(name, src_tree, cmd, cfg, work, out):
    tree = work / name
    shutil.copytree(src_tree, tree, ignore=shutil.ignore_patterns(".git", "out"))
    log = out / "builds" / name / "build.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.monotonic()
    with open(log, "wb") as fh:
        r = subprocess.run(["sh", "-c", cmd], cwd=tree, env=MIN_ENV,
                           stdout=fh, stderr=subprocess.STDOUT, timeout=300)
    binary = tree / cfg.build.binary_path
    if r.returncode != 0 or not binary.exists() or not is_x86_64_elf(binary):
        return BuildRecord(name, "failed", cmd, MIN_ENV, r.returncode,
                           time.monotonic() - t0, str(log), None, None, None)
    kept = out / "builds" / name / "bin" / binary.name
    kept.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, kept)
    ...  # sha256, then verify_profile(kept, sanitized=name.endswith("sanitized"))
```

Profile check by symbols (§6.3), using pyelftools:

```python
def symbols(path):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        names = set()
        for sec in (elf.get_section_by_name(".dynsym"), elf.get_section_by_name(".symtab")):
            if sec:
                names.update(s.name for s in sec.iter_symbols())
        return names

def verify_profile(path, sanitized):
    s = symbols(path)
    has_asan = "__asan_init" in s
    has_ubsan = any(n.startswith("__ubsan_handle_") for n in s)
    if sanitized and not (has_asan and has_ubsan):
        raise ToolError("SANITIZER_MISSING", details={"binary": str(path)})
    if not sanitized and has_asan:
        raise ToolError("PROFILE_MIXED", details={"binary": str(path)})
```

#### A5. Hardening checker (§11)

```python
# zaraban/hardening.py
from elftools.elf.elffile import ELFFile

PF_X, DF_BIND_NOW, DF_1_NOW = 0x1, 0x8, 0x1

def check(path):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        segs = {s["p_type"]: s for s in elf.iter_segments()}
        stack = segs.get("PT_GNU_STACK")
        nx = stack is not None and not (stack["p_flags"] & PF_X)
        pie = elf["e_type"] == "ET_DYN" and "PT_INTERP" in segs
        relro, bind = "none", None
        if "PT_GNU_RELRO" in segs:
            relro = "partial"
            dyn = elf.get_section_by_name(".dynamic")
            for t in (dyn.iter_tags() if dyn else []):
                tag, val = t.entry.d_tag, t.entry.d_val
                if tag == "DT_BIND_NOW" or (tag == "DT_FLAGS" and val & DF_BIND_NOW) \
                        or (tag == "DT_FLAGS_1" and val & DF_1_NOW):
                    relro, bind = "full", tag
    canary = "__stack_chk_fail" in symbols(path)
    return {
        "nx":     {"value": nx,     "evidence": f"PT_GNU_STACK {'present' if stack else 'missing'}"},
        "pie":    {"value": pie,    "evidence": f"e_type={elf['e_type']}, PT_INTERP={'PT_INTERP' in segs}"},
        "relro":  {"value": relro,  "evidence": f"PT_GNU_RELRO={'PT_GNU_RELRO' in segs}, bind={bind}"},
        "canary": {"value": canary, "evidence": "__stack_chk_fail in symbol table" if canary else "not found"},
    }
```

Test fixtures: build four tiny binaries once (`-z execstack`, `-no-pie`,
`-z norelro`, `-fno-stack-protector`) and assert each check flips.

Sample comparison in the report:

```json
"changes": [
  {"protection": "relro", "from": "full", "to": "partial", "kind": "downgrade"}
]
```

with the warning `HARDENING_DOWNGRADE` and no change to the exit code.

**Done for A when:** CLI, config, sources, builder and hardening each have
tests for every rule in §3, §4.5, §6 and §11.

---

### Member B: runner, analysis, oracle

#### B1. Running one test (§5.3, §7.2, §7.3)

```python
# zaraban/runner.py
import os, resource, signal, subprocess, time

def _limits(cpu_s, data_bytes):
    def apply():
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if data_bytes:                                   # release builds only
            resource.setrlimit(resource.RLIMIT_DATA, (data_bytes, data_bytes))
    return apply

def run_once(binary, test, cfg, sanitized, run_dir):
    run_dir.mkdir(parents=True)
    cmd, stdin_bytes = [str(binary)] + list(test.args), b""
    if cfg.input_method == "file":
        name = "input" + test.input_ext
        (run_dir / name).write_bytes(test.input_bytes or b"")
        ph = cfg.file_arg_placeholder
        if any(ph in a for a in cmd[1:]):
            cmd = [cmd[0]] + [a.replace(ph, name) for a in cmd[1:]]
        else:
            cmd.append(name)
    elif cfg.input_method == "stdin":
        stdin_bytes = test.input_bytes or b""
    elif test.input_bytes is not None:                   # args
        if b"\0" in test.input_bytes:
            raise ToolError("CONFIG_INVALID", details={"test": test.name, "reason": "NUL in args input"})
        cmd.append(test.input_bytes.decode())

    env = run_env(cfg, sanitized)                        # PATH + cfg.env + sanitizer options
    cpu = int(cfg.limits.timeout_seconds + 0.999) + 1
    data = None if sanitized else cfg.limits.memory_limit_mb * 1024 * 1024
    t0 = time.monotonic()
    p = subprocess.Popen(cmd, cwd=run_dir, env=env, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         start_new_session=True, preexec_fn=_limits(cpu, data))
    timed_out = False
    try:
        out, err = p.communicate(stdin_bytes, timeout=cfg.limits.timeout_seconds)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, err = p.communicate()
        timed_out = True
    rc = p.returncode
    sig = signal.Signals(-rc).name if rc < 0 else None
    return out[:1 << 20], err[:1 << 20], (None if rc < 0 else rc), sig, timed_out, time.monotonic() - t0
```

#### B2. Deciding the outcome and error type (§7.4)

Apply the rules in order. The first match wins.

```python
# zaraban/analysis.py
import re

ASAN = re.compile(r"ERROR: AddressSanitizer: ([\w-]+)")
FRAME = re.compile(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)(?:\s+(\S+?):(\d+)(?::\d+)?)?", re.M)
RUNTIME_PREFIX = ("__asan_", "__interceptor_", "__sanitizer_", "__ubsan_")

ASAN_TYPES = {
    "stack-buffer-overflow": "STACK_BUFFER_OVERFLOW",
    "dynamic-stack-buffer-overflow": "STACK_BUFFER_OVERFLOW",
    "heap-buffer-overflow": "HEAP_BUFFER_OVERFLOW",
    "global-buffer-overflow": "GLOBAL_BUFFER_OVERFLOW",
    "heap-use-after-free": "USE_AFTER_FREE",
    "stack-use-after-scope": "USE_AFTER_SCOPE",
    "stack-use-after-return": "USE_AFTER_SCOPE",
    "stack-overflow": "STACK_EXHAUSTION",
}

def outcome(stderr, sig, timed_out, limit_hit):
    if timed_out:
        return "TIMEOUT", None
    if sig == "SIGXCPU" or limit_hit:
        return "RESOURCE_LIMIT", None
    if "ERROR: AddressSanitizer" in stderr:
        return "CRASH", "ASAN"
    if "runtime error:" in stderr and sig:
        return "CRASH", "UBSAN"
    if "*** stack smashing detected ***" in stderr:
        return "CRASH", "STACK_CANARY"
    if "*** buffer overflow detected ***" in stderr:
        return "CRASH", "FORTIFY"
    if any(s in stderr for s in ("double free detected", "free(): invalid pointer", "malloc(): corrupted")):
        return "CRASH", "ALLOCATOR_CHECK"
    if sig in ("SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL", "SIGABRT", "SIGTRAP"):
        return "CRASH", "SIGNAL"
    return "NORMAL", None            # any exit code, including non-zero

def frames(stderr, source_root):
    out = []
    for m in FRAME.finditer(stderr):
        idx, fn, file, line = int(m[1]), m[2], m[3], m[4]
        runtime = fn.startswith(RUNTIME_PREFIX) or (file or "").find("libasan") >= 0 \
                  or (file or "").find("libc") >= 0
        if file and file.startswith(source_root):
            file = file[len(source_root):].lstrip("/")    # /…/work/patch-sanitized/src/main.c -> src/main.c
        out.append(Frame(idx, fn, file, int(line) if line else None, runtime))
    return out

def signature(error_type, frames):
    names = [f.function for f in frames if not f.runtime and f.function][:3]
    return f"{error_type} @ {' < '.join(names)}" if names else None
```

Note: in a sanitizer report, the first stack is the crash. ASan prints more
stacks after it (where memory was allocated or freed). Parse frames only up to
the first blank line after `#0`, or the "allocated by" frames will leak into
the signature.

**Sample unit test with a saved stderr fixture:**

```python
ASAN_STDERR = """\
==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd5c3e1a40
WRITE of size 121 at 0x7ffd5c3e1a40 thread T0
    #0 0x49a1b2 in __interceptor_strcpy (/w/bin+0x49a1b2)
    #1 0x4f8a1b in handle_set_command /w/src/main.c:37:5
    #2 0x4f8c10 in process_input /w/src/main.c:60:9
    #3 0x4f8e00 in main /w/src/main.c:80:5

"""

def test_7_4_asan_stack_overflow():
    kind, det = outcome(ASAN_STDERR, "SIGABRT", False, None)
    assert (kind, det) == ("CRASH", "ASAN")
    fr = frames(ASAN_STDERR, "/w")
    assert signature("STACK_BUFFER_OVERFLOW", fr) == \
        "STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main"

def test_7_4_nonzero_exit_is_not_a_crash():
    assert outcome("error: bad command\n", None, False, None) == ("NORMAL", None)
```

Collect real fixtures for every row of the error-type table: write five tiny C
programs (overflow, UAF, double free, null deref, divide by zero), run them in
the container, and save their stderr under `tests/fixtures/stderr/`.

#### B3. Oracle matching (§5.4)

```python
# zaraban/oracle.py
def match(test, outcome, exit_code, stdout: bytes):
    reasons = []
    if outcome != "NORMAL":
        reasons.append(f"ended with {outcome}")
    if test.expected_exit_code is not None and exit_code != test.expected_exit_code:
        reasons.append(f"exit code {exit_code}, expected {test.expected_exit_code}")
    if test.expected_output is not None:
        want = test.expected_output.encode()
        ok = (stdout == want) if test.output_match == "exact" else (want in stdout)
        if not ok:
            reasons.append(f"output does not {test.output_match}-match")
    checked = test.expected_exit_code is not None or test.expected_output is not None
    return checked, not reasons, reasons
```

#### B4. Repeats and flakiness (§7.5)

```python
def combine(runs):
    key = lambda r: (r.analysis.outcome, r.analysis.signature, r.oracle_passed)
    flaky = len({key(r) for r in runs}) > 1
    return CombinedResult(runs[0].test, runs[0].kind, runs[0].build, runs[0], flaky, runs)
```

Test: three fake runs, one with a different signature, gives `flaky=True`.

**Done for B when:** every row of the outcome table and the error-type table
has a fixture test, and the runner passes tests for timeout, CPU limit, each
input method and the placeholder.

---

### Member C: diff info, findings, linking

#### C1. Reading the diff (§9.2)

```python
# zaraban/diffinfo.py
from unidiff import PatchSet

def hunks(diff_text):
    out = []
    for pf in PatchSet(diff_text):
        for h in pf:
            out.append({
                "file": pf.path,                       # prefix a/ b/ already stripped
                "header": f"@@ -{h.source_start},{h.source_length} +{h.target_start},{h.target_length} @@",
                "base": (h.source_start, h.source_start + h.source_length - 1),
                "patch": (h.target_start, h.target_start + h.target_length - 1),
                "removed": [l.source_line_no for l in h if l.is_removed],
                "added": [l.target_line_no for l in h if l.is_added],
            })
    return out
```

#### C2. Changed functions with ctags (§9.2)

```bash
ctags --output-format=json --fields=+ne --kinds-C=f -o - src/cJSON.c
# {"_type": "tag", "name": "cJSON_Minify", "path": "src/cJSON.c", "line": 2840, "end": 2905, "kind": "function"}
```

```python
def functions(tree, rel_path):
    r = subprocess.run(["ctags", "--output-format=json", "--fields=+ne", "--kinds-C=f",
                        "-o", "-", rel_path], cwd=tree, capture_output=True, text=True, check=True)
    tags = [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
    return [(t["name"], t["line"], t.get("end", t["line"])) for t in tags if t.get("_type") == "tag"]

def changed_functions(tree, hunk_list, side):
    changed = set()
    for h in hunk_list:
        lines = h["removed"] if side == "base" else h["added"]
        for name, start, end in functions(tree, h["file"]):
            if any(start <= ln <= end for ln in lines):
                changed.add((h["file"], name))
    return changed
```

#### C3. Crash findings with the same-bug rule (§8.2)

```python
def crash_findings(results, tests):
    """results[test][build] -> CombinedResult. Only stable sanitized crashes."""
    def sig(t, build):
        r = results[t][build]
        a = r.first.analysis
        return a.signature if (not r.flaky and a.outcome == "CRASH") else None

    groups = {}                                   # signature -> (B, P), in first-seen order
    for t in tests:
        for build, side in (("base-sanitized", 0), ("patch-sanitized", 1)):
            s = sig(t, build)
            if s:
                groups.setdefault(s, ([], []))[side].append(t)

    # same-bug rule: merge groups with the same error type and frame 0
    merged = {}
    for s, (B, P) in groups.items():
        key = same_bug_key(s, results, B + P)     # (error_type, frame0_function, frame0_file)
        mB, mP, sigs = merged.setdefault(key, ([], [], []))
        mB += B; mP += P; sigs.append(s)

    findings = []
    for (etype, _, _), (B, P, sigs) in merged.items():
        cat = "FIXED" if B and not P else "INCOMPLETE_FIX" if B and P else "NEW_ISSUE"
        note = "call paths differ: " + " | ".join(sigs) if len(sigs) > 1 else ""
        findings.append(new_finding(cat, sigs[0], etype, sorted(set(B + P)), note))
    return findings
```

Sample unit test for the incomplete patch:

```python
def test_8_2_incomplete_fix():
    r = fake_results({
        "exploit_primary":   {"base-sanitized": crash(SIG), "patch-sanitized": normal(exit=1)},
        "exploit_secondary": {"base-sanitized": crash(SIG), "patch-sanitized": crash(SIG)},
    })
    [f] = crash_findings(r, ["exploit_primary", "exploit_secondary"])
    assert f.category == "INCOMPLETE_FIX"
```

#### C4. Functional findings (§8.4)

```python
def functional_findings(results, tests):
    out = []
    for t in tests:
        if t.kind not in ("valid", "boundary", "invalid"):
            continue
        base_ok = all(oracle_ok(results[t.name][b]) for b in ("base-release", "base-sanitized"))
        patch_ok = all(oracle_ok(results[t.name][b]) for b in ("patch-release", "patch-sanitized"))
        if not base_ok:
            out.append(new_finding("INCONCLUSIVE", None, None, [t.name],
                                   "test fails its oracle on base, so it cannot judge the patch"))
        elif not patch_ok:
            out.append(new_finding("FUNCTIONAL_REGRESSION", None, None, [t.name], ""))
    return out
```

(`oracle_ok` is false for crashes too, but crashes on patch are already a
`NEW_ISSUE` from C3, so skip a test here if it crashed.)

#### C5. Location evidence (§9.3)

```python
def link_level(frames, hunk_list, changed_fns, side):
    for f in frames:
        if f.runtime or not f.file:
            continue
        for h in hunk_list:
            lo, hi = h[side]
            if f.file == h["file"] and f.line and lo <= f.line <= hi:
                return "IN_CHANGED_HUNK", f, h
    if frames and (frames[0].file, frames[0].function) in changed_fns:
        return "IN_CHANGED_FUNCTION", frames[0], None
    for f in frames[1:]:
        if (f.file, f.function) in changed_fns:
            return "CHANGED_FUNCTION_IN_STACK", f, None
    return "UNDETERMINED", None, None
```

(A finer version checks `IN_CHANGED_FUNCTION` on every non-runtime frame
before falling to callers. Follow §9.3 exactly in the real code.)

Sample explanation built only from facts:

```text
Frame #1 handle_set_command (src/main.c:37) of the crash on patch lies inside
hunk @@ -21,14 +21,19 @@. The patch blocks exploit_primary but
exploit_secondary still reaches the same error.
```

**Done for C when:** each row of the tables in §8.2, §8.3, §8.4 and §9.3 has a
unit test built from fake results.

---

### Member D: minimize, bundles, regression tests, status, report

#### D1. Delta debugging (§10.2)

```python
# zaraban/minimize.py
class Budget(Exception):
    pass

def ddmin(data: bytes, crashes, max_runs=500, max_s=120):
    """crashes(candidate) -> True if it gives the same signature."""
    start, runs, best = time.monotonic(), 0, data

    def test(c):
        nonlocal runs
        if runs >= max_runs or time.monotonic() - start > max_s:
            raise Budget()
        runs += 1
        return crashes(c)

    n = 2
    try:
        while len(best) >= 2:
            n = min(n, len(best))
            size = max(1, len(best) // n)
            chunks = [best[i:i + size] for i in range(0, len(best), size)]
            for i in range(len(chunks)):
                cand = b"".join(chunks[:i] + chunks[i + 1:])
                if cand and test(cand):
                    best, n = cand, max(n - 1, 2)
                    break
            else:
                if n >= len(best):
                    break
                n = min(n * 2, len(best))
        return best, runs, False
    except Budget:
        return best, runs, True        # True -> warning MINIMIZE_LIMIT
```

Sample `minimize.log`:

```text
step  size  accepted
1     94    -        (original)
2     47    no
3     47    no
4     71    yes
5     53    no
...
41    69    final (1-minimal)
```

Test: a fake `crashes` that returns true when the input contains `b"AAAA"`;
`ddmin(b"xxAAAAyy", ...)` must return `b"AAAA"`.

#### D2. Reproducer bundle and `reproduce.sh` (§10.3 to §10.5)

Sample `metadata.json`:

```json
{
  "schema_version": 1,
  "finding": "F-001",
  "source_test": "exploit_secondary",
  "version": "patch",
  "build": "patch-sanitized",
  "git_commit": "c76e9ca",
  "tree_sha256": "…",
  "diff_sha256": "…",
  "binary_sha256": "…",
  "build_settings": {"cmd": "make sanitized", "env": {"PATH": "…", "HOME": "/tmp", "LANG": "C"},
                     "compilers": {"clang": "Ubuntu clang version 14.0.0"}},
  "run_env": {"PATH": "…", "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:…"},
  "cmd": ["./bin/token_parser", "input.txt"],
  "input_method": "file",
  "input_name": "input.txt",
  "expected": {"signature": "STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main",
               "error_type": "STACK_BUFFER_OVERFLOW", "detection": "ASAN"},
  "sizes": {"original": 94, "minimized": 69, "minimize_runs": 41}
}
```

Sample `reproduce.sh` (generated, values filled in by the tool):

```bash
#!/usr/bin/env bash
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WANT_SHA="<binary sha256>"
GOT_SHA="$(sha256sum "$HERE/bin/token_parser" | cut -d' ' -f1)"
[ "$GOT_SHA" = "$WANT_SHA" ] || { echo "binary hash mismatch"; exit 2; }

WHICH="${1:-min}"                       # ./reproduce.sh orig  replays the original input
TMP="$(mktemp -d)"
cp "$HERE/input.$WHICH.txt" "$TMP/input.txt"
cd "$TMP"
env -i PATH=/usr/bin:/bin \
  ASAN_OPTIONS='abort_on_error=1:detect_leaks=0:symbolize=1:disable_coredump=1' \
  "$HERE/bin/token_parser" input.txt > stdout.txt 2> stderr.txt
cat stdout.txt stderr.txt
if grep -q 'AddressSanitizer: stack-buffer-overflow' stderr.txt && grep -q 'handle_set_command' stderr.txt; then
  echo "REPRODUCED"; exit 0
fi
echo "NOT REPRODUCED"; exit 1
```

Sample `replays.json`:

```json
{"input": "min", "stable": true, "replays": [
  {"n": 1, "reproduced": true, "signal": "SIGABRT", "error_type": "STACK_BUFFER_OVERFLOW", "duration_s": 0.021},
  {"n": 2, "reproduced": true, "signal": "SIGABRT", "error_type": "STACK_BUFFER_OVERFLOW", "duration_s": 0.019},
  {"n": 3, "reproduced": true, "signal": "SIGABRT", "error_type": "STACK_BUFFER_OVERFLOW", "duration_s": 0.020}
]}
```

#### D3. Regression tests (§10.6)

Sample generated file `tests/regression/reg-exploit_secondary-3f2a91c0.yaml`:

```yaml
name: reg-exploit_secondary-3f2a91c0
input_file: reg-exploit_secondary-3f2a91c0.txt
expect_base_crash: true
signature: "STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main"
created_by: {tool_version: "0.2.0", run_id: "20261111-183002-3f2a91c0",
             finding: "F-001", source_test: "exploit_secondary"}
created_on: {base_version: "c76e9ca", base_binary_sha256: "…"}
```

Before adding: run it once on `base-sanitized` and check the signature (or
"no crash" for a `NEW_ISSUE`). Skip it if the same SHA-256 is already in the
directory.

#### D4. Status and exit code (§13)

```python
# zaraban/status.py
PRIORITY = (30, 10, 20, 40, 0)

def conditions(findings, errors, base_reproduced):
    c = []
    if errors:
        c.append(Condition(30, "BUILD_OR_CONFIG_ERROR", errors[0]["code"], [], []))
    for cat, code, name in (("INCOMPLETE_FIX", 10, "VULN_REMAINS"),
                            ("NEW_ISSUE", 10, "NEW_ISSUE"),
                            ("FUNCTIONAL_REGRESSION", 20, "FUNC_REGRESSION"),
                            ("INCONCLUSIVE", 40, "INCONCLUSIVE")):
        fs = [f for f in findings if f.category == cat]
        if fs:
            c.append(Condition(code, name, f"{len(fs)} {cat} finding(s)",
                               [f.id for f in fs], sorted({t["test"] for f in fs for t in f.tests})))
    if not base_reproduced:
        c.append(Condition(40, "INCONCLUSIVE", "a security test did not crash on base", [], []))
    if not c:
        fixed = any(f.category == "FIXED" for f in findings)
        c.append(Condition(0, "PASS", "all checks passed", [], []) if fixed
                 else Condition(40, "INCONCLUSIVE", "no fixed finding", [], []))
    return c

def exit_code(conds):
    codes = {x.code for x in conds}
    return next(p for p in PRIORITY if p in codes)
```

Tests: one per priority pair, for example 10 and 20 together give 10; 20 and
40 together give 20; no conditions and no FIXED gives 40.

#### D5. `summary.txt` and `report.json` (§12)

`report.json` is the dataclasses dumped in the order of §12.4. `summary.txt`
follows the layout in §12.5. Test both against a small fake run, and
validate `report.json` against a JSON Schema file so the format cannot drift.

**Done for D when:** ddmin, bundle, regression, status and report each have
tests, and `reproduce.sh` works on a bundle made from a fixture binary.

**Gate for Phase 1:** `pytest -q` passes with tests for every rule in each
member's SPEC sections.

---

## Phase 2: Integration on `token_parser`

**Goal:** connect the four modules into one command and prove it on the toy
target, where every expected result is known in advance (§8.9).

### Task 2.1: Pipeline wiring (A)

```python
# zaraban/pipeline.py
def run(args):
    cfg, warnings = load_config(args.config)                         # A
    out = new_run_dir(args.out, cfg.name)
    base, patch, diff, strip = prepare_sources(cfg, args)            # A
    builds = build_all(cfg, base, patch, out)                        # A
    if any(b.status != "ok" for b in builds.values()):
        return finish(out, errors=[build_error(builds)])             # exit 30
    hardening = compare_hardening(builds)                            # A
    tests = all_tests(cfg)                                           # A: config + regression_dir
    results = run_matrix(tests, builds, cfg, out)                    # B
    findings = build_findings(results, tests)                        # C
    link_all(findings, results, diff, base, patch)                   # C
    make_bundles(findings, results, builds, cfg, out, args.no_promote)   # D
    check_completeness(results, findings)                            # B
    return finish(out, cfg, builds, hardening, results, findings, warnings)  # D: report + exit
```

Each step's output is written to the run directory as it finishes, so a crash
of the tool still leaves a partial report (§13.4).

### Task 2.2: Execution trace with coverage (C)

For findings with no stack evidence, and for every `FUNCTIONAL_REGRESSION`,
build an extra trace binary of the relevant version and record which changed
lines ran.

```bash
clang -O0 -g -fprofile-instr-generate -fcoverage-mapping src/*.c -o trace_bin
LLVM_PROFILE_FILE=run.profraw ./trace_bin input.txt
llvm-profdata merge -sparse run.profraw -o run.profdata
llvm-cov export ./trace_bin -instr-profile=run.profdata -format=lcov > run.lcov
# lines look like:  SF:/…/src/main.c   DA:24,1   DA:25,0
```

Keep only `DA:<line>,<count>` lines of changed files where the line is a
changed line on that side and `count > 0`. Sample result in the link:

```json
"executed_changed_lines": [24, 25, 27],
"explanation": "valid_set ran the added key-length check at src/main.c:24-27 and returned through its error branch."
```

### Task 2.3: Regression tests in later runs (D)

Load every `.yaml` in `regression_dir` as a test of kind `regression`. Run a
scenario twice: the second run must show the regression test in
`execution_logs` and must not add it again (`already_present`).

### Task 2.4: Completeness check (B)

```python
def check_completeness(results, findings):
    referenced = {(t["test"]) for f in findings for t in f.tests}
    for test, per_build in results.items():
        abnormal = any(r.flaky or r.first.analysis.outcome != "NORMAL"
                       or r.first.oracle_passed is False for r in per_build.values())
        if abnormal and test not in referenced and not expected_abnormal(test, per_build):
            raise ToolError("TOOL_INTERNAL", details={"unreferenced": test})
```

(`expected_abnormal` covers a security test that crashes on base as it
should, which is not a finding on its own when the patch fixes it, because it
is listed in the FIXED finding anyway.)

### Task 2.5: `scenarios.yaml` and `run_matrix.py` for `token_parser` (A)

```yaml
# targets/target1_sample/scenarios.yaml
- name: correct
  patch: patches/correct.patch
  version_dir: versions/patch_correct
  expect_exit: 0
  expect_findings:
    - {category: FIXED, tests: [exploit_primary, exploit_secondary]}
- name: incomplete
  patch: patches/incomplete.patch
  version_dir: versions/patch_incomplete
  expect_exit: 10
  expect_findings:
    - {category: INCOMPLETE_FIX, tests: [exploit_primary, exploit_secondary]}
- name: regression
  patch: patches/regression.patch
  version_dir: versions/patch_regression
  expect_exit: 20
  expect_findings:
    - {category: FIXED, tests: [exploit_primary, exploit_secondary]}
    - {category: FUNCTIONAL_REGRESSION, tests: [valid_set]}
```

Sample `run_matrix.py` output:

```text
target1_sample/correct      exit 0  (expected 0)   findings ok   PASS
target1_sample/incomplete   exit 10 (expected 10)  findings ok   PASS
target1_sample/regression   exit 20 (expected 20)  findings ok   PASS
3/3 scenarios matched
```

**Gate for Phase 2:** the three lines above, and the summary for
`incomplete` looks like the sample in SPEC §12.5.

---

## Phase 3: Real targets

**Goal:** make cJSON (A+B) and md4c (C+D) complete targets with four versions,
tests, oracles and scenarios. The two pairs work in parallel.

### Task 3.1: Target directory and Makefile

```
targets/cjson/
  zaraban.yaml  ORACLE.md  scenarios.yaml  Makefile
  src/cJSON.c  src/cJSON.h  driver/main.c
  patches/correct.patch  patches/incomplete.patch  patches/regression.patch
  versions/patch_correct/  versions/patch_incomplete/  versions/patch_regression/
  tests/valid/  tests/boundary/  tests/invalid/  tests/exploits/  tests/regression/
```

**Sample `Makefile`:** release and sanitized flags live here, not in the
config, so a patch that weakens the release flags is caught by the hardening
check (§4.3).

```make
SRC = src/cJSON.c driver/main.c
BIN = cjson_driver

release:
	gcc -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie \
	    -Wl,-z,relro,-z,now -Isrc -o $(BIN) $(SRC)

sanitized:
	clang -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
	    -Isrc -o $(BIN) $(SRC)

.PHONY: release sanitized
```

For md4c, the same idea with its sources, for example
`src/md4c.c src/md4c-html.c src/entity.c md2html/md2html.c md2html/cmdline.c`,
and `BIN = md2html`. Check the exact file list in the version you pick.

### Task 3.2: The driver (cJSON only)

cJSON is a library, so it needs a small `main`. Keep it trivial and give it
a documented contract, because it is part of the oracle.

```c
/* driver/main.c
 * usage: cjson_driver minify|parse FILE
 * minify: prints cJSON_Minify(FILE), exit 0
 * parse:  prints the unformatted JSON, exit 0; prints "parse error" to stderr, exit 1
 * wrong usage or unreadable file: exit 2
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

static char *read_all(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); rewind(f);
    char *b = malloc((size_t)n + 1);
    if (b && fread(b, 1, (size_t)n, f) == (size_t)n) b[n] = '\0'; else { free(b); b = NULL; }
    fclose(f);
    return b;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s minify|parse FILE\n", argv[0]); return 2; }
    char *buf = read_all(argv[2]);
    if (!buf) { fprintf(stderr, "cannot read %s\n", argv[2]); return 2; }
    int rc = 0;
    if (strcmp(argv[1], "minify") == 0) {
        cJSON_Minify(buf);
        puts(buf);
    } else if (strcmp(argv[1], "parse") == 0) {
        cJSON *j = cJSON_Parse(buf);
        if (!j) { fprintf(stderr, "parse error\n"); rc = 1; }
        else { char *s = cJSON_PrintUnformatted(j); puts(s); free(s); cJSON_Delete(j); }
    } else { fprintf(stderr, "unknown mode\n"); rc = 2; }
    free(buf);
    return rc;
}
```

### Task 3.3: The four versions

| Version | How to make it | Sample idea for cJSON |
|---|---|---|
| Base | Upstream source at the vulnerable tag | `v1.7.10` |
| Correct | Base plus the upstream fix commit, nothing else | the CVE-2019-11835 fix from 1.7.11 |
| Incomplete | Blocks only the public PoC's exact pattern | Reject input that ends with the PoC's exact last bytes. A second input with the same structure but a different tail still overflows; put it in `tests/exploits/exploit_bypass.json` |
| Regression | Removes the overflow, but too broadly | Stop minifying at the first `/*`, even inside a string. The valid test `{"pattern":"/*"}` then comes out truncated and fails its oracle |

Make each patch with git, so the diff and the directory always agree:

```bash
git diff --no-index src versions/patch_incomplete/src > patches/incomplete.patch
```

Check every version by hand before writing scenarios:

```bash
docker compose run --rm zaraban python -m zaraban.cli -c targets/cjson/zaraban.yaml \
  --patch targets/cjson/patches/incomplete.patch
# expected: exit 10, one INCOMPLETE_FIX finding listing exploit_primary (blocked) and exploit_bypass (reaches)
```

### Task 3.4: Tests and oracle

**Sample `zaraban.yaml` (shortened):**

```yaml
name: cjson
input_method: file
build:
  binary_path: cjson_driver
  release_cmd: make release
  sanitized_cmd: make sanitized
limits: {timeout_seconds: 2.0, memory_limit_mb: 256}

valid_tests:
  - name: minify_spaces
    args: ["minify", "{input_file}"]
    input_file: tests/valid/spaces.json
    expected_exit_code: 0
    expected_output: |
      {"a":1,"b":[true,false,null]}
    output_match: exact
  - name: minify_line_comment
    args: ["minify", "{input_file}"]
    input_file: tests/valid/line_comment.json
    expected_exit_code: 0
  - name: string_with_comment_marks
    args: ["minify", "{input_file}"]
    input_data: '{"pattern":"/*"}'
    expected_exit_code: 0
    expected_output: '{"pattern":"/*"}'

boundary_tests:
  - name: empty_file
    args: ["minify", "{input_file}"]
    input_data: ""
    expected_exit_code: 0

invalid_tests:
  - name: parse_truncated
    args: ["parse", "{input_file}"]
    input_data: '{"a":'
    expected_exit_code: 1

security_tests:
  - name: exploit_primary
    args: ["minify", "{input_file}"]
    input_file: tests/exploits/poc.json
    description: "Public PoC for CVE-2019-11835"
  - name: exploit_bypass
    args: ["minify", "{input_file}"]
    input_file: tests/exploits/exploit_bypass.json
    description: "Same bug, different tail; passes the incomplete patch"
```

**Sample `ORACLE.md` rows:**

| Test | Expected behavior | Source |
|---|---|---|
| `minify_spaces` | Whitespace removed, prints `{"a":1,"b":[true,false,null]}`, exit 0 | cJSON README, "cJSON_Minify" |
| `string_with_comment_marks` | Text inside strings is kept as-is | RFC 8259 §7 (strings); cJSON README |
| `parse_truncated` | Prints `parse error`, exit 1 | `driver/main.c` usage contract |
| `exploit_primary` | On the fixed version: no crash, exit 0 | Upstream fix commit and its test |

For md4c, the best oracle is the CommonMark spec examples that ship with md4c
(`test/spec.txt`): each example has the Markdown input and the exact HTML
output. Pick 10 to 20 of them as valid tests with `output_match: exact`.

**How many tests:** about 10 to 20 valid, 10 boundary and 10 invalid per
target. Put boundary tests around every threshold the patches touch.

### Task 3.5: Scenarios and saved results

Write `scenarios.yaml` like the one in Task 2.5, then:

```bash
docker compose run --rm zaraban python scripts/run_matrix.py --save
```

**Gate for Phase 3:** all six real scenarios match (three per target), and
`results/` holds their reports, summaries and bundles.

---

## Phase 4: CI, docs and the defense drill

**Goal:** the pipeline runs on every push, the repository can be run by a
stranger, and the team has rehearsed unseen patches.

### Task 4.1: CI workflow (A)

```yaml
# .github/workflows/zaraban.yml
name: zaraban
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t zaraban .
      - name: Unit tests
        run: docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace" -w /workspace zaraban pytest -q
      - name: Scenario matrix
        run: docker run --rm --user "$(id -u):$(id -g)" --network none -v "$PWD:/workspace" -w /workspace zaraban python scripts/run_matrix.py
      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: zaraban-out
          path: out/
```

`--user` makes the container write files as the CI runner's user, so the
bind-mounted `out/` is writable. Any step that exits non-zero fails the job,
so the tool's exit codes decide the pipeline result.

### Task 4.2: Documentation (everyone)

Each member writes one page in `docs/` about their module:

```markdown
# Runner and crash analysis (Member B)

## What it does
## Design decisions and why
## Rules it implements (with SPEC section numbers)
## Known limitations
## How to change it (e.g. add a new error type)
```

The last section is your preparation for the live change at the defense.

### Task 4.3: Unseen-patch drill (all)

Each pair writes **two surprise patches** for the other pair's target and
hands over only the `.patch` file, with a neutral name like `p1.patch`.

```bash
docker compose run --rm zaraban python -m zaraban.cli -c targets/md4c/zaraban.yaml --patch /tmp/p1.patch
```

Record the result:

| Patch | Author's intended verdict | Tool's verdict | Correct? | Fix needed |
|---|---|---|---|---|
| `p1.patch` | Incomplete (blocks only short lines) | 10, INCOMPLETE_FIX | yes | none |
| `p2.patch` | Regression (breaks tables) | 0, PASS | **no** | add a table valid test |

A wrong verdict usually means a missing test, not a tool bug. Add the test,
note it in `ORACLE.md`, and rerun.

Also rehearse the "sibling program" case from the PDF: write a `zaraban.yaml`
for a program you have not used before (copy `targets/_template/`) and time
how long it takes to get a first run.

### Task 4.4: Optional variant step (B or C, if time allows)

A bounded mutation of each security input on `patch-sanitized`, with a fixed
seed, behind a config flag:

```yaml
variants: {enabled: true, budget_runs: 300, budget_seconds: 30, seed: 1}
```

Mutations: lengths around known buffer sizes, single byte flips, repeating
the input. Any crash goes through the normal finding rules.

**Gate for Phase 4:** CI is green on `main`, the drill table has no unfixed
wrong verdicts, and a teammate who did not write the README can clone the
repository and run the matrix by following it.

---

## Defense preparation (each member)

| Defense part | Points | How to prepare |
|---|---|---|
| Architecture and your code | 3 | Explain the pipeline in two minutes, then your module's design using your `docs/` page |
| Analyse a finding | 3 | Take `results/cjson/incomplete/report.json`, explain each piece of evidence and how it led to exit 10 |
| Small live change | 4 | Practise the "How to change it" items in your docs page, for example add an error type (B), change `repeats` (A), add a boundary test (pairs), change the minimization budget (D) |

You need at least 5 of 10, and at least 1 point in each part.
