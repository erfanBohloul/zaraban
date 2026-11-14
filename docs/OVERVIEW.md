# Zaraban: design overview

A short tour of how Zaraban works and why it is built this way. The
[README](../README.md) explains how to run it. [SPEC.md](SPEC.md) gives every
rule in full; the section numbers below (§7.4 and so on) point there.

## The question

A security patch can fail in two ways. It can be **incomplete**: it blocks
the known exploit, but a different input still reaches the bug. Or it can
cause a **regression**: the crash is gone, but valid inputs now behave
differently. Zaraban answers both questions for one patch of one C/C++
program by **running** the program before and after the patch, never by
reading the code alone:

1. Does the base version's vulnerability still occur on the patched version,
   within the tests we run?
2. Does the patched version still behave correctly on valid inputs?

The answer is an exit code a CI pipeline can act on, a readable summary, and
a JSON report with all the evidence.

## One run, end to end

```
zaraban.yaml + base tree + patch (diff or tree)
 │
 ├─ config.py        validate the config strictly; resolve every test input      §4
 ├─ sources.py       copy base, apply the diff (or diff the two trees)           §3.2
 ├─ builder.py       4 isolated builds: base/patch × release/sanitized           §6
 ├─ hardening.py     NX, PIE, RELRO, canary on both release binaries             §11
 ├─ runner.py        every test × every build × `repeats`, same env and limits   §7
 │   analysis.py     how each run ended, what detected it, which error, where    §7.4
 │   oracle.py       does the output match the expected behavior                 §5.4
 ├─ variants.py      optional: seeded mutations of the security inputs           §7.6
 ├─ findings.py      compare base and patch → FIXED / INCOMPLETE_FIX / …         §8
 ├─ linking.py       link each finding to the diff (stack, functions, trace)     §9
 │   diffinfo.py     hunks and changed functions;  coverage.py  execution trace
 ├─ reproducer.py    minimize, bundle, replay 3 times, reproduce.sh              §10
 ├─ regression.py    turn each stable bundle into a regression test              §10.6
 ├─ completeness.py  check that no abnormal result is missing from the report    §8.7
 ├─ status.py        decide the exit code                                        §13
 └─ report.py        summary.txt and report.json                                 §12
```

`pipeline.py` wires it: `exec_stage.py` runs the first half (builds,
hardening, execution, variants) and `analysis_stage.py` the second (findings
to report). The two halves exchange only `RunContext` (`pipeline_state.py`),
and every shared type lives in `models.py`. Whatever fails, a report is still
written: a tool error becomes `TOOL_INTERNAL` with exit 30 and `errors.log`.

## Key design decisions

**Isolation.** Everything runs in one Docker image (Ubuntu 22.04, gcc,
clang 14, llvm, ctags), as a non-root user, with no network and with memory,
CPU and process limits (§14.5). Each run of the target gets a clean
environment, an empty working directory, a timeout, a CPU limit and a memory
limit (§7.2, §7.3).

**Four builds, never mixed.** Each version is built twice from a fresh copy:
a **release** build, which is what users ship (optimized, hardened), and a
**sanitized** build with ASan and UBSan (§6). The tool checks that each
binary really is the profile it claims, for example that a sanitized binary
contains the sanitizer runtime. Results are reported per build, so you can
see both how the bug shows up in the real binary and what the sanitizer says
about it. Base and patch are always compared on the matching build.

**Build flags belong to the target.** The config calls the target's own
`make release`, so if a patch changes the Makefile and drops a protection,
the hardening check sees it and warns (§11). A warning never changes the
exit code, as the spec asks.

**Repeats and flakiness.** Each test runs 3 times on each build. If the
repeats disagree, the result is **flaky** and gets an `INCONCLUSIVE` finding
instead of a verdict (§7.5, §8.5). One lucky run never decides anything.

**Classifying a run.** Each run ends as `NORMAL`, `CRASH`, `TIMEOUT` or
`RESOURCE_LIMIT`; a timeout is never a crash (§7.4). For a crash the tool
records:
- the **detection mechanism**: ASan, UBSan, stack canary, FORTIFY, the
  allocator's own checks, or a plain signal;
- the **error type**: for example `HEAP_BUFFER_OVERFLOW`, `USE_AFTER_FREE`,
  `NULL_DEREF`, `DIV_BY_ZERO`, or `UNKNOWN`;
- the **stack trace** and a **signature**: the error type plus the top three
  functions of the program (runtime frames skipped).

**The same-bug rule.** Two crashes are the same bug when they have the same
error type, function and file (§8.2). For each bug, the tool looks at which
tests crash with it on base and on patch:

| Base | Patch | Finding |
|---|---|---|
| crashes | does not | `FIXED` |
| crashes | crashes | `INCOMPLETE_FIX` (the exit code says `VULN_REMAINS`) |
| does not | crashes | `NEW_ISSUE` |

A valid test that matches its oracle on base but not on patch is a
`FUNCTIONAL_REGRESSION` (§8.4). A test whose oracle already fails on base,
a flaky result, or a stop with no classification is `INCONCLUSIVE`: the
evidence cannot support a verdict. As the spec warns, a new crash alone does
not prove that the patch caused it, so the category only says what was
observed, and the link says how it relates to the patch.

**Linking a finding to the patch.** The crash's stack trace is checked
against the diff on the matching side (base for a fixed bug, patch for one
that remains), every frame, not only the top one (§9.3). The strongest match
wins:

| Level | Meaning |
|---|---|
| `IN_CHANGED_HUNK` | a frame is on a changed line range |
| `IN_CHANGED_FUNCTION` | a frame is in a function the patch changed |
| `CHANGED_FUNCTION_IN_STACK` | a changed function called the crashing code (a check in the caller) |
| `CHANGED_CODE_EXECUTED` | no frame matches, but a coverage trace shows the input ran changed lines |
| `UNDETERMINED` | none of these; being in the same file is not enough |

The finding also carries **comparative evidence**: the same input on both
versions, with the same build and settings (§9.5).

**Reproducible evidence.** Every confirmed crash gets a bundle (§10): the
original input and a version shrunk by delta debugging, which keeps only
inputs that crash with the **same signature** (a non-zero exit code is not
enough). The bundle also holds the binary and its hash, the build settings,
the environment, the exact command, and a `reproduce.sh`. The bundle is
replayed 3 times and any instability is reported. A stable bundle becomes a
**regression test** in the target's `tests/regression/`. Later runs load it,
check that it still fails on base, and check that it no longer fails on
patch (§10.6).

**Nothing is lost.** Before the report is written, the tool checks that
every abnormal result (crash, oracle mismatch, timeout, limit, flaky) is
covered by a finding. If one is not, that is a bug in the tool, and the run
exits 30 (§8.7).

**One exit code.** When several outcomes apply, the priority is
`30 > 10 > 20 > 40 > 0` (§13): a tool or build error, then a vulnerability,
then a regression, then insufficient evidence, then pass. Every finding,
whatever its weight, stays in the JSON report.

**Optional variant step.** With `--variants`, the tool mutates each security
input with a fixed seed, using integers and character literals from the
diff as hints. It tries the mutants on `patch-sanitized` within a fixed
number of runs. Each new crash, confirmed by a second run, is kept and runs
as a normal test (§7.6). There is no time budget, so the result never
depends on the machine's speed. The step is off by default. On cJSON it
finds the incomplete patch's bypass on its own. On jhead it also finds older
jhead bugs that the original crash hides on base.

**Generic by design.** The tool never names a function or file of a target.
A new program needs only its directory: a `zaraban.yaml`, a `Makefile`, the
sources and the tests (§4.1). `targets/_template/` is the starting point.

## Where each requirement is met

| Course requirement (points) | Where |
|---|---|
| Patch validation, version comparison, linking to the diff (25) | `findings.py`, `linking.py`, `diffinfo.py`, `coverage.py`; §8, §9 |
| Dynamic testing, boundary inputs, separate release/sanitized builds, error classification (25) | `runner.py`, `analysis.py`, `oracle.py`, `builder.py`; §5, §6, §7 |
| Reproducibility, minimization, regression tests (15) | `reproducer.py`, `regression.py`; §10 |
| Scenarios on two programs and unseen patches (15) | `targets/cjson`, `targets/jhead`, `scripts/run_matrix.py`, `results/`; §14.3, §7.6 |
| CI, standard JSON output, exit codes (10) | `.github/workflows/zaraban.yml`, `report.py`, `status.py`; §12, §13, §14.4 |
| Binary hardening and change detection (5) | `hardening.py`, `elf.py`; §11 |
| Documentation, modular design, independent run (5) | `README.md`, this file, `SPEC.md`, each target's `ORACLE.md` |

## The targets

| Target | Program | Vulnerability | Correct patch |
|---|---|---|---|
| `cjson` | cJSON `v1.7.10`, with a small driver | CVE-2019-11834 and CVE-2019-11835: heap over-reads in `cJSON_Minify` | upstream `a43fa56` and `08d2bc7` |
| `jhead` | jhead 3.04 (`56c108f`), its own CLI | heap over-read in `ProcessExifDir` (EXIF DateTime) | upstream `df124a4` |

Each has four versions (base, correct, incomplete, regression), stored both
as complete trees and as diffs. Each has valid, boundary, invalid and
security tests, whose expected behavior comes from upstream tests and
documentation, never from running a patched version. Its `ORACLE.md`
explains every test and every expected verdict. `results/<target>/<scenario>/`
holds the reports and bundles of the six delivered runs (exits 0, 10 and 20
for each target).

## Known limitations

- **The tests limit the verdict.** `PASS` means no error was seen in the
  tests that ran, not that none exists. The variant step widens the search,
  but only around the known exploits.
- **The same-bug rule is a heuristic.** Two different bugs in one function
  with the same error type count as one bug. Two crashes of one bug in
  different functions count as two.
- **A masked bug looks new.** On base, an input can stop at the original bug
  before it reaches a second one. When the patch removes the first bug, the
  second appears as `NEW_ISSUE`. The link and the regression-test check on
  base show this case. It is common with variants on jhead.
- **The execution trace needs clang coverage** (`coverage_cmd`). Without it,
  a crash outside the changed code stays `UNDETERMINED`.
- **ASan on newer kernels.** clang 14's ASan can crash at start-up when the
  host uses `vm.mmap_rnd_bits=32`. The README's troubleshooting section has
  the fix, and CI applies it.
