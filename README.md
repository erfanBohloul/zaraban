# Zaraban

Zaraban checks whether a security patch to a C/C++ program really fixes the
vulnerability, and whether it breaks anything else. It builds the program
before the patch (**base**) and after it (**patch**). It runs both on the same
tests, in release and sanitized builds, and compares what happens. It then
reports a verdict as a CI exit code, a readable summary and a JSON report
with all the evidence: the crash, where it is in the diff, a minimized input
that reproduces it, and a regression test.

Course project 1, Data & Network Security, Sharif University of Technology.

| Document | What it is for |
|---|---|
| This README | How to install and run the tool, read its results, and add a target |
| [`docs/OVERVIEW.md`](docs/OVERVIEW.md) | A short tour of the design and why it works this way |
| [`docs/SPEC.md`](docs/SPEC.md) | The full technical reference: every rule, input and output format |
| `targets/<target>/ORACLE.md` | Each target's versions, tests and the source of every expected result |
| [`docs/project1_spec.pdf`](docs/project1_spec.pdf) | The course specification |

## Contents

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Quick start on a fresh clone](#quick-start-on-a-fresh-clone)
- [Validating a patch](#validating-a-patch)
- [Command-line options](#command-line-options)
- [Exit codes](#exit-codes)
- [Reading the results](#reading-the-results)
- [The variant step (optional)](#the-variant-step-optional)
- [The delivered targets](#the-delivered-targets)
- [Demo targets](#demo-targets)
- [Adding a new target](#adding-a-new-target)
- [Tests and CI](#tests-and-ci)
- [Troubleshooting](#troubleshooting)
- [Repository layout](#repository-layout)

## What it does

One run validates **one patch** of **one target**:

```
zaraban.yaml + base + patch (a diff file or a patched source tree)
  -> check the config, prepare both source trees and the diff
  -> 4 isolated builds: base/patch × release/sanitized (ASan + UBSan)
  -> hardening check of both release binaries: NX, PIE, RELRO, stack canary
  -> every test on every build, 3 times, with the same limits and environment
  -> for each run: how it ended, what detected the error, which error, where
  -> findings: FIXED / INCOMPLETE_FIX / NEW_ISSUE / FUNCTIONAL_REGRESSION / INCONCLUSIVE
  -> link each finding to the diff (stack trace, changed functions, coverage)
  -> for each crash: minimized input, reproducer bundle, 3 replays, regression test
  -> summary.txt + report.json + exit code
```

The tool depends on no specific program. A target is described only by its
`zaraban.yaml`: how to build it, how its input is given (file, stdin or
arguments), and its tests with their expected behavior.

## Requirements

- **Docker** with Compose v2 (`docker compose`). Everything runs inside the
  image (Ubuntu 22.04, gcc, clang 14, llvm, universal-ctags, Python 3.10).
  Nothing else is needed on the host.
- An **x86-64** machine. Linux is the tested host. On macOS with Apple
  silicon, Docker runs the `linux/amd64` image under emulation, which is
  slower.
- **Linux hosts only:** clang 14's AddressSanitizer needs
  `vm.mmap_rnd_bits=28`. Set it once per boot, or sanitized runs crash at
  random (see [Troubleshooting](#asan-crashes-at-random-or-many-results-are-flaky)):

  ```bash
  sudo sysctl -w vm.mmap_rnd_bits=28
  ```

## Quick start on a fresh clone

These are the same steps CI runs:

```bash
git clone https://github.com/erfanBohloul/zaraban.git && cd zaraban
sudo sysctl -w vm.mmap_rnd_bits=28                          # Linux, once per boot
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose build    # files in out/ stay yours
docker compose run --rm zaraban python3 -m pytest -q        # unit and end-to-end tests
docker compose run --rm zaraban python3 scripts/run_matrix.py cjson jhead
```

The last command runs the six delivered scenarios. It prints one line per
scenario and ends with `6/6 scenarios matched`; it exits non-zero if any
scenario does not match. Each run's full output is under
`out/run_matrix/<target>/<scenario>/`.

```
cjson/correct                   exit 0  (expected 0 )  findings ok   PASS
cjson/incomplete                exit 10 (expected 10)  findings ok   PASS
cjson/regression                exit 20 (expected 20)  findings ok   PASS
jhead/correct                   exit 0  (expected 0 )  findings ok   PASS
jhead/incomplete                exit 10 (expected 10)  findings ok   PASS
jhead/regression                exit 20 (expected 20)  findings ok   PASS
6/6 scenarios matched
```

## Validating a patch

Give the target's config and the patch. The patch can be a unified diff
(any `-p` level, found automatically) or a directory with the complete
patched source tree:

```bash
# A diff file
docker compose run --rm zaraban \
  python3 -m zaraban.cli -c targets/cjson/zaraban.yaml \
  --patch targets/cjson/patches/incomplete.patch
echo "exit code: $?"

# A patched source tree
docker compose run --rm zaraban \
  python3 -m zaraban.cli -c targets/cjson/zaraban.yaml \
  --patch targets/cjson/versions/patch_incomplete

# Only check a config and its test files, without building anything
docker compose run --rm zaraban \
  python3 -m zaraban.cli -c targets/cjson/zaraban.yaml --check-config
```

The base is the target's `src/` tree (`base_dir` in the config) unless you
give `--base DIR`. An unseen patch is validated the same way: only the
`.patch` file is needed, and the verdict comes from running the tests, never
from the patch's name.

The paths must be inside the repository, because only the repository is
mounted in the container (at `/workspace`). Copy an external patch into the
repository first, for example to `tmp/` (git-ignored).

> **Regression tests are added to the target.** A run that finds a crash
> writes a regression test to the run's `regression/` directory, and also
> copies it to `targets/<target>/tests/regression/`, so later runs check it
> (SPEC §10.6). When you are only experimenting, add `--no-promote` to leave
> the target unchanged.

## Command-line options

| Option | Meaning |
|---|---|
| `-c, --config FILE` | The target's `zaraban.yaml` (required). |
| `--patch PATCH` | The patched version: a diff file or a directory (required, except with `--check-config`). |
| `--base DIR` | The base source tree (default: `base_dir` from the config). |
| `--out DIR` | Where outputs go; each run gets its own `<out>/<target>/<run id>/` (default: `out/`). |
| `--no-promote` | Do not copy new regression tests into the target's `tests/regression/`. |
| `--keep-work` | Keep the temporary source and build copies in `<run dir>/work/`, for debugging. |
| `--variants` | Also run the [variant step](#the-variant-step-optional) for this run, even if the config leaves it off. |
| `--no-variants` | Skip the variant step for this run, even if the config turns it on. |
| `--check-config` | Only validate the config and its files, then exit `0` (valid) or `30` (invalid). |
| `-v, --verbose` | Print progress details. |
| `--version` | Print the tool version. |

## Exit codes

| Code | Name | Meaning |
|---|---|---|
| `0` | `PASS` | The bug was reproduced on base and is gone on patch, no other security error was found, and every functional test and required check passed. |
| `10` | `VULN_REMAINS` / `NEW_ISSUE` | The original bug still occurs on patch, or another memory or security error was confirmed there. |
| `20` | `FUNC_REGRESSION` | A valid test that passed on base fails on patch. |
| `30` | `BUILD_OR_CONFIG_ERROR` | A build failed, the config or an argument is invalid, the patch does not apply, or the tool itself failed. |
| `40` | `INCONCLUSIVE` | Not enough evidence: the base bug did not reproduce, a result was flaky, or a stop could not be classified. |

When several apply, the priority is `30 > 10 > 20 > 40 > 0`. Every finding
stays in `report.json` whatever the exit code. A hardening downgrade is a
warning and never changes the exit code.

## Reading the results

Every run writes to its own new directory, `out/<target>/<run id>/`. The run
id is the UTC start time plus the first 8 hex digits of the diff's SHA-256.
The summary is also printed at the end of the run. This is the cJSON
incomplete patch (saved in `results/cjson/incomplete/summary.txt`):

```
ZARABAN 0.2.0  cjson  run 20261114-093419-5d31d06f
base:  /workspace/targets/cjson (directory)
patch: /workspace/targets/cjson/patches/incomplete.patch (diff, -p1)

BUILDS     base-release ok · base-sanitized ok · patch-release ok · patch-sanitized ok
HARDENING  NX on→on · PIE on→on · RELRO full→full · canary on→on   (no changes)
TESTS      40 tests × 4 builds × 3 repeats   flaky: 0

FINDINGS
  F-001 INCOMPLETE_FIX  HEAP_BUFFER_OVERFLOW @ cJSON_Minify < main
        tests:     exploit_comment blocked · exploit_string blocked · exploit_comment_bypass reaches
        release:   NORMAL exit 0 → NORMAL exit 0
        sanitized: ASAN/SIGABRT → CRASH ASAN SIGABRT (exploit_comment_bypass); NORMAL exit 0 (exploit_comment, exploit_string)
        link:      IN_CHANGED_FUNCTION  src/cJSON.c:2642 cJSON_Minify (patch side)
        bundle:    reproducers/F-001  6 → 3 bytes, replay 3/3
        regression: regression/reg-exploit_comment_bypass-f8be50c1.yaml
        notes:     HEAP_BUFFER_OVERFLOW @ cJSON_Minify (src/cJSON.c) still occurs on patch with exploit_comment_bypass; the patch blocks exploit_comment, exploit_string.

RESULT     exit 10  VULN_REMAINS
```

How to read a finding:

- **Category and signature.** `INCOMPLETE_FIX` means the same bug (same
  error type, function and file) crashes on base and still crashes on patch.
  The signature is the error type and the top three functions of the
  program.
- **tests.** For each test of the finding, what it does on patch: `blocked`
  (no crash any more), `reaches` (still crashes with this bug) or
  `other_error`.
- **release / sanitized.** What happened on base → patch, per profile. The
  two profiles are never mixed. Here the release binary does not crash
  (the over-read is silent there), and the sanitized binary shows the error.
- **link.** How the finding relates to the diff. From strongest to weakest:
  `IN_CHANGED_HUNK`, `IN_CHANGED_FUNCTION`, `CHANGED_FUNCTION_IN_STACK`,
  `CHANGED_CODE_EXECUTED` (seen in a coverage trace) and `UNDETERMINED`.
- **bundle.** The input was minimized from 6 to 3 bytes, and the bundle
  reproduced the crash in 3 of 3 replays.

The run directory holds:

```
summary.txt                  the summary above
report.json                  everything, machine-readable (SPEC §12.4)
inputs/                      copies of the config and the diff used
builds/<build>/              build.json, build.log, the binary
runs/<test>/<build>/         <n>.json, <n>.stdout, <n>.stderr for each repeat
reproducers/<finding id>/    input.orig.*, input.min.*, bin/, metadata.json, replays.json, reproduce.sh
regression/                  new regression tests (YAML plus input)
variants/                    inputs of kept variants (only with --variants)
errors.log                   only if the tool itself failed
```

`report.json` starts with the run, target, versions (with commit and tree
hashes), environment and settings. Then come `builds`, `hardening`,
`execution_logs` (every test on every build), `findings` (with their links
and bundles), `regression_added`, `status` (the required checks, the
conditions that decided the exit code, and why), `warnings` and `errors`.

A reproducer bundle runs on its own, with the same command, environment and
limits as during the run, and checks the binary's hash first:

```bash
docker compose run --rm zaraban bash results/cjson/incomplete/reproducers/F-001/reproduce.sh       # minimized input
docker compose run --rm zaraban bash results/cjson/incomplete/reproducers/F-001/reproduce.sh orig  # original input
```

It exits `0` when the same error is reproduced, `1` when it is not, and `2`
for a hash mismatch or bad usage.

## The variant step (optional)

An incomplete patch often blocks the known exploit but not a slightly
different input. With `--variants`, after the normal runs, the tool makes
mutated copies of each security input with a fixed seed. It uses lengths
and characters from the diff as hints, and runs each copy once on
`patch-sanitized`. A copy that crashes with a bug no test showed there, and
does so again on a second run, is kept. It then runs on all four builds like
any other test, so the normal finding, minimization and regression-test
rules apply to it (SPEC §7.6).

```bash
docker compose run --rm zaraban \
  python3 -m zaraban.cli -c targets/cjson/zaraban.yaml \
  --patch targets/cjson/patches/incomplete.patch --variants --no-promote
```

It is off by default, so the delivered scenarios do not depend on it. It can
also be turned on in the config:

```yaml
variants:
  enabled: false     # --variants / --no-variants override this for one run
  budget_runs: 200   # screening runs in total; no time budget, so results do not depend on machine speed
  seed: 1            # same seed, same candidates
  max_tests: 5       # kept variants, at most one per new bug
```

The summary then gets a `VARIANTS` line, and `report.json` records what the
step did in `settings.variants`. On cJSON, with the hand-written bypass
exploit removed from the config, the step alone finds an input that still
overflows on the incomplete patch (exit `10`). On jhead it also finds older
bugs of jhead itself that the original crash hides on base, so every jhead
patch then gives exit `10` (see `targets/jhead/ORACLE.md`).

## The delivered targets

The course asks for two independent programs, at least one of them a real
project. Each must have four versions: a vulnerable base, a correct patch
(exit `0`), an incomplete patch (exit `10`) and a regression patch
(exit `20`). Both of our targets are real open-source programs. The correct
patch is the upstream fix, and we wrote the incomplete and regression
patches.

| Target | Program | Vulnerability | Input | Tests (valid / boundary / invalid / security) |
|---|---|---|---|---|
| [`cjson`](targets/cjson/ORACLE.md) | cJSON `v1.7.10` | CVE-2019-11834 and CVE-2019-11835: heap over-reads in `cJSON_Minify`; fixed upstream in `a43fa56` | a file, through a small driver (`src/main.c`) | 17 / 10 / 10 / 3 |
| [`jhead`](targets/jhead/ORACLE.md) | jhead 3.04 (`56c108f`) | heap over-read in `ProcessExifDir` (EXIF DateTime); fixed upstream in `df124a4` | a JPEG file, jhead's own CLI | 12 / 10 / 10 / 2 |

| Scenario | cjson | jhead |
|---|---|---|
| correct | exit `0`: one `FIXED` | exit `0`: one `FIXED` |
| incomplete | exit `10`: `INCOMPLETE_FIX`, `exploit_comment_bypass` still crashes | exit `10`: `INCOMPLETE_FIX`, `exploit_datetime` still crashes |
| regression | exit `20`: two `FUNCTIONAL_REGRESSION` (strings with `/*` are cut) and `FIXED` | exit `20`: six `FUNCTIONAL_REGRESSION` (the time is dropped from dates) and `FIXED` |

Each target directory contains:

```
targets/<target>/
  zaraban.yaml        the config: build, input method, limits, tests
  ORACLE.md           versions, tests, and the source of every expected result
  scenarios.yaml      the expected exit code and findings of each patch
  Makefile            release, sanitized and coverage rules
  src/                the vulnerable base
  patches/*.patch     correct, incomplete and regression, as diffs
  versions/patch_*/   the same three versions as complete trees
  tests/              valid/, boundary/, invalid/, exploits/, regression/
```

The expected results come from upstream tests and documentation, never from
running a patched version. The saved outputs of the six scenarios (reports,
summaries, bundles) are in `results/<target>/<scenario>/`. To regenerate
them:

```bash
docker compose run --rm zaraban python3 scripts/run_matrix.py cjson jhead --save
```

`scripts/run_matrix.py` first checks that each `.patch` file and its
`versions/` tree describe the same change. It then runs the tool and
compares the exit code and the findings with `scenarios.yaml`.

`targets/test_token_parser` is a small program we wrote for the tool's own
end-to-end tests. It is not one of the two delivered targets.

## Demo targets

`targets/demo_*` are four tiny programs (about 25 lines each) for trying the
tool by hand. Each has one easy-to-read bug and three patches:

| Target | Bug |
|---|---|
| `demo_stack_overflow` | stack buffer overflow (write) |
| `demo_heap_overread` | heap out-of-bounds read |
| `demo_divzero` | division by zero |
| `demo_null_deref` | NULL pointer dereference |

In each one, `correct` fixes the bug (exit `0`). `incomplete` adds a check
that misses the bug, a wrong bound or the wrong variable (exit `10`).
`regression` fixes the bug but breaks a valid input (exit `20`). Read
`src/main.c` and `patches/*.patch`, then run:

```bash
docker compose run --rm zaraban \
  python3 -m zaraban.cli -c targets/demo_stack_overflow/zaraban.yaml \
  --patch targets/demo_stack_overflow/patches/incomplete.patch --no-promote

# all three patches of all four demos, checked against their scenarios.yaml
docker compose run --rm zaraban python3 scripts/run_matrix.py \
  demo_stack_overflow demo_heap_overread demo_divzero demo_null_deref
```

The demos have no invalid tests, so each run prints the warning
`NO_INVALID_TESTS`. A warning never changes the exit code.

## Adding a new target

No tool code changes are needed:

1. Copy the template: `cp -r targets/_template targets/<name>`. It has a
   `zaraban.yaml` that lists and explains every key, and a `Makefile` with
   the `release`, `sanitized`, `coverage` and `clean` rules. It also has
   skeletons of `ORACLE.md` and `scenarios.yaml`, and the test directories
   with one placeholder input each.
2. Put the base sources in `src/`, and set `SRC` and `BIN` in the
   `Makefile`. `BIN` must match `build.binary_path`. Keep the hardening
   flags in the Makefile, not in the config, so a patch that weakens them
   is detected.
3. Replace every `REPLACE` in `zaraban.yaml` with the real tests and their
   expected behavior, and write in `ORACLE.md` where each expectation comes
   from. Delete the placeholder `example.txt` inputs.
4. Check the config:

   ```bash
   docker compose run --rm zaraban python3 -m zaraban.cli -c targets/<name>/zaraban.yaml --check-config
   ```

5. Run the tool on a patch:

   ```bash
   docker compose run --rm zaraban python3 -m zaraban.cli -c targets/<name>/zaraban.yaml --patch <file>.patch
   ```

6. For a delivered target only, add the three `versions/patch_*/` trees and
   `patches/*.patch`. `ORACLE.md` shows how to make a diff from a tree.
   Then run `python3 scripts/run_matrix.py <name>`.

`run_matrix.py` skips directories whose name starts with `_`, so the
template itself is never run.

## Tests and CI

```bash
docker compose run --rm zaraban python3 -m pytest -q                      # everything
docker compose run --rm zaraban python3 -m pytest -q tests/test_e2e.py    # end to end only
docker compose run --rm zaraban bash scripts/verify_env.sh                # check the image's tools
```

Unit tests are named after the SPEC section they check, for example
`test_7_4_…` for §7.4.

`.github/workflows/zaraban.yml` runs on every push and every pull request to
`main`. It sets `vm.mmap_rnd_bits`, builds the image, and runs the unit
tests, the end-to-end tests and the scenarios of `test_token_parser`,
`cjson` and `jhead`. It uploads `out/` as the `zaraban-out` artifact, with
every report, summary and reproducer bundle, even when a step fails. Any
failing step fails the job, so the tool's exit codes decide the pipeline
result.

## Troubleshooting

### ASan crashes at random, or many results are flaky

Many tests become `INCONCLUSIVE` with notes such as `CRASH SIGNAL SIGSEGV in
repeat 2`, or sanitized binaries die with `SIGSEGV` and no ASan report. Newer
Linux kernels use `vm.mmap_rnd_bits=32`. clang 14's AddressSanitizer
(Ubuntu 22.04) then sometimes places memory where it does not expect it, and
crashes itself. This is a setting of the **host** kernel:

```bash
cat /proc/sys/vm/mmap_rnd_bits                                    # 32 means affected
sudo sysctl -w vm.mmap_rnd_bits=28                                # fix until reboot
echo 'vm.mmap_rnd_bits=28' | sudo tee /etc/sysctl.d/99-asan.conf  # keep it after reboot
```

If you cannot change it, run the tests with address randomization turned
off for the container instead:

```bash
docker run --rm --network none --security-opt seccomp=unconfined -v "$PWD":/workspace -w /workspace \
  zaraban:latest setarch x86_64 -R python3 -m pytest -q
```

### `docker compose build` cannot download packages

If `apt-get` or `pip` time out during the build, the build container cannot
reach the package servers, for example when a VPN runs only on the host.
The Dockerfile tries a direct download first, and retries through
`BUILD_PROXY` only if that fails:

1. `cp .env.example .env`, then set your VPN's local HTTP proxy, for example
   `BUILD_PROXY=http://host.docker.internal:7890`. Turn on "Allow LAN" in
   the VPN app, so the build container can reach it.
2. `docker compose build`.

Leave `BUILD_PROXY` empty when no proxy is needed.

### Files in `out/` belong to root, or the run cannot write `out/`

Build the image with your own user ids, so the container user matches you:
`HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose build`.

### A config error (exit 30)

The message lists every problem at once, each with its place, for example:

```
CONFIG_INVALID: the config targets/demo_divzero/zaraban.yaml has 1 problem
  - valid_tests[0] (valid_ten_two): unknown key 'expected_exitcode'; did you mean 'expected_exit_code'?
```

Run `--check-config` until it prints `Config OK`.

## Repository layout

```
zaraban/                      the tool (Python package; one module per stage, see docs/OVERVIEW.md)
tests/                        unit and end-to-end tests (pytest)
targets/cjson, targets/jhead  the two delivered targets
targets/test_token_parser     small target for the end-to-end tests
targets/demo_*                four tiny targets for trying the tool
targets/_template             the starting point for a new target
scripts/run_matrix.py         runs and checks every scenario in targets/*/scenarios.yaml
scripts/verify_env.sh         checks the tools inside the image
results/<target>/<scenario>/  saved outputs of the six delivered scenarios
docs/                         OVERVIEW.md, SPEC.md, and the course specification
.github/workflows/zaraban.yml the CI pipeline
Dockerfile, docker-compose.yml
```
