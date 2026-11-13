# Zaraban

Zaraban checks whether a security patch to a C/C++ program really fixes the
vulnerability without breaking the program. It builds the version before the
patch (base) and after it (patch), runs both on the same tests, and reports a
verdict as a CI exit code, a readable summary and a JSON report.

Course project 1, Data & Network Security, Sharif University of Technology.
The behavior of the tool is defined in [`docs/SPEC.md`](docs/SPEC.md). Design
choices are recorded in [`docs/DECISIONS.md`](docs/DECISIONS.md).

---

## Quick start

Everything runs inside the Docker image, which provides the isolated
environment the course requires.

```bash
# Build the image
docker compose build

# Validate a patch given as a diff file
docker compose run --rm zaraban \
  python -m zaraban.cli -c targets/<target>/zaraban.yaml \
  --patch targets/<target>/patches/incomplete.patch

# Only check a config file, without building anything
docker compose run --rm zaraban \
  python -m zaraban.cli -c targets/<target>/zaraban.yaml --check-config

# Run every delivered scenario and compare with the expected results
docker compose run --rm zaraban python scripts/run_matrix.py
```

Outputs go to `out/<target>/<run id>/`: `summary.txt`, `report.json`, raw
run logs, builds, reproducer bundles and new regression tests (SPEC §12).

## Exit codes

| Code | Name | Meaning |
|---|---|---|
| `0` | `PASS` | The bug was reproduced on base and is gone on patch, and all functional tests and required checks passed. |
| `10` | `VULN_REMAINS` / `NEW_ISSUE` | The original bug still occurs, or another confirmed security bug appeared. |
| `20` | `FUNC_REGRESSION` | A valid test that passed on base fails on patch. |
| `30` | `BUILD_OR_CONFIG_ERROR` | Build failed, config is invalid, or the tool itself failed. Never counts as fixed. |
| `40` | `INCONCLUSIVE` | Not enough evidence, for example the base bug did not reproduce or results were unstable. |

When several apply, the priority is `30 > 10 > 20 > 40 > 0`. Hardening
downgrades are warnings and never change the exit code.

## How it works

```
config + base + patch (dir or diff)
  -> prepare trees, derive diff                         SPEC §3
  -> 4 builds: base/patch x release/sanitized           SPEC §6
  -> hardening check on both release builds             SPEC §11
  -> run every test on every build, 3 repeats           SPEC §5, §7
  -> analyse each run: outcome, detection, error type   SPEC §7.4
  -> findings: FIXED / INCOMPLETE_FIX / NEW_ISSUE /
     FUNCTIONAL_REGRESSION / INCONCLUSIVE               SPEC §8
  -> link each finding to the diff                      SPEC §9
  -> minimize, reproducer bundle, 3 replays,
     regression test                                    SPEC §10
  -> summary.txt + report.json + exit code              SPEC §12, §13
```

## Targets

The course requires two independent C/C++ programs, at least one of them a
real project, each with four versions in this repository: Vulnerable Base,
Correct Patch (exit `0`), Incomplete Patch (exit `10`) and Regression Patch
(exit `20`). Targets, patches and oracles must be approved by the instructor
at the design stage.

We use **two real open-source projects with public CVEs**. The Correct patch
is the upstream fix. The Incomplete and Regression patches are written by us.
`token_parser` stays in the repository as a development fixture only.

| Target | Upstream | Vulnerability | Bug class | Input | Status |
|---|---|---|---|---|---|
| `cjson` | DaveGamble/cJSON | CVE-2019-11834 and CVE-2019-11835 (out-of-bounds reads in `cJSON_Minify`, fixed in 1.7.11) | heap buffer overflow (read) | file, via a small driver | confirmed ([repro](docs/repro/cjson.md)); target ready in `targets/cjson` |
| `jhead` | Matthias Wandel's jhead | Heap out-of-bounds read in `ProcessExifDir` (EXIF DateTime), fixed upstream in commit `df124a4` | heap buffer overflow (read) | file, own CLI (`jhead FILE`) | confirmed; target ready in `targets/jhead` |

`md4c` (CVE-2021-30027) was dropped: its CVE is a use-of-uninitialized-value
found with MemorySanitizer, which AddressSanitizer/UBSan (our profile) does
not catch, so it cannot reproduce cleanly as a crash. jhead replaces it: a
real C program with its own CLI and an ASan-detectable over-read.

Backups if one of these does not reproduce cleanly under ASan:

- cJSON CVE-2023-50471: NULL dereference in `cJSON_InsertItemInArray`
  (1.7.16, fixed in 1.7.17).
- giflib CVE-2016-3977: heap overflow in the official `gif2rgb` utility.
- zlib CVE-2022-37434: heap overflow in `inflateGetHeader` (needs a small
  driver).

How we chose them:

- A real, widely used C library with a public CVE and a public fix commit.
- Builds with a plain Makefile or a few `cc` lines, so the release and
  sanitized profiles stay simple.
- Takes input from a file or stdin, so no network or GUI is involved.
- The PoC crashes under ASan in a few milliseconds.
- Both current CVEs are heap out-of-bounds reads, reached in different code
  (a minifier vs. a Markdown line analyser) and through different input paths
  (a driver vs. the official `md2html` CLI). If a second error class is wanted
  for the classifier, one of the backups below (a NULL dereference, or a
  heap-overflow write) can replace a target.

Every target directory must contain `zaraban.yaml`, `ORACLE.md`,
`scenarios.yaml`, a `Makefile` with `release` and `sanitized` rules, `src/`,
`patches/*.patch`, `versions/patch_*/` and `tests/{valid,boundary,invalid,exploits,regression}/`
(SPEC §14.2).

## Adding a target

No tool code changes are needed (SPEC §4.1):

1. Copy `targets/_template/` to `targets/<name>/`.
2. Put the base sources in `src/` and write a `Makefile` with `release` and
   `sanitized` rules.
3. Write the tests and their expected behavior in `zaraban.yaml`, and the
   source of each expectation in `ORACLE.md`.
4. Run `--check-config`, then run the tool on each patch.

## Repository layout

```
zaraban/                      the tool (Python package)
tests/                        unit tests of the tool (pytest)
targets/<target>/             one directory per target
scripts/run_matrix.py         runs and checks all delivered scenarios
results/<target>/<scenario>/  committed outputs of the delivered scenarios
docs/SPEC.md                  tool specification
docs/DECISIONS.md             design decisions
.github/workflows/zaraban.yml CI pipeline
Dockerfile, docker-compose.yml
```

---

## Team and ownership

Each member owns one module end to end: design, code, unit tests, and the
section of the docs that explains it. This matches the individual defense,
where each member explains their own part, analyses a finding, and makes a
small live change. Each member also co-owns one target.

| Member | Module | SPEC sections | Grading rows it serves | Target |
|---|---|---|---|---|
| A: _name_ | **Orchestrator, builds, hardening, CI**: CLI, config validation, source preparation and diff derivation, the four builds and profile checks, hardening checker, Docker image, CI workflow, `run_matrix.py` | §3, §4, §6, §11, §14 | CI/JSON/exit codes (10), hardening (5), docs and modularity (5) | cJSON |
| B: _name_ | **Runner and crash analysis**: input delivery, run environment and limits, repeats, outcome and error-type rules, stack-trace parsing, signatures, oracle matching | §5, §7 | Dynamic testing and classification (25) | cJSON |
| C: _name_ | **Findings and patch linking**: findings from results, diff parsing, changed functions, location and comparative evidence, execution trace | §8, §9 | Patch validation and diff linking (25) | md4c |
| D: _name_ | **Reproducibility and reporting**: minimization, reproducer bundles, replays, regression tests, `report.json`, `summary.txt`, status and exit code | §10, §12, §13 | Reproducibility and regression tests (15) | md4c |

The 15 points for the scenarios on two programs and the unseen patches are
shared. Each target pair owns its four versions, its tests and its
`ORACLE.md`.

### Shared interfaces (agree on these first)

Every module depends on these types. They live in `zaraban/models.py`. A
change to them needs a pull request reviewed by all four members.

| Type | Defined in | Producer | Consumers |
|---|---|---|---|
| `Config`, `TestCase` | SPEC §4 | A | B, C, D |
| `BuildRecord` | SPEC §6.4, §12.3 | A | B, D |
| `RunRecord`, `Analysis`, `Frame` | SPEC §7, §12.3 | B | C, D |
| `CombinedResult` | SPEC §7.5 | B | C |
| `Finding`, `Link` | SPEC §8.8, §9.6 | C | D |
| `Bundle`, `RegressionTest` | SPEC §10 | D | D, A |
| `Status`, `Condition`, warnings and errors | SPEC §12.6, §13 | D | A |

---

## Implementation plan

The work runs in five phases. Inside a phase, members work in parallel on
their own module. A phase ends at its gate: the listed checks pass on `main`.

### Phase 0: Foundation (all members)

- [ ] Approve `docs/SPEC.md`, including the review fixes (target rule,
      same-bug rule, coverage-based trace, optional variant step).
- [ ] Write `zaraban/models.py` with the shared types above, as dataclasses or
      pydantic models with no logic.
- [ ] **A**: update the Docker image: universal-ctags, llvm tools, non-root
      user, compose limits, `network_mode: none`.
- [ ] **A + B**: confirm the cJSON CVE reproduces under ASan, and pick the
      exact base version and fix commit.
- [ ] **C + D**: confirm the md4c CVE reproduces under ASan, and pick the
      exact base version and fix commit.
- [ ] Send the target proposal (projects, CVEs, four versions, oracle sources)
      to the instructor for approval.

**Gate:** models merged, image builds, both PoCs crash under ASan, and the
target proposal is sent.

### Phase 1: Modules in isolation (parallel)

Each module is built and unit-tested against fixtures, without the rest of
the pipeline.

- [ ] **A**: CLI and arguments (§3), strict config validation and
      `--check-config` (§4.5), source preparation and strip-level detection
      (§3.2), four isolated builds with logs and hashes (§6.2), profile
      verification (§6.3), hardening checker (§11).
- [ ] **B**: input delivery for file, stdin and args (§5.3), clean environment
      and sanitizer options (§7.2), limits and process groups (§7.3), outcome
      and error-type rules (§7.4), frame parsing and signatures, repeats and
      flakiness (§7.5), oracle matching (§5.4). Fixtures: saved stderr from
      real ASan, UBSan, canary, fortify and glibc aborts.
- [ ] **C**: diff parsing into hunks on both sides (§9.2), changed functions
      with ctags, finding rules from fixture results (§8.2 to §8.6), including
      the same-bug rule for incomplete fixes.
- [ ] **D**: byte-level ddmin with a pluggable "same crash" check (§10.2),
      bundle writer and `reproduce.sh` (§10.3 to §10.5), status and exit-code
      resolution (§13), JSON and summary writers (§12).

**Gate:** `pytest` is green for all four modules, and each module has at least
one fixture test per rule in its SPEC sections.

### Phase 2: Integration on `token_parser`

- [ ] **A**: wire the pipeline in order: config, sources, builds, hardening,
      runs, findings, link, bundles, report.
- [ ] **C**: location evidence (§9.3) on real stack traces, plus the execution
      trace. Coverage-based trace is recommended over `gdb`.
- [ ] **D**: regression-test verification, deduplication and promotion
      (§10.6), and loading regression tests in later runs.
- [ ] **B**: completeness check: every abnormal result is referenced by a
      finding (§8.7).

**Gate:** the three `token_parser` scenarios give exits `0`, `10` and `20`
with the findings of SPEC §8.9, through `run_matrix.py`.

### Phase 3: Real targets

For each target, the pair prepares:

- [ ] `src/` at the vulnerable upstream version, with a minimal `Makefile`.
- [ ] Correct patch = the upstream fix commit.
- [ ] Incomplete patch: blocks the public PoC only. Write a second exploit
      input that still reaches the bug, and add it to `security_tests`.
- [ ] Regression patch: removes the crash but rejects or breaks some valid
      inputs, with no other security bug.
- [ ] Tests: about 10 to 20 valid, 10 boundary (around every threshold the
      patches touch) and 10 invalid, each with its source in `ORACLE.md`.
- [ ] `scenarios.yaml` with the expected exit and findings for each patch.

**Gate:** `run_matrix.py` passes for all scenarios of both targets. Results are
saved to `results/` with `--save`.

### Phase 4: CI, docs, and unseen-patch drill

- [ ] **A**: `.github/workflows/zaraban.yml`: build the image, run pytest, run
      the matrix, upload `out/`.
- [ ] Everyone: document your module in `docs/` (design, rules, limitations).
- [ ] **Unseen-patch drill**: each pair writes two surprise patches for the
      other pair's target, gives only the diff, and records the tool's verdict.
      Fix anything it gets wrong.
- [ ] Optional: the bounded variant step for security inputs (SPEC §9.4 and
      the security-test notes in §5).

**Gate:** CI is green on `main`, the drill verdicts are correct, and the README
run guide works on a fresh clone.

### Dependency flow

```
Phase 0  models.py + Docker + PoCs confirmed
           |
Phase 1  A builds | B runner | C findings | D repro+report     (parallel)
           |
Phase 2  A wires pipeline -> token_parser scenarios pass
           |
Phase 3  cJSON pair (A+B)  |  md4c pair (C+D)                  (parallel)
           |
Phase 4  CI + docs + unseen-patch drill
```

The critical path is `models.py`, then B's `RunRecord`, then C's findings,
then D's status. Agree on the models early, because a late change there
blocks everyone.

---

## Working rules

- One branch per task, for example `feat/runner-limits`. Open a pull request
  into `main`, reviewed by one other member.
- Every rule in the SPEC gets a unit test. Name the test after the SPEC
  section, for example `test_7_4_fortify_abort`.
- Never edit `results/` by hand. Regenerate it with
  `run_matrix.py --save`.
- Expected behavior comes from documentation or reference tests and is
  written in `ORACLE.md`. Never take it from the patched program's output or
  from an LLM.
- LLM help is allowed for code. You must be able to explain and change your
  own module without help at the defense.

## Individual defense checklist

Each member, for their own module:

- [ ] Explain the overall architecture and why your module is designed this
      way (3 points).
- [ ] Take one finding from `results/` and explain how its evidence leads to
      the verdict (3 points).
- [ ] Practise a small live change, for example a new error-type rule, a
      different repeat count, or a new boundary test (4 points).

To get a grade you need at least 5 of 10 in the defense, and at least 1 point
in each of the three parts.
