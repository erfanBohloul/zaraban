# Team contributions

This document records what each member of the Zaraban team did in design,
implementation, testing, analysis of results and documentation, as the course
specification asks. It follows the order of the work: initial setup, then
Phases 0 to 4. For each step it names the member responsible and the
branches and pull requests where the work is. Section numbers such as §7.4
refer to [`SPEC.md`](SPEC.md).

## Team

| Name | Role | Main parts | Testing |
|---|---|---|---|
| Amir Mohammad Hamidi (امیر محمد حمیدی) | Orchestrator, builds, hardening, CI | Phase 0 foundation; CLI, config, sources, builds, hardening; pipeline wiring; CI workflow | Phase 1 tests |
| Ali Nouri (علی نوری) | Runner and crash analysis | runner, analysis, oracle; coverage trace; regression tests in later runs | Phase 3 tests; CI tests |
| Fatemeh Shafiei (فاطمه شفیعی) | Findings and patch linking | diff info, findings, linking; completeness check; `run_matrix.py`; variant step | Phase 2 tests |
| Erfan Bohloul (عرفان بهلول) | Reproducibility, reporting and real targets | initial setup; minimize, bundles, regression tests, status, report; cJSON and jhead targets | Final test of the project |

## Summary by activity

| Member | Design | Implementation | Testing | Analysis of results | Documentation |
|---|---|---|---|---|---|
| Amir | Phase 0: Docker isolation, shared types, SPEC review and the phase plan; the two-stage pipeline around `RunContext`; the CI pipeline | Phase 0; Phase 1 CLI, config, sources, builds, hardening; Phase 2 pipeline wiring; Phase 4 CI workflow | Phase 1 unit tests | Root cause of the random ASan crashes (`vm.mmap_rnd_bits`) and of the read-only `UID` problem in CI | Shared docs; README run guide and CI section |
| Ali | Run model, outcome and error-type classification, flakiness rule | Phase 1 runner, analysis, oracle; Phase 2 coverage trace and regression tests in later runs | Phase 3 tests of both real targets; CI tests | Checked the cJSON and jhead verdicts against their oracles; checked the CI runs and artifact | Shared docs |
| Fatemeh | Same-bug rule, link levels, completeness rules, variant step | Phase 1 diff info, findings, linking; Phase 2 completeness check, `scenarios.yaml` and `run_matrix.py`; Phase 4 variant step | Phase 2 integration and end-to-end tests on `token_parser` | Scenario comparison in `run_matrix.py`; what the variant step finds on cJSON and jhead | Shared docs |
| Erfan | Repository setup; bundle and report formats; target choice (jhead in place of md4c) | Initial setup; Phase 1 minimize, bundles, regression tests, status, report; Phase 3 cJSON and jhead | Final test of the whole project | Expected verdicts and `ORACLE.md` of each target; saved results in `results/` | Shared docs |

The whole team wrote and reviewed the documents: `README.md`,
`docs/OVERVIEW.md`, `docs/SPEC.md`, each target's `ORACLE.md`, the demo
targets and `targets/_template`.

## The work in order

### Initial setup (Erfan)

**Where:** the first commits on `main`.

- The GitHub repository and its first layout.
- A first isolated Linux x86-64 Docker environment with the C/C++ toolchain.
- The reference target `token_parser`: a vulnerable base, its patch files
  and a test suite, later used for Phase 2.
- A first test runner with time, CPU and memory watchdogs.

### Phase 0: Foundation (Amir)

**Where:** branches `docs/spec` and `Foundation`, and the commits on `main`
before PR #1.

- The tool specification `SPEC.md`, its review (`SPEC_REVIEW.md`) and the
  team's approval of it (Task 0.1). `PHASES.md`, the plan of phases and tasks
  used for the rest of the project.
- The shared data types in `zaraban/models.py`, with their unit tests (Task 0.2).
- The final Docker image and `docker-compose.yml` (Task 0.3): Ubuntu 22.04,
  gcc, clang 14, llvm and ctags, a non-root user, no network, and memory,
  CPU and process limits (§14.5). This includes a download fallback through
  a proxy, and `scripts/verify_env.sh`, which checks the image's tools.
- Reproduction of the cJSON CVEs under ASan, with the driver and the PoC
  inputs in `docs/repro/` (Task 0.4).
- Test templates for the Phase 1 modules.

### Phase 1: Modules in isolation

Each member built one group of modules, against the shared types of Phase 0.
Each group has its own branch and pull request.

| Member | Branch and PR | Modules | SPEC |
|---|---|---|---|
| Amir | `phase1-a-orchestration`, PR #1 | CLI that never exits with 2 (`cli.py`), strict config validation (`config.py`), source preparation and strip level (`sources.py`), four isolated builds with profile checks (`builder.py`), hardening checker (`hardening.py`, `elf.py`) | §3, §4.5, §6, §11 |
| Ali | `phase1-b-runner`, PR #4 | Running one test (`runner.py`), outcome and error type (`analysis.py`, with real sanitizer stderr fixtures), oracle matching (`oracle.py`), repeats and flakiness | §5.3, §5.4, §7.2 to §7.5 |
| Fatemeh | `phase1-c-findings-linking`, PR #3 | Hunks and changed functions with ctags (`diffinfo.py`), crash and functional findings with the same-bug rule (`findings.py`), location and comparative evidence (`linking.py`) | §8, §9.2, §9.3, §9.5 |
| Erfan | `phase1-d-repro-report`, PR #2 | Delta debugging and reproducer bundles with `reproduce.sh` (`reproducer.py`), regression tests (`regression.py`), status and exit code (`status.py`), `summary.txt` and `report.json` (`report.py`) | §10, §12, §13 |

**Testing (Amir):** the Phase 1 unit tests, one test per SPEC rule, named
after the section they check (for example `test_7_4_…` for §7.4).

Before Phase 2, the branch `refactor/pre-phase2-cleanup` moved shared helpers
into `zaraban/util.py` and switched every module to relative imports.

### Phase 2: Integration on `token_parser`

**Where:** branch `phase2`, PR #8 ("Integration on token_parser, Tasks 2.1 to
2.5"), built from `feat/phase2-exec`, `feat/phase2-report` and
`fix/phase2-pipeline`. PR #5 was a first attempt at the same work and was
closed.

The goal was one working pipeline, proved on the small `token_parser`
target with exits 0, 10 and 20 and the right findings.

| Task | Member | Result |
|---|---|---|
| 2.1 Pipeline wiring | Amir | `pipeline.py` in two halves: `exec_stage.py` (sources, builds, hardening, the test matrix and combining repeats) and `analysis_stage.py` (findings to report). They share only `RunContext` (`pipeline_state.py`). Also `environment.py` for the report's environment section. Any failure still writes a report (`TOOL_INTERNAL`, exit 30). |
| 2.2 Execution trace with coverage | Ali | `coverage.py`: clang source-based coverage, a `coverage` build rule for `token_parser`, and traces wired into linking for the `CHANGED_CODE_EXECUTED` level (§9.4). |
| 2.3 Regression tests in later runs | Ali | Later runs load `tests/regression/` before the builds and skip duplicates by SHA-256. They warn with `REGRESSION_BASE_CLEAN` when a regression test no longer fails on base (§10.6, §8.6). |
| 2.4 Completeness check | Fatemeh | `completeness.py`: every abnormal result is covered by a finding, and each stable crash is in exactly one crash finding, otherwise exit 30 (§8.7). The bug key is rebuilt from the finding's tests. Crash frames are made relative to an absolute build tree. |
| 2.5 `scenarios.yaml` and `run_matrix.py` | Fatemeh | The three patches of `token_parser` (correct, incomplete, regression) also as complete trees, next to the base. `scripts/run_matrix.py` runs every scenario with `--no-promote` and compares the exit code and findings with `scenarios.yaml` (§14.2, §14.3). |

**Testing (Fatemeh):** the end-to-end test suite (`tests/test_e2e.py`), the
second-run regression tests, and the fixes they led to in the run directory,
failure reports, source application and the coverage environment.

### Phase 3: Real targets (Erfan)

**Where:** PR #6 (`phase3-cjson`), PR #7 (`phase3-jhead`), PR #10
(`phase3-jhead-tests`, more boundary and invalid inputs in the jhead test
suite itself), and PRs #11 and #12 (`phase3-finish`).

The goal was two real programs, each with a vulnerable base and three
patches: correct (exit 0), incomplete (exit 10) and regression (exit 20).

- **cJSON `v1.7.10`**: CVE-2019-11834 and CVE-2019-11835, heap over-reads in
  `cJSON_Minify`, with a small driver. The correct patch is upstream
  `a43fa56` with `08d2bc7`. It has 40 tests.
- **jhead 3.04**: heap over-read in `ProcessExifDir` (EXIF DateTime). The
  correct patch is upstream `df124a4`. It has 34 tests: 12 valid, 10 boundary,
  10 invalid and 2 security. jhead replaced the planned md4c target, because
  md4c's CVE is a use of uninitialized memory that only MemorySanitizer
  detects, and the tool uses ASan and UBSan.
- For each target: a Makefile with release, sanitized and coverage rules, the
  three versions both as diffs and as complete trees, `ORACLE.md` with the
  source of every expected result, `scenarios.yaml`, and the saved outputs of
  the six scenarios in `results/`.
- `phase3-finish` also made error and warning messages clearer, printed the
  summary at the end of each run, and renamed `target1_sample` to
  `test_token_parser`.

**Testing (Ali):** ran the six cJSON and jhead scenarios and checked every
verdict against the targets' oracles.

### Phase 4: CI, variants and final checks

| Task | Member | Branch and PR | Result |
|---|---|---|---|
| 4.1 CI workflow | Amir | `phase4`, PR #13 | `.github/workflows/zaraban.yml` (§14.4). It runs on every push and on pull requests to `main`, sets `vm.mmap_rnd_bits=28`, and builds the image with the runner's user ids (`HOST_UID`, `HOST_GID`). It then runs the unit tests, the end-to-end tests and the scenarios of `test_token_parser`, `cjson` and `jhead`, and uploads `out/` as the `zaraban-out` artifact even when a step fails. The same PR added the README's fresh-clone run guide. |
| CI testing | Ali | `phase4` | Checked the workflow locally and on GitHub, and checked that the artifact holds every report. |
| 4.2 Documentation | everyone | see below | The README, `docs/OVERVIEW.md`, `docs/SPEC.md` and the targets' `ORACLE.md` files. |
| 4.3 Final testing | Erfan | `main` after PR #16 | The final check of the whole project: 541 tests, all scenarios, and a run from a fresh clone. |
| 4.4 Optional variant step | Fatemeh | `feat/variants`, PR #15 | `variants.py` and `--variants` (§7.6): seeded mutations of the security inputs, with hints from the diff and a fixed number of runs. On cJSON it finds the incomplete patch's bypass on its own. |

### Task 4.2: Documentation (everyone)

**Where:** PR #9 (`chore/code-cleanup`, self-contained comments in every
module), PR #14 (`feat/target-template`, `targets/_template`), PR #16
(`docs/cleanup`, the README as the run guide and `docs/OVERVIEW.md`), and the
demo targets in `phase3-finish`.

## Problems found and solved

| Problem | How it showed | Cause and fix | Member |
|---|---|---|---|
| ASan crashed at random | Sanitized runs died with `SIGSEGV` and no ASan report, so results were flaky and `INCONCLUSIVE` | clang 14's ASan does not work with `vm.mmap_rnd_bits=32`. It is set to 28 (README troubleshooting, and a CI step). | Amir |
| Duplicate completeness errors | A correct run reported unreferenced crashes and exited 30 | The bug key was taken from the signature text. It is now rebuilt from the finding's tests and category, and crash frames are relative to an absolute build tree. | Fatemeh |
| md4c could not be used | Its CVE is not detected by ASan or UBSan | Replaced by jhead | Erfan |
| CI build would fail on GitHub | `bash: UID: readonly variable` | `UID` is read-only in bash, and GitHub runs steps with `bash -e`. The build arguments became `HOST_UID` and `HOST_GID`. | Amir |
