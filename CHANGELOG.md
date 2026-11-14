# Changelog

All notable changes to the Zaraban security patch validation engine are documented in this file.

## [Unreleased] - Phase 4: CI, docs and variants

### Added
- **Variant step** (`zaraban.variants`, SPEC §7.6), off by default: `variants` in the config or `--variants` / `--no-variants` on the command line. Seeded mutations of each security input (hints from the diff's integers and character literals) are screened on `patch-sanitized` within `budget_runs`; a confirmed new crash becomes a test of kind `variant` that runs on all four builds and goes through the normal finding, minimization and regression-test rules. `report.settings.variants` and a `VARIANTS` summary line record what was done.
- **Target template**: `targets/_template/` for adding a new target; `run_matrix.py` skips directories that start with `_`.

## [Unreleased] - Phase 3: Real targets

### Added
- **Targets**: `targets/cjson` (CVE-2019-11834 and CVE-2019-11835, 40 tests) and `targets/jhead` (EXIF DateTime heap over-read, 34 tests), each with base, correct, incomplete and regression versions, `ORACLE.md` and `scenarios.yaml`.
- **Saved results**: `results/<target>/<scenario>/` holds the report, summary and reproducer bundles of the six real scenarios (`run_matrix.py cjson jhead --save`).
- **CI**: runs the cjson and jhead scenarios after the `token_parser` ones.
- **Demo targets**: four tiny programs (`targets/demo_*`) for trying the tool by hand.

### Changed
- The summary is printed at the end of every run, not only written to `summary.txt`. It shows each warning with its message, lists the problems of each error, and says `not run` for builds and tests that never ran.
- Error and warning messages are written for someone new to the tool: they say what is wrong, where (for example `valid_tests[2] (name).key`), and what to change, suggest the closest key for a typo, and no longer refer to the design documents.

## [Unreleased] - Phase 2: Pipeline Integration, E2E, and CI

### Added
- **Analysis and Reporting Stage (`zaraban.analysis_stage`)**:
  - Wires pipeline stages 6 through 11 behind a unified `analyze_and_report(ctx: RunContext) -> int` entry point.
  - Diff parsing into hunks from `RunContext.sources` via `diffinfo.sources_hunks`.
  - Finding classification from execution `Results` matrix and linking to diff hunks via `linking.link_findings`.
  - Reproducer bundle generation with input delta debugging (`ddmin`), replays, and bundle metadata via `reproducer.reproduce`.
  - Automatic regression test generation, duplicate detection, and target directory promotion via `regression.add_regression`.
  - Complete `Checks` object construction (7 required checks from SPEC §13.2) feeding `status.compute_status` to determine conditions and the final exit code.
  - Final report assembly and generation of structured `report.json` and human-readable `summary.txt` via `report.assemble_report` and `report.write`.
  - Work directory cleanup unless `--keep-work` is specified.
- **Unit Test Suite for Analysis Stage (`tests/test_analysis_stage.py`)**:
  - Tests for clean `PASS` (exit 0), `VULN_REMAINS` (exit 10), `FUNC_REGRESSION` (exit 20), `BUILD_OR_CONFIG_ERROR` (exit 30), and `INCONCLUSIVE` (exit 40).
  - Validation of check evaluation, flakiness handling, execution log formatting, and work directory retention.
- **End-to-End Test Suite (`tests/test_e2e.py`)**:
  - Full-pipeline verification on `targets/test_token_parser` (token_parser).
  - Verifies correct patch -> exit 0 (`PASS`), incomplete patch -> exit 10 (`VULN_REMAINS`), regression patch -> exit 20 (`FUNC_REGRESSION`), and invalid config -> exit 30 (`BUILD_OR_CONFIG_ERROR`).
  - Verifies presence and schema conformance of `report.json` (all required keys from SPEC §12.4) and `summary.txt`.
- **Continuous Integration (`.github/workflows/ci.yml`)**:
  - Automated GitHub Actions workflow on Ubuntu 22.04 runner.
  - Applies ASan kernel address randomization fix (`sudo sysctl vm.mmap_rnd_bits=28`, Issue #002).
  - Builds the Docker container and runs unit tests and end-to-end integration tests in Docker.
- **Documentation**:
  - Updated `README.md` with comprehensive "How to run" instructions, CLI flags, scenario descriptions, and output inspection details.

### Fixed (Task 2.1 review)
- Each run writes to its own `out/<target>/<run id>/` with the §12.1 run id (UTC time + diff hash) and `inputs/config.yaml`, `inputs/patch.diff`; report paths are relative to it.
- Run files are written at `runs/<test>/<build>/<n>.*` again (they were nested one level deeper, so the paths in the records pointed at missing files).
- Frame paths are made relative to each build's own copy `work/<build>/` (§7.4).
- A patch that does not apply, any `ZarabanError` in a stage, and any tool bug now still end in a report with exit 30; a tool bug adds `TOOL_INTERNAL` and `errors.log` (§13.4).
- Build errors and warnings are reported once, not twice; `NO_SYMBOLIZER` and `OUTPUT_TRUNCATED` reach the report; `settings.sanitizer_options` and the symbolizer path are recorded (§12.4).
- The execution matrix uses the runner's `run_test`, and reproducer candidates use its `run_once`; the duplicate `execution.py` and the copied run code in `analysis_stage.py` are removed.

### Added (Tasks 2.2–2.5)
- Execution traces with clang source-based coverage (`zaraban.coverage`, §9.4): a finding still `UNDETERMINED` after the stack check gets a second linking pass with the changed lines its test ran (`CHANGED_CODE_EXECUTED`), or the warning `TRACE_UNAVAILABLE`. The coverage run uses the same environment and limits as the normal runs.
- Regression tests of earlier runs are loaded from `regression_dir` and run last (`regression.load_tests`, §10.6); one that no longer crashes on base gives `REGRESSION_BASE_CLEAN` (§8.6).
- Completeness check (`zaraban.completeness`, §8.7): a lost abnormal result is `TOOL_INTERNAL` (exit 30).
- `targets/test_token_parser/scenarios.yaml`, the three `versions/patch_*` trees and `scripts/run_matrix.py` (§14.3).
