# Changelog

All notable changes to the Zaraban security patch validation engine are documented in this file.

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
  - Full-pipeline verification on `targets/target1_sample` (token_parser).
  - Verifies correct patch -> exit 0 (`PASS`), incomplete patch -> exit 10 (`VULN_REMAINS`), regression patch -> exit 20 (`FUNC_REGRESSION`), and invalid config -> exit 30 (`BUILD_OR_CONFIG_ERROR`).
  - Verifies presence and schema conformance of `report.json` (all required keys from SPEC §12.4) and `summary.txt`.
- **Continuous Integration (`.github/workflows/ci.yml`)**:
  - Automated GitHub Actions workflow on Ubuntu 22.04 runner.
  - Applies ASan kernel address randomization fix (`sudo sysctl vm.mmap_rnd_bits=28`, Issue #002).
  - Builds the Docker container and runs unit tests and end-to-end integration tests in Docker.
- **Documentation**:
  - Updated `README.md` with comprehensive "How to run" instructions, CLI flags, scenario descriptions, and output inspection details.
