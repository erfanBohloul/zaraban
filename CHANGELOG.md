# Changelog

All notable changes to Zaraban are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

Rules for the team:
- Every pull request that changes behavior adds one line under `[Unreleased]`,
  in the right group, with the PR number and the author.
- When a phase gate passes, `[Unreleased]` becomes a version (one minor
  version per phase) and the gate result is noted.
- Commit-by-commit history lives in `git log`; this file is for people.

Groups: Added, Changed, Fixed, Removed, Security, Docs.

## [Unreleased]

### Added
- `zaraban/models.py`: shared data types, exit-code priority, warning and
  error codes, JSON serialization (SPEC §12.2). (#PR, A)
- `tests/test_models.py`: 11 unit tests for the shared types. (#PR, A)
- `.dockerignore` limiting the build context to `pyproject.toml`. (#PR, A)

### Changed
- Docker image: adds universal-ctags, runs as non-root `zaraban` user,
  installs dependencies from `pyproject.toml`, fails early on missing tools.
  (#PR, A)
- `docker-compose.yml`: no network, 2 CPUs, 2 GB memory, 512 processes,
  no core dumps; new `zaraban-online` service for fetching sources. (#PR, A)

### Fixed
- Python dependencies were not installed with `pip install .` on Ubuntu
  22.04 (old pip installed a package named "UNKNOWN"). (#PR, A)

## [0.1.0] - before Phase 0

### Added
- Initial engine on `main` and `feat/complete-zaraban-engine` (commit
  `fe43c75`), `token_parser` sample target, `docs/SPEC.md` draft,
  `docs/DECISIONS.md`.
