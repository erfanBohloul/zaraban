# Architecture Decision Records (ADR) - Zaraban

This document logs all key design choices, architectural decisions, and trade-offs made during the development of **Zaraban**, directly mapped to the project requirements of Sharif University of Technology (Data & Network Security).

---

## ADR-001: Execution Sandbox & Architecture Emulation
* **Status:** Accepted
* **Context:**
  The project specification mandates analyzing **Linux x86_64 ELF** binaries. Development is taking place on macOS (ARM64 Apple Silicon).
* **Decision:**
  Use Docker with `--platform linux/amd64` based on `ubuntu:22.04`.
  Bind mount the local directory (`.:/workspace`) to allow seamless host editing while executing binaries in an isolated Linux x86_64 environment.
* **Consequences:**
  - Guaranteed exact POSIX signal semantics, Linux sys-calls, and compiler behavior.
  - Zero pollution of the host machine with crashing/exploited binaries.

---

## ADR-002: Implementation Language
* **Status:** Accepted
* **Context:**
  The tool requires process orchestration, Git diff analysis, ELF inspection, automated input minimization, and CI/CD CLI exit codes.
* **Decision:**
  Implement the tool in **Python 3.10+**.
* **Rationale:**
  - Section 2 explicitly allows any language for the validation tool.
  - Robust ecosystem: `pyelftools` (native ELF inspection), `unidiff` (Git diff parsing), `pydantic` (config validation), and `rich` (CLI reporting).
  - Excellent process management via `subprocess` with timeout and POSIX signal handling.

---

## ADR-003: Target Generalizability & Configuration Schema
* **Status:** Accepted
* **Context:**
  Section 2 mandates that adding a new target must require only changing a configuration file (no hardcoded function names or binary paths).
* **Decision:**
  Implement [`zaraban/config.py`](../zaraban/config.py) supporting `zaraban.yaml` format.
  Configurable fields include:
  - Binary path & build commands (`release_cmd`, `sanitized_cmd`, `clean_cmd`)
  - Input methods: `stdin`, `file`, or `args`
  - Resource limits (`timeout_seconds`, `memory_limit_mb`)
  - Test suites: `valid_tests`, `boundary_tests`, and `security_tests`.

---

## ADR-004: Standardized Exit Codes & Priority Resolution
* **Status:** Accepted
* **Context:**
  Section 3.5 mandates strict exit codes:
  - `0`: PASS
  - `10`: VULN_REMAINS or NEW_ISSUE
  - `20`: FUNC_REGRESSION
  - `30`: BUILD_OR_CONFIG_ERROR
  - `40`: INCONCLUSIVE
* **Decision:**
  Implement strict priority resolution (SPEC §13.1):
  $$\text{Priority: } 30 > 10 > 20 > 40 > 0$$
  If both a regression and an unresolved security bug are found, priority mandates reporting code `10`.
* **Note:** The exit-code names follow the spec's own wording, as in SPEC §13.
  The single source is [`zaraban/models.py`](../zaraban/models.py)
  (`ExitCode`, `ConditionName`, `EXIT_PRIORITY`). The earlier standalone
  `zaraban/constants.py`, which used the draft names `VULN_OR_NEW_ISSUE` and
  `ERROR_CONFIG_OR_BUILD`, has been removed so there is only one definition.

---

## ADR-005: Dual-Build Strategy (Release vs. Sanitized)
* **Status:** Accepted
* **Context:**
  Section 3.2 requires testing both Release and Sanitized builds separately, ensuring results are never mixed.
* **Decision:**
  - **Release Build:** GCC with `-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now -pie -fPIE`. Tests real-world binary behavior and compiler hardening.
  - **Sanitized Build:** Clang with `-fsanitize=address,undefined -g -O1`. Pinpoints precise memory error types and stack traces.

---

## ADR-006: Process Watchdogs & Resource Limiting
* **Status:** Accepted
* **Context:**
  Section 3.2 states: "عبور از محدودیت زمان یا منابع جداگانه گزارش شود؛ هر توقف برنامه الزاماً آسیب‌پذیری قابل بهره‌برداری نیست."
* **Decision:**
  Implement a multi-tier watchdog system:
  1. **Wall-Clock Timeout:** Python `subprocess` watchdog kills hanging/sleeping processes.
  2. **CPU Limit:** Set `resource.RLIMIT_CPU` before execution; kernel sends `SIGXCPU` (signal 24) on infinite computation loops.
  3. **Memory Limits:**
     - For Release builds: Enforce `resource.RLIMIT_DATA`.
     - For Sanitized (ASan) builds: Avoid `RLIMIT_AS` (which conflicts with ASan's 16-32TB shadow memory reservation) and use `ASAN_OPTIONS="max_allocation_size_mb=..."`.
  4. **Peak Resource Tracking:** Capture peak Resident Set Size (`rusage.ru_maxrss`) via `os.wait4`.

---

## ADR-007: Reference Target Design
* **Status:** Accepted
* **Context:**
  Section 4 requires two target programs, each with 4 specific versions (Base, Correct, Incomplete, Regression).
* **Decision:**
  Created `targets/test_token_parser` (`token_parser`):
  - Base: Stack buffer overflow via unchecked `strcpy` into a 64-byte buffer.
  - Correct Patch: Bounds check with `sizeof(value)`.
  - Incomplete Patch: Naive 100-byte filter (blocked by 120-byte exploit, but secondary 80-byte exploit still crashes).
  - Regression Patch: Rejects valid keys shorter than 8 chars, breaking `SET name=alice`.
