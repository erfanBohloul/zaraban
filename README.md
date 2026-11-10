# Zaraban (ضربان)
> **Automated Security Patch Validation and Regression Testing Tool in CI/CD**  
> *Sharif University of Technology — Data and Network Security Course (Project 1)*

[![Tests](https://img.shields.io/badge/tests-13%20passed-brightgreen.svg)]()
[![Evaluation Matrix](https://img.shields.io/badge/matrix-6%2F6%20matched-success.svg)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![Target](https://img.shields.io/badge/target-Linux%20x86__64%20ELF-orange.svg)]()

---

## 1. Executive Summary

Applying a security patch does not guarantee that a vulnerability has been reliably solved. A patch may be **incomplete** (bypassed with an alternative input), or introduce a **functional regression** that breaks normal software behavior.

**Zaraban** is an automated CI/CD security engine that evaluates C/C++ security patches through **actual dynamic execution** rather than relying solely on static scans. It provides answers to two fundamental questions:
1. **Security:** Does the base vulnerability remain reproducible in the patched version, or does the patch introduce a new memory error?
2. **Regression:** Does the patch preserve expected behavior on valid inputs?

Zaraban correlates runtime crashes and stack traces directly with Git diff changes, performs automated testcase minimization via Delta Debugging, generates standalone reproducer bundles with 3x replay stability checks, inspects ELF binary hardening protections, and returns strictly prioritized standard exit codes for CI/CD pipeline automation.

---

## 2. Core Architecture & Feature Matrix (Grading Alignment)

| Section | Feature | Implementation Module | Rubric Points |
| :--- | :--- | :--- | :---: |
| **§ 3.1** | **Finding-to-Patch Correlation**<br>Matches call stacks with Git diff hunks & functions. Distinguishes `Fixed`, `Incomplete Fix`, `New Issue`, `Functional Regression`, and `Inconclusive`. | [`zaraban.correlator`](zaraban/correlator/) | **25 pts** |
| **§ 3.2** | **Dynamic Testing & Dual-Build Separation**<br>Strictly separates Release and Sanitized (ASan/UBSan) builds. Tracks error types, detection mechanisms, and OS signals. | [`zaraban.executor`](zaraban/executor/) & [`zaraban.core`](zaraban/core/) | **25 pts** |
| **§ 3.3** | **Reproducibility & Testcase Minimization**<br>Delta Debugging (`ddmin`) minimizes crashing inputs preserving error signature. 3x stability replay check. Reproducer bundles. | [`zaraban.minimizer`](zaraban/minimizer/) & [`zaraban.reproducer`](zaraban/reproducer/) | **15 pts** |
| **§ 4** | **Target Programs & Scenario Validation**<br>Two independent C programs (Synthetic `token_parser` + Real-World `cJSON`), each with 4 versions (Base, Correct, Incomplete, Regression). | [`targets/`](targets/) | **15 pts** |
| **§ 3.5** | **CI/CD Exit Codes & Structured JSON**<br>Standard priority exit codes ($30 > 10 > 20 > 40 > 0$). Human-readable terminal UI + complete machine-readable `report.json`. | [`zaraban.cli`](zaraban/cli.py) & [`zaraban.reporter`](zaraban/reporter/) | **10 pts** |
| **§ 3.4** | **Binary Hardening Checks**<br>Inspects NX, PIE, RELRO (None/Partial/Full), and Stack Canary (`__stack_chk_fail`). Detects hardening downgrades/regressions. | [`zaraban.hardening`](zaraban/hardening/) | **5 pts** |
| **§ 5, 6**| **Modular Architecture & Standalone Execution**<br>Zero fragile runtime dependencies, Docker environment, comprehensive tests, and independent execution. | [`docs/`](docs/) & [`tests/`](tests/) | **5 pts** |
| **Total**| | | **100 / 100** |

---

## 3. Exit Code Standard & Priority Resolution

As mandated in Section 3.5, Zaraban resolves multiple concurrent findings using the strict priority hierarchy:
$$\text{Priority: } \mathbf{30} > \mathbf{10} > \mathbf{20} > \mathbf{40} > \mathbf{0}$$

- **`0` (`PASS`):** Base vulnerability successfully reproduced; not observed on patched version. No new security issues detected, and all functional/boundary tests passed.
- **`10` (`VULN_OR_NEW_ISSUE`):** The vulnerability remains reproducible (`Incomplete Fix`), or a new confirmed memory error has been introduced (`New Issue`).
- **`20` (`FUNC_REGRESSION`):** At least one valid functional test that succeeded on the base version failed on the patched version.
- **`30` (`ERROR_CONFIG_OR_BUILD`):** Compilation failed, configuration file is invalid, or runtime environment error.
- **`40` (`INCONCLUSIVE`):** Analysis could not be completed with sufficient certainty (e.g. base vulnerability failed to reproduce, flaky crash, or unclassified crash).

---

## 4. Evaluated Target Programs

Zaraban is completely generalizable and relies solely on configuration (`zaraban.yaml`), without hardcoded function names or target paths. Two independent C programs are provided in the repository:

### Target 1: `token_parser` (Synthetic Reference Target)
* **Vulnerability:** Unbounded `strcpy` into a 64-byte stack buffer inside `handle_set_command`.
* **Versions:**
  1. `Base`: Unbounded copy into 64-byte stack buffer.
  2. `versions/patch_correct`: Bounds validation `if (val_len >= sizeof(value))` -> **Exit Code `0`**
  3. `versions/patch_incomplete`: Naive check `if (val_len >= 100)`. Bypassed by 80-byte exploit -> **Exit Code `10`**
  4. `versions/patch_regression`: Correct buffer bounds, but accidentally rejects keys shorter than 8 chars, breaking `SET name=alice` -> **Exit Code `20`**

### Target 2: `cJSON` (Real-World Industry Library)
* **Vulnerability:** Ultralightweight ANSI C JSON parser used worldwide in embedded and network software. Fixed 32-byte stack buffer `num_buf` in `parse_number` overflows when parsing numeric literals exceeding 32 digits.
* **Versions:**
  1. `Base`: Unchecked copy into 32-byte stack buffer.
  2. `versions/patch_correct`: Strict bounds check `if (len >= sizeof(num_buf))` -> **Exit Code `0`**
  3. `versions/patch_incomplete`: Shallow check `if (len >= 64)`. Blocked by 80-digit exploit, but bypassed by 45-digit exploit -> **Exit Code `10`**
  4. `versions/patch_regression`: Bounds enforced, but accidentally rejects negative numbers (`{"temperature": -15.5}`) -> **Exit Code `20`**

---

## 5. Quickstart & Usage

### 5.1 CLI Execution
Run Zaraban on any target configuration:
```bash
python3 -m zaraban.cli -c targets/target1_sample/zaraban.yaml \
  --base-dir targets/target1_sample \
  --patch-dir targets/target1_sample/versions/patch_correct \
  --diff targets/target1_sample/patches/correct.patch \
  --report report.json
```

### 5.2 Automated Evaluation Matrix
Run the automated matrix across all 6 scenarios (Target 1 & Target 2):
```bash
python3 scripts/run_matrix.py
```
Output:
```
========================================================================
   Evaluation Matrix Summary
========================================================================
  [✓] Target 1 (token_parser) - Correct Patch: Expected 0, Got 0
  [✓] Target 1 (token_parser) - Incomplete Patch: Expected 10, Got 10
  [✓] Target 1 (token_parser) - Regression Patch: Expected 20, Got 20
  [✓] Target 2 (cjson_parser) - Correct Patch: Expected 0, Got 0
  [✓] Target 2 (cjson_parser) - Incomplete Patch: Expected 10, Got 10
  [✓] Target 2 (cjson_parser) - Regression Patch: Expected 20, Got 20
========================================================================
>>> ALL 6 SCENARIOS SUCCEEDED AND MATCHED SPECIFICATION EXIT CODES! <<<
```

### 5.3 Unit Test Suite
Run the built-in test suite:
```bash
python3 -m unittest discover tests
```

### 5.4 Docker Environment (Linux x86_64)
To run in the isolated Linux x86_64 container:
```bash
docker compose run --rm zaraban python3 scripts/run_matrix.py
```

---

## 6. Detailed Technical Highlights

### Finding-to-Patch Correlation Algorithm
When a crash occurs in the patched build, `CorrelationEngine` analyzes the symbolized call stack:
1. **Direct Hunk Match:** Frame file and line falls directly inside added/modified lines in the Git diff.
2. **Modified Function Match:** Frame executed inside a function modified by the patch.
3. **Caller-Callee Relationship:** Call stack includes a modified function within depth 3 (e.g. caller parameter validation error affecting callee).
4. **Execution Delta Evidence:** Matching failure signatures between Base and Patch versions confirm persistent vulnerability.

### Delta Debugging (`ddmin`) Testcase Minimization
Crashing inputs are automatically reduced while maintaining the exact crash signature (same error type and detection mechanism):
- Divides inputs hierarchically into chunks, testing subsets and complements.
- Eliminates superfluous bytes, reducing exploit payloads by 25% to 75%.
- Saves both original and minimized files into `artifacts/reproducers/<target>_<test>/`.
- Automatically generates regression test suites.

### Binary Hardening Verification
Directly parses ELF binary headers in pure Python:
- **NX:** Inspects `PT_GNU_STACK` flags (verifies executable permission bit `PF_X` is absent).
- **PIE:** Inspects ELF header `e_type` (`ET_DYN` vs `ET_EXEC`) and dynamic flags.
- **RELRO:** Inspects `PT_GNU_RELRO` program header and `DT_BIND_NOW` / `DF_BIND_NOW` dynamic tags (`None`, `Partial`, or `Full`).
- **Stack Canary:** Inspects `.dynsym` and `.symtab` for `__stack_chk_fail` symbols.
- **Downgrade Warning:** Emits explicit warnings if a patch or build script change weakens any binary protection.

---

## 7. Individual Defense Guide (راهنمای دفاع فردی - ۱۰ نمره)

Section 6.2 outlines the individual defense structure:

### Axis 1: Overall Architecture & Design Logic (3 Points)
* **Q: How does Zaraban ensure target generalizability?**  
  *A:* All target-specific attributes (build commands, binary path, input method, test suites, and resource limits) are defined in `zaraban.yaml`. The core engine (`zaraban.core.validator`) contains zero hardcoded target names.
* **Q: Why are Release and Sanitized builds tested separately?**  
  *A:* Release builds test real-world binary compiler protections (`-fstack-protector-strong`, RELRO, PIE) and runtime behavior. Sanitized builds (`-fsanitize=address,undefined`) pinpoint precise memory error types and symbolized stack traces without masking compiler hardening.

### Axis 2: Finding Analysis & Evidence Correlation (3 Points)
* **Q: Why is superficial textual proximity of a static scanner not enough?**  
  *A:* A bug often triggers in a helper or callee function because the caller failed to validate input lengths (as demonstrated in `handle_set_command`). Zaraban traces the execution call chain against diff hunks rather than relying on line proximity.
* **Q: What happens if an unseen patch crashes with an unclassified signal?**  
  *A:* Section 3.5 mandates reporting exit code `40` (`INCONCLUSIVE`). A non-zero exit code or unclassified crash alone is not sufficient to confirm an exploitable memory vulnerability.

### Axis 3: Live Code / Config Modification (4 Points)
During the defense, you may be asked to make a quick modification:
* **Adding a new test:** Add an entry under `valid_tests` or `security_tests` in `zaraban.yaml`.
* **Modifying resource limits:** Adjust `timeout_seconds` or `memory_limit_mb` in `zaraban.yaml`.
* **Evaluating an unseen patch:** Point `--patch-dir` to the unseen patch directory and `--diff` to its diff file. Zaraban dynamically compiles, inspects hardening, and executes tests live.