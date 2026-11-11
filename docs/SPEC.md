# Zaraban Tool Specification

This document defines what Zaraban does, what it takes as input, and what it
produces. It is the single reference for the team and for anyone (human or
agent) implementing the tool.

The course specification is [`project1_spec.pdf`](project1_spec.pdf). This
document cites it as "the spec", with section numbers such as §3.1.

> **Status:** draft, written section by section on branch `docs/spec`.
> Sections marked *(to be written)* are not decided yet.

Where a section changes something that exists in the current code, it says so
under **Change from current code**. "Current code" means the `main` branch plus
the `feat/complete-zaraban-engine` branch, as of commit `fe43c75`.

---

## 1. Terms

These words have one fixed meaning throughout this document.

| Term | Meaning |
|---|---|
| **Target** | A C/C++ program under test, described by one config file (`zaraban.yaml`). Example: `token_parser`, `cjson`. |
| **Base** | The version of the target before the patch. Expected to contain the vulnerability. |
| **Patch** | The version of the target after the patch. The tool decides whether this version is acceptable. |
| **Diff** | The textual difference between base and patch (unified diff format). Used to link findings to changed code. |
| **Profile** | One of two ways to build a version: `release` (normal optimized build with the project's own hardening flags) or `sanitized` (built with AddressSanitizer and UndefinedBehaviorSanitizer). |
| **Build** | One version built with one profile. There are always exactly four builds: `base-release`, `base-sanitized`, `patch-release`, `patch-sanitized`. |
| **Test** | One input to the target, plus the behavior we expect from it (its oracle). Each test has a kind: `valid`, `boundary`, `invalid`, `security`, or `regression`. |
| **Oracle** | The expected behavior of a test (expected exit code and/or expected output), defined independently of the patched version (§2 of the spec). |
| **Run** | One execution of one test on one build. |
| **Repeat** | Each test is run several times on each build (default 3) to detect unstable results. |
| **Signature** | A short identifier of a crash: error type plus the top three functions of the stack trace, for example `STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main`. |
| **Finding** | One reportable problem, built from one or more tests. Defined in §8 *(to be written)*. |

---

## 2. What the tool does

Zaraban answers the two questions in §1 of the spec by **running** the target,
not by reading its source:

- Does the vulnerability that exists in the base version still occur in the
  patched version, within the tests we run?
- Does the patched version keep the correct behavior on valid inputs?

One invocation of the tool validates **one patch** of **one target**. It goes
through these steps, in this order:

1. **Load the config** of the target and validate it.
2. **Prepare two source trees**, base and patch, and obtain the diff between
   them.
3. **Build** the four builds, each in its own separate directory.
4. **Check binary hardening** (NX, PIE, RELRO, stack canary) on the two release
   builds and compare them.
5. **Run every test on every build**, several times each, under the same
   limits and environment.
6. **Analyse each run**: how the program ended, and if it crashed, what kind of
   error it was, what detected it, and where it happened.
7. **Build findings** by comparing each test's behavior on base and patch.
8. **Link each finding to the diff**, using stack traces and the comparison of
   the two versions, or report the link as undetermined.
9. **For each confirmed crash**, minimize the input, create a reproducer bundle,
   replay it at least three times, and add a regression test.
10. **Write the reports** (human-readable summary and JSON) and **exit** with
    the status code defined by §3.5 of the spec.

The rest of this document defines each step.

---

## 3. Command-line interface

### 3.1 Invocation

The tool keeps the current entry point:

```bash
python -m zaraban.cli -c <config> --patch <patch> [options]
```

| Option | Required | Default | Meaning |
|---|---|---|---|
| `-c`, `--config` | yes | | Path to the target's `zaraban.yaml`. |
| `--patch` | yes, except with `--check-config` | | The patched version. See §3.2 for accepted forms. |
| `--base` | no | `base_dir` from the config | The base version. See §3.2. |
| `--out` | no | `out/` | Directory where all outputs of this run are written (§ outputs, *to be written*). |
| `--repeats` | no | `repeats` from the config (3) | How many times each test runs on each build. |
| `--no-promote` | no | off | Do not copy new regression tests into the target's `tests/regression/` directory. They are still written to the run's output directory. |
| `--keep-work` | no | off | Keep the temporary build directories after the run, for debugging. |
| `--check-config` | no | off | Only validate the config file and its referenced files, then exit with `0` (valid) or `30` (invalid). Nothing is built or run. |
| `-v`, `--verbose` | no | off | Print progress details. |
| `--version` | no | | Print the tool version and exit. |

The set of options is kept small on purpose. An option that can switch off a
required check (for example, skipping the release builds) could produce a
`PASS` that the spec would not accept, so no such option exists.

**Change from current code:**

- `--base-dir`, `--patch-dir` and `--diff` are replaced by `--base` and
  `--patch`, which accept several forms (§3.2). The diff is no longer a
  separate input; the tool derives it.
- `--report` and `--artifacts` are replaced by `--out`, so that all outputs of
  one run live in one directory.
- `--patch` is now required. Currently, base and patch both default to the
  config's own directory, so running the tool without arguments silently
  compares a version with itself.
- `--check-config`, `--repeats`, `--no-promote` and `--keep-work` are new.

### 3.2 Forms of `--patch` and `--base`

The patched version can be given in three forms. The tool decides the form
from the argument itself:

| Form | How it is recognized | What the tool does |
|---|---|---|
| **Diff file** | The argument is an existing file. | Copies the base tree and applies the diff to the copy with `git apply`. |
| **Directory** | The argument is an existing directory. | Uses the directory as the complete patched source tree. It must have the same layout as the base (Makefile, `src/`, and so on). |
| **Git revision** | Neither a file nor a directory. | Treats the argument as a commit, branch or tag of the repository that contains `base_dir`, and extracts the `base_dir` subtree at that revision (with `git archive`). |

`--base` accepts the **directory** and **git revision** forms. A diff file is
not accepted for `--base`, because a diff has nothing to apply to.

Rules for diff files:

- The format is unified diff, as produced by `git diff`, `diff -u`, or
  `git format-patch`. A diff may change, add, delete or rename several files.
- The diff is applied strictly (`git apply` with no fuzz). If it does not apply
  cleanly, the run stops with exit code `30`.
- The path prefix depth differs between tools (for example `a/src/main.c`
  versus `targets/target1_sample/src/main.c`). The tool tries strip levels
  `-p0` to `-p4` with `git apply --check` and uses the first that applies. The
  chosen level is recorded in the report.

Why accept all three forms: at the defense session, unseen patches are given
to us through an agreed interface (§4 of the spec), most likely as diff files
or commits. In CI, the natural input is a pair of commits. For the delivered
scenarios, the repository stores both full version directories and diff files
(see the target layout, *to be written*), and both must give the same result.

The tool must never depend on the file name or identity of the patch. Its
verdict comes only from building and running the code (§4 of the spec).

**Change from current code:** currently the patch must be a complete directory
that contains its own copy of the Makefile, and the diff is either a separate
`--diff` argument or computed with `diff -u -r` over the whole directory,
including build outputs.

### 3.3 Rules that apply to every run

- **Relative paths.** Paths inside the config are relative to the directory
  that contains the config file. Paths given on the command line are relative
  to the current working directory.
- **Trusted inputs.** The config file and all test files are always read from
  the location given by `-c`, never from the patched tree. A patch that edits
  `zaraban.yaml` or files under `tests/` is still applied to the patched source
  tree, but those edits do not change which tests run or what they expect.
  Otherwise a patch could delete its own failing test and pass.
- **Diff source.** If `--patch` is a diff file, that file is the diff. Otherwise
  the tool computes the diff with `git diff --no-index` between the two clean
  source trees, before anything is built, so build outputs never appear in it.
- **Separate build directories.** Each of the four builds is made in its own
  fresh copy of its source tree, under a temporary work directory. Nothing is
  ever built inside the repository, and no `clean` step is needed between
  builds.
- **Clean environment.** The target runs with a minimal environment: `PATH`,
  plus the variables set in the config's `env`, plus the sanitizer options
  set by the tool. Variables from the user's shell are not passed through.
  This makes all four builds run under identical conditions and makes
  reproducer bundles exact.
- **Argument errors.** Invalid command-line arguments exit with code `30`
  (`BUILD_OR_CONFIG_ERROR`), not with Python's default code `2`.

**Change from current code:** currently the tool builds inside the target's own
directory, runs `make clean` between builds (which deletes the patched release
binary before it is ever tested), passes the whole host environment to the
target, and exits with code `2` on argument errors.

### 3.4 Examples

Validate a delivered scenario, giving the patch as a diff file:

```bash
python -m zaraban.cli -c targets/target1_sample/zaraban.yaml \
  --patch targets/target1_sample/patches/incomplete.patch
```

The same scenario, giving the patch as a full directory. The result must be
identical. (This requires the version directory to be a complete tree with
its own Makefile. On `main` today, `versions/patch_*` contain only `src/`;
the target layout section will fix this.)

```bash
python -m zaraban.cli -c targets/target1_sample/zaraban.yaml \
  --patch targets/target1_sample/versions/patch_incomplete
```

In CI, compare the previous commit with the current one:

```bash
python -m zaraban.cli -c targets/target2_cjson/zaraban.yaml \
  --base "$BASE_SHA" --patch "$HEAD_SHA"
```

Check a config after editing it, without building anything:

```bash
python -m zaraban.cli -c targets/target2_cjson/zaraban.yaml --check-config
```

---

## 4. Target config file (`zaraban.yaml`)

### 4.1 What the config describes

The config describes **one target**: how to build it, how to run it, which
tests to run, and what each test is expected to do. It does **not** say which
patch to validate; that comes from the command line (§3), because a new patch
arrives on every CI run and at the defense session.

Adding a new target requires only a new config file and the target's own
files (sources, Makefile, tests). No tool code changes (§2 of the spec).

The file is YAML. All paths in it are relative to the directory that contains
the config file.

### 4.2 Top-level fields

| Field | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `name` | string | yes | | Target name. Used in output paths, so it may contain only letters, digits, `_` and `-`. |
| `base_dir` | path | no | `.` | The default base source tree, used when `--base` is not given. It is the directory that contains the target's Makefile and sources. |
| `input_method` | `file` \| `stdin` \| `args` | no | `stdin` | How each test's input reaches the program (§5). |
| `file_arg_placeholder` | string | no | `{input_file}` | Placeholder that is replaced by the input file path inside a test's `args` (§5). |
| `repeats` | integer ≥ 1 | no | `3` | How many times each test runs on each build (§7). |
| `env` | map of string → string | no | `{}` | Extra environment variables for the target program. The same values are used for all four builds. |
| `regression_dir` | path | no | `tests/regression` | Directory of automatically generated regression tests (§10). |
| `build` | object | yes | | How to build the target (§4.3). |
| `limits` | object | no | see §4.3 | Time and memory limits for each run (§4.3). |
| `valid_tests` | list of tests | yes, at least one | | Valid inputs with their expected behavior. |
| `boundary_tests` | list of tests | no | `[]` | Valid inputs at the edges of what the program accepts. |
| `invalid_tests` | list of tests | no | `[]` | Malformed or unacceptable inputs. The program must handle them without crashing. |
| `security_tests` | list of tests | yes, at least one | | Inputs that trigger the vulnerability in the base version. |

The meaning of each test kind, and how results are judged, is defined in §5.

### 4.3 `build` and `limits`

| Field | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `build.binary_path` | path | yes | | Path of the program after building, relative to the root of the source tree. |
| `build.release_cmd` | string | yes | | Shell command that produces the release build, run in the root of a fresh copy of the source tree. |
| `build.sanitized_cmd` | string | yes | | Shell command that produces a build with AddressSanitizer and UndefinedBehaviorSanitizer. The tool verifies afterwards that both sanitizers are really present in the binary (§6). |
| `build.clean_cmd` | string | no | none | Run before building. Normally unnecessary, because each build starts from a fresh copy. |
| `limits.timeout_seconds` | number > 0 | no | `3.0` | Wall-clock limit for one run. |
| `limits.memory_limit_mb` | integer > 0 | no | `256` | Memory limit for one run. How it is enforced for each profile is defined in §7. |

The build commands should call the **target's own build script** (for example
`make release`), not repeat compiler flags in the config. The release flags
then come from the source tree being built, so if a patch changes the build
script and weakens a protection, the hardening check (§11) can detect it, as
§3.4 of the spec requires.

### 4.4 Test fields

Every entry in `valid_tests`, `boundary_tests`, `invalid_tests` and
`security_tests` has the same fields:

| Field | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `name` | string | yes | | Unique across all test lists, including generated regression tests. Letters, digits, `_` and `-` only, because it is used in output paths. |
| `description` | string | no | none | What the test checks, and where its expected behavior comes from. |
| `input_file` | path | no | none | File whose bytes are the test input. |
| `input_data` | string | no | none | Inline test input, encoded as UTF-8. Only for short text inputs; binary inputs must use `input_file`. |
| `args` | list of strings | no | `[]` | Extra command-line arguments. May contain the placeholder (§5). |
| `expected_exit_code` | integer | no | not checked | Exit code the program must return. |
| `expected_output` | string | no | not checked | Expected standard output, compared according to `output_match`. |
| `output_match` | `contains` \| `exact` \| `regex` | no | `contains` | How `expected_output` is compared with the real output (§5). |

A test has at most one of `input_file` and `input_data`.

### 4.5 Validation

The config is validated at the start of every run and by `--check-config`.
Validation is strict: any problem stops the run with exit code `30` before
anything is built. All problems found are reported together, not only the
first one.

The following are errors:

- A key that is not defined in this section, at any level. This catches typos
  such as `expected_exitcode`, which would otherwise be silently ignored.
- The removed keys `patch_dir` and `diff_file`. The error message tells the
  user to use `--patch` instead.
- A missing required field, or a value of the wrong type or out of range.
- Two tests with the same `name`, or a name with characters other than
  letters, digits, `_` and `-`.
- A referenced file (`input_file`, `base_dir`) that does not exist.
- A test that has both `input_file` and `input_data`.
- With `input_method: file`, a test with neither `input_file` nor
  `input_data`.
- An `expected_output` with `output_match: regex` that is not a valid regular
  expression.
- No `valid_tests` or no `security_tests`. Without them, the tool cannot detect
  functional regressions or reproduce the base vulnerability.

A config with no `invalid_tests` is accepted, but produces a warning, because
§3.2 of the spec requires the team to design invalid inputs.

### 4.6 Example

The config of the `token_parser` target in this format, shortened: some of
the current file's tests and its `clean_cmd` are left out to keep the example
readable. What is new compared with the current file is `invalid_tests` and
the exact match on `valid_set`.

```yaml
name: "token_parser"
input_method: "file"

build:
  binary_path: "token_parser"
  release_cmd: "make release"
  sanitized_cmd: "make sanitized"

limits:
  timeout_seconds: 2.0
  memory_limit_mb: 128

valid_tests:
  - name: "valid_ping"
    input_file: "tests/valid/valid_1_ping.txt"
    expected_exit_code: 0
    expected_output: "PONG"
  - name: "valid_set"
    input_file: "tests/valid/valid_3_set.txt"
    expected_exit_code: 0
    expected_output: |
      OK: name=alice (value length: 5)
      OK: role=engineer (value length: 8)
    output_match: exact

boundary_tests:
  - name: "boundary_max_safe"
    input_file: "tests/boundary/boundary_max_safe.txt"
    expected_exit_code: 0

invalid_tests:
  - name: "invalid_unknown_cmd"
    input_file: "tests/invalid/unknown_cmd.txt"
    expected_exit_code: 1
  - name: "invalid_set_no_equals"
    input_file: "tests/invalid/set_no_equals.txt"
    expected_exit_code: 1

security_tests:
  - name: "exploit_primary"
    input_file: "tests/exploits/exploit_primary.txt"
    description: "Stack buffer overflow via a 120-byte SET value"
  - name: "exploit_secondary"
    input_file: "tests/exploits/exploit_secondary.txt"
    description: "82-byte SET value; passes the incomplete patch's 100-byte check"
```

The two files under `tests/invalid/` do not exist yet and must be added.

### 4.7 Change from current code

Both existing config files (`token_parser` and Erfan's `cjson`) remain valid
without edits. The differences are in what the fields mean and how strictly
they are checked:

| Field or behavior | Current code | This spec |
|---|---|---|
| Validation | Values are read with defaults; unknown keys and typos are silently ignored. `pydantic` is installed but not used. | Strict validation, all errors reported, exit code `30`. |
| `patch_dir`, `diff_file` | Accepted, but always overridden by command-line arguments. | Removed; an error if present. |
| `base_dir` | Default `"base"`, a directory that does not exist in our targets. | Default `"."`. |
| `file_arg_placeholder` | Parsed, never used; the input path is always appended to the command. | Applied as defined in §5. |
| `expected_exit_code` | Default `0`, and never checked. | Default "not checked", and checked when given. |
| `expected_output` | Substring match only. | Substring by default; `exact` and `regex` through `output_match`. |
| `invalid_tests` | Not supported. | New. |
| `repeats`, `env`, `regression_dir` | Not supported. | New, all optional. |

The default of `expected_exit_code` changes because a correct patch often
rejects an exploit input with a non-zero exit code. With a default of `0`,
checking exit codes would wrongly report that as a regression.

---

## 5. Test inputs and oracles

### 5.1 Test kinds

Section 3.2 of the spec asks for valid, boundary and invalid inputs, and §4
asks for inputs that trigger the vulnerability. Each kind has one purpose:

| Kind | Config list | Purpose |
|---|---|---|
| `valid` | `valid_tests` | Normal inputs. Detect functional regressions. |
| `boundary` | `boundary_tests` | Valid inputs at the edges of what the program accepts (empty input, maximum safe length, and so on). Detect off-by-one fixes and over-strict checks. |
| `invalid` | `invalid_tests` | Malformed or unacceptable inputs. The program must reject them without crashing. Detect new crashes on error paths. |
| `security` | `security_tests` | Inputs that trigger the vulnerability in the base version, including the alternative input that bypasses the incomplete patch (§4 of the spec). |
| `regression` | generated files in `regression_dir` | Minimized crashing inputs found by earlier runs (§10). Never written by hand. |

### 5.2 Input data

- **`input_file`**: the file's bytes are given to the program exactly as they
  are. Nothing is added, removed or re-encoded; no newline is appended.
  Files live under `tests/<kind>/` (`tests/exploits/` for security tests).
  The extension is free (`.txt`, `.json`, `.bin`). The maximum size is 1 MB.
- **`input_data`**: the string from the config, encoded as UTF-8. Intended for
  short text inputs only.
- **No input**: allowed with `input_method: stdin` (the program gets an empty
  standard input) and with `input_method: args` (only the test's `args` are
  passed).

### 5.3 How the input reaches the program

Each run happens in its own empty run directory, which is also the program's
working directory. The command is always the build's binary followed by the
test's `args`, with the input added according to `input_method`:

| `input_method` | What the tool does |
|---|---|
| `file` | Writes the input to a file named `input` plus the original extension (for example `input.txt`) in the run directory. If the test's `args` contain the placeholder (`{input_file}` by default), the placeholder is replaced by this file's path. Otherwise the path is added as the last argument. |
| `stdin` | Writes the input to the program's standard input, then closes it, so the program sees end-of-file. |
| `args` | Adds the input as one extra argument after the test's `args`. An input that contains a NUL byte cannot be passed this way and is a config error (exit code `30`). |

The input file always has the same name and relative path, for all four
builds and all repeats. A difference in path length could otherwise change
memory layout and crash behavior between builds.

Example: with `input_method: file`, `args: []` and
`input_file: tests/exploits/exploit_primary.txt`, the command is
`<binary> input.txt`, run inside the run directory.

### 5.4 Oracle matching

A run **matches its oracle** when all of the following hold:

1. The program ended normally: no crash, no timeout, no resource limit hit.
2. If `expected_exit_code` is given, the exit code equals it.
3. If `expected_output` is given, standard output matches it according to
   `output_match`:

| `output_match` | Rule |
|---|---|
| `contains` | The UTF-8 bytes of `expected_output` appear somewhere in standard output. |
| `exact` | Standard output is byte-for-byte equal to the UTF-8 bytes of `expected_output`, including spaces and newlines. |
| `regex` | Python `re.search` with the `MULTILINE` flag finds the pattern in standard output, decoded as UTF-8 (invalid bytes replaced). |

Standard error is not compared. It is stored with every run (§12) and used to
analyse crashes (§7).

YAML note for `exact`: a block written with `|` keeps the final newline, and
`|-` removes it. Most programs end their output with a newline, so `|` is
usually right.

```yaml
expected_output: |
  OK: name=alice (value length: 5)
  OK: role=engineer (value length: 8)
output_match: exact
```

### 5.5 Expected behavior of each kind

This table defines what each kind must do on each version. What the tool
reports when a test does not behave as expected is defined in §8.

| Kind | On base | On patch |
|---|---|---|
| `valid`, `boundary` | Must match the oracle. If it does not, the test or its oracle is wrong, and no judgement about the patch can be made from this test. | Must match the oracle. |
| `invalid` | Must not crash. If the oracle gives an exit code or output, must match it. | Same as base. |
| `security` | **Must crash.** This is how the tool shows the vulnerability is reproduced. | Must not crash. If the oracle gives an exit code or output (for example, "rejects the input with exit code 1"), must match it. |
| `regression` | Must show the crash signature stored with the test (§10). | Must not show that signature, and must not crash. |

For `security` tests, the oracle fields describe the expected behavior of the
patched version only. On base, the test is expected to crash, so the oracle is
not checked there.

### 5.6 Where oracles come from

Section 2 of the spec says the expected behavior must be defined before
evaluation, from the program's documentation or from independent reference
tests, and approved by the instructor. The output of the patched version, or
the opinion of a language model, is not a valid source on its own.

So each target has a file `ORACLE.md` next to its config. For every test it
states the expected behavior and its source. For example, for the cJSON
target (`invalid_truncated` is a test still to be written):

| Test | Expected behavior | Source |
|---|---|---|
| `valid_rfc7386` | Prints `{"title":"Hello!",…}` and exits with `0`. | RFC 7386, §3 example |
| `valid_delete` | A key whose patch value is `null` is removed from the result. | RFC 7386, §2 |
| `invalid_truncated` | Prints an error and exits with `1`, without crashing. | `main.c` usage contract |

The tool does not read `ORACLE.md`. It exists for review, for the instructor's
approval, and for the defense.

### 5.7 Change from current code

| Behavior | Current code | This spec |
|---|---|---|
| Input path with `input_method: file` | The absolute path of the test file inside the base directory, always added as the last argument. | A fixed `input.<ext>` in the run directory; placeholder supported. |
| Input with `input_method: args` | Only `input_data` is passed; `input_file` is ignored. | Either is passed as one argument. |
| Working directory | The directory of the binary, which is shared by all runs of a build. | A fresh, empty directory for every run. |
| `expected_exit_code` | Never checked. | Checked when given. |
| `expected_output` | Stripped of surrounding whitespace, then searched as a substring. | Compared exactly as written, with three matching modes. |
| Oracle on security tests | Not supported. | Optional, checked on the patched version. |
| Invalid inputs and `ORACLE.md` | Do not exist. | Required for every target. |

---

## Sections still to be written

- 6. Builds
- 7. Runs and repeats
- 8. Findings
- 9. Linking findings to the patch
- 10. Minimization, reproducer bundles and regression tests
- 11. Binary hardening
- 12. Outputs and their formats
- 13. Status and exit codes
- 14. Repository layout and deliverables
