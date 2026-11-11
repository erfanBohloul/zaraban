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

## 6. Builds

### 6.1 The four builds

Section 3.2 of the spec requires the release build and the instrumented build
to be run and reported separately, and the comparison of base and patch to use
matching builds. So every run of the tool makes exactly four builds:

| Build | Version | Profile | Built with |
|---|---|---|---|
| `base-release` | base | release | `build.release_cmd` |
| `base-sanitized` | base | sanitized | `build.sanitized_cmd` |
| `patch-release` | patch | release | `build.release_cmd` |
| `patch-sanitized` | patch | sanitized | `build.sanitized_cmd` |

Base and patch are always built with the same commands and the same
environment. The only difference between `base-release` and `patch-release`
is the source tree, and likewise for the two sanitized builds.

### 6.2 Build procedure

The four builds run one after another, in the order of the table above. For
each build:

1. **Copy the source tree** (base or patch, prepared as in §3.2) into a fresh
   directory `work/<build>/`. The `.git` directory and any `out/` directory are
   not copied.
2. **Run `build.clean_cmd`**, if the config has one.
3. **Run the build command** with `sh -c`, in the root of the copy. The build
   environment is minimal and identical for all four builds: `PATH`, `HOME`,
   and `LANG=C`. Standard output and standard error go to `build.log`. A build
   that takes longer than 300 seconds is stopped and counts as failed.
4. **Check the result.** The build fails if the command exits with a non-zero
   code, or if `build.binary_path` does not exist afterwards, or if it is not an
   x86-64 ELF executable (§2 of the spec).
5. **Copy the binary** to the run's output directory,
   `builds/<build>/bin/<name>`, and compute its SHA-256 hash. All runs use
   this copy, so the hash in the report is the hash of the binary that was
   actually run.
6. **Verify the profile** (§6.3).

If any build fails, the tool records the failure (`BUILD_FAILED`, with the
path of `build.log`), skips all remaining steps, writes the report, and exits
with code `30`. Tests are never run on an incomplete set of builds.

### 6.3 Profile verification

A build command can silently produce the wrong kind of binary, for example
when a patch edits the Makefile, or when the compiler adds flags by default.
The tool therefore checks every binary after building it, by reading its
symbol tables:

| Check | Applies to | If it fails |
|---|---|---|
| The binary contains the AddressSanitizer runtime (`__asan_init`). | sanitized builds | Error `SANITIZER_MISSING`, exit code `30`. |
| The binary contains UndefinedBehaviorSanitizer handlers (`__ubsan_handle_*`). | sanitized builds | Error `SANITIZER_MISSING`, exit code `30`. |
| The binary does **not** contain the AddressSanitizer runtime. | release builds | Error `PROFILE_MIXED`, exit code `30`. The release build must show the real behavior of the program (§3.2 of the spec). |
| The binary has debug information (a `.debug_info` section). | sanitized builds | Warning `NO_DEBUG_INFO`. Stack traces will have function names but no file and line, so links to the diff may be undetermined (§9). |
| The binary does not call `_FORTIFY_SOURCE` checking functions (`__*_chk`). | sanitized builds | Warning `FORTIFY_IN_SANITIZED`. Fortify checks can stop the program before AddressSanitizer reports the error, so the error type would be less precise. |

The last check comes from a real case: Ubuntu's GCC enables
`_FORTIFY_SOURCE` by default, and a "sanitized" build of `token_parser` made
with it reported a fortify abort instead of an AddressSanitizer stack buffer
overflow. Our targets build the sanitized profile with clang, which does not do
this.

### 6.4 What is recorded

For each build, the tool records the command, the environment, the working
directory, the compiler and its version, the exit code, the duration, the
path of `build.log`, and the binary's path, size and SHA-256 hash. The
compiler version is taken from the output of `gcc --version` and
`clang --version` in the build environment. The exact file format is defined
in §12.

This information is required for the reproducer bundles (§3.3 of the spec:
"build settings" and "binary hash").

### 6.5 Change from current code

| Behavior | Current code | This spec |
|---|---|---|
| Where builds happen | Inside the target's own directory in the repository. | In fresh copies under a temporary work directory. |
| Separation of builds | Release and sanitized builds overwrite the same binary, with `make clean` in between. The patched release binary is built, checked for hardening, then deleted before any test runs on it. | Four separate directories and four kept binaries. |
| Build environment | The whole host environment. | A minimal, identical environment. |
| Build log | Kept only when the build fails, inside the error message. | Always kept in `build.log`. |
| Profile verification | None. | Sanitizers present in sanitized builds, absent in release builds. |
| Binary hash | Only for binaries that get a reproducer bundle. | For all four builds. |

---

## 7. Runs and repeats

### 7.1 What is run

Every test runs on every build, `repeats` times (default 3). This includes all
kinds: valid, boundary, invalid, security and regression tests. Section 3.1 of
the spec requires every input to run on both versions with matching settings,
and §3.2 requires the release and sanitized builds to be run separately.

Runs happen one at a time, in a fixed order: tests in config order (valid,
boundary, invalid, security, then regression), and for each test the four
builds in the order of §6.1, and for each build repeats 1 to N. Running one at
a time keeps timing stable, which matters for timeouts.

For example, a target with 10 tests and 3 repeats needs 10 × 4 × 3 = 120
runs. Our targets run in a few milliseconds each, so this takes seconds.

### 7.2 Run environment

Each run uses:

- a **fresh, empty working directory**, containing only the input file when
  `input_method` is `file` (§5.3);
- the **command** defined in §5.3;
- **standard input** as defined in §5.3, or an empty, closed standard input;
- the **environment**: `PATH`, the config's `env`, and, for sanitized builds
  only, the sanitizer options below. Nothing else from the host.

Sanitizer options, identical for `base-sanitized` and `patch-sanitized`:

```
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=1:disable_coredump=1:hard_rss_limit_mb=<limit>:max_allocation_size_mb=<limit>
UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1:symbolize=1
ASAN_SYMBOLIZER_PATH=<path of llvm-symbolizer>
```

- `abort_on_error=1` makes every sanitizer report end the program with
  `SIGABRT`, so a reported error always terminates the run.
- `halt_on_error=1` makes UndefinedBehaviorSanitizer stop at the first error
  instead of printing it and continuing.
- `detect_leaks=0`: memory leaks are not treated as crashes. A leak report
  appears only at exit and would turn every run of a leaky program into a
  failure, unrelated to the patch.
- If the config's `env` sets `ASAN_OPTIONS` or `UBSAN_OPTIONS`, the tool's
  options are appended after the config's, so the tool's values win.
- If `llvm-symbolizer` is not found, the tool still runs, but stack traces have
  no function names. It records the warning `NO_SYMBOLIZER`.

### 7.3 Limits

| Limit | How it is enforced | Outcome when hit |
|---|---|---|
| Wall-clock time (`timeout_seconds`) | The tool kills the program's whole process group with `SIGKILL` when the time is up. | `TIMEOUT` |
| CPU time | `RLIMIT_CPU` set to `timeout_seconds` rounded up, plus 1 second. The kernel sends `SIGXCPU`. | `RESOURCE_LIMIT` (cpu) |
| Memory, release builds | `RLIMIT_AS` set to `memory_limit_mb`. | `RESOURCE_LIMIT` (memory), when the program ends abnormally and its peak memory reached at least 90% of the limit |
| Memory, sanitized builds | `RLIMIT_AS` cannot be used, because AddressSanitizer reserves terabytes of virtual address space. The tool sets `hard_rss_limit_mb` and `max_allocation_size_mb` instead. | `RESOURCE_LIMIT` (memory), when AddressSanitizer reports an exhausted RSS limit or a too-large allocation |
| Output | Standard output and standard error are each stored up to 1 MB. The rest is read and discarded, so the program never blocks on a full pipe. | Not a failure. The run is marked truncated, with the warning `OUTPUT_TRUNCATED`. |
| Core dumps | `RLIMIT_CORE` set to 0. | |

Each program runs in its own process group (`setsid`), so child processes are
killed with it. Peak memory use is read from the kernel's resource usage
(`wait4`).

Section 3.2 of the spec says that exceeding a time or resource limit must be
reported separately, because not every stop is an exploitable vulnerability.
That is why `TIMEOUT` and `RESOURCE_LIMIT` are separate outcomes and never
count as `CRASH`.

### 7.4 Analysing a run

After each run, the tool decides the **outcome** from the termination status
and standard error. The rules are applied in this order, and the first that
matches wins:

| # | Condition | Outcome | Detection |
|---|---|---|---|
| 1 | The tool killed the program for exceeding the wall-clock limit. | `TIMEOUT` | |
| 2 | `SIGXCPU`, or a memory-limit condition from §7.3. | `RESOURCE_LIMIT` | |
| 3 | Standard error contains an AddressSanitizer report (`ERROR: AddressSanitizer`). | `CRASH` | `ASAN` |
| 4 | Standard error contains an UndefinedBehaviorSanitizer report (`runtime error:`) and the program was stopped. | `CRASH` | `UBSAN` |
| 5 | Standard error contains `*** stack smashing detected ***`. | `CRASH` | `STACK_CANARY` |
| 6 | Standard error contains `*** buffer overflow detected ***`. | `CRASH` | `FORTIFY` |
| 7 | Standard error contains a glibc allocator check (`double free detected`, `free(): invalid pointer`, `malloc(): corrupted`, and similar). | `CRASH` | `ALLOCATOR_CHECK` |
| 8 | The program was killed by `SIGSEGV`, `SIGBUS`, `SIGFPE`, `SIGILL`, `SIGABRT` or `SIGTRAP`. | `CRASH` | `SIGNAL` |
| 9 | Anything else, with any exit code. | `NORMAL` | |

A non-zero exit code alone is never a crash (§3.3 of the spec). Whether it is
correct is decided by the oracle (§5.4).

For a `CRASH`, the tool also records the **error type**:

| Error type | Determined from |
|---|---|
| `STACK_BUFFER_OVERFLOW` | ASan `stack-buffer-overflow` or `dynamic-stack-buffer-overflow`; a stack canary abort |
| `HEAP_BUFFER_OVERFLOW` | ASan `heap-buffer-overflow` |
| `GLOBAL_BUFFER_OVERFLOW` | ASan `global-buffer-overflow` |
| `BUFFER_OVERFLOW` | A fortify abort (the kind of buffer is not known) |
| `USE_AFTER_FREE` | ASan `heap-use-after-free` |
| `USE_AFTER_SCOPE` | ASan `stack-use-after-scope` or `stack-use-after-return` |
| `DOUBLE_FREE` | ASan `attempting double-free`; glibc `double free detected` |
| `INVALID_FREE` | ASan `attempting free on address which was not malloc()-ed`; glibc `free(): invalid pointer` |
| `NULL_DEREF` | ASan `SEGV` on an address in the zero page; UBSan `null pointer` |
| `SEGV` | ASan `SEGV` on another address; `SIGSEGV` or `SIGBUS` without a sanitizer report |
| `STACK_EXHAUSTION` | ASan `stack-overflow` (unbounded recursion) |
| `DIV_BY_ZERO` | UBSan `division by zero`; `SIGFPE` |
| `INTEGER_OVERFLOW` | UBSan `signed integer overflow` |
| `OUT_OF_BOUNDS_INDEX` | UBSan `index out of bounds` |
| `UB_OTHER` | Any other UBSan report |
| `HEAP_CORRUPTION` | Other glibc allocator checks |
| `ABORT` | `SIGABRT` with none of the above |
| `UNKNOWN` | Any other crash |

The spec notes that this classification is not a root-cause analysis (§3.2).
It records what the detection mechanism observed.

For sanitizer crashes, the tool also parses the **stack trace**: one frame per
line of the form `#N 0xADDR in function file:line:column`. All frames are
recorded. Frames inside the sanitizer runtime or the C library (functions
starting with `__asan_`, `__interceptor_`, `__sanitizer_`, `__ubsan_`, or
frames located in `libasan`, `libubsan` or `libc`) are marked as runtime
frames.

The **signature** of the crash is the error type plus the names of the first
three frames that are not runtime frames, for example
`STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main`. If no
frame has a function name (no symbolizer, or a release build without a stack
trace), the crash has **no signature**. Line numbers are not part of the
signature, because they change between base and patch. How signatures are used
is defined in §8.

### 7.5 Combining repeats

For each test on each build, the repeats are combined into one **result**:

- The result is **stable** when all repeats have the same outcome, the same
  signature (for crashes), and the same oracle result. The values of the
  result are those of the first repeat.
- Otherwise the result is **flaky**. Every repeat is still stored, so the
  difference can be inspected. How a flaky result is reported is defined in §8.

With `repeats: 1`, flaky results cannot be detected. The tool accepts it, but
records the warning `REPEATS_TOO_LOW`.

### 7.6 Change from current code

| Behavior | Current code | This spec |
|---|---|---|
| Which tests run on which builds | Security tests on base release, base sanitized and patch sanitized. Valid and boundary tests on base and patch sanitized only. Nothing runs on the patched release build. | Every test on all four builds. |
| Repeats | One run per test. | `repeats` runs per test per build. |
| Environment | The whole host environment. | Minimal and identical. |
| Memory limit, release builds | `RLIMIT_DATA` | `RLIMIT_AS`, which also covers memory obtained with `mmap`. |
| Memory limit, sanitized builds | `max_allocation_size_mb` only. | Also `hard_rss_limit_mb`. |
| Output size | Unlimited, kept in memory. | 1 MB per stream. |
| Timeouts | Counted as crashes (`is_crash` is true). | A separate outcome. |
| `*** buffer overflow detected ***` | Reported as a stack canary. | Reported as fortify. |
| `*** stack smashing detected ***` | Not recognized. | Reported as a stack canary. |
| `SIGABRT` with "abort" in the output | Error type reported as stack canary corruption. | Reported as `ABORT`. |
| glibc allocator checks | Not recognized. | Recognized. |
| Signature | None; crashes are compared by signal and detection mechanism only. | Error type plus top three non-runtime functions. |

---

## 8. Findings

### 8.1 What a finding is

A **finding** is one reportable problem, found by comparing how the tests
behave on base and on patch. Every finding has one of the five categories of
§3.1 of the spec:

| Category | Meaning |
|---|---|
| `FIXED` | An error that occurs on base no longer occurs on patch, within the tests run. |
| `INCOMPLETE_FIX` | An error that occurs on base still occurs on patch. |
| `NEW_ISSUE` | An error occurs on patch that does not occur on base. |
| `FUNCTIONAL_REGRESSION` | A behavior that is correct on base is wrong on patch, without a crash. |
| `INCONCLUSIVE` | Something abnormal was observed, but the evidence is not enough to put it in another category. |

A finding can come from **several tests**. Crashes are grouped by signature
(§7.4), so that one error reached by several inputs is one finding. This
follows the spec's own description of an incomplete patch (§4): it blocks the
original input, but the same vulnerability still occurs with a different
input. Reporting the two inputs as one `FIXED` finding and one
`INCOMPLETE_FIX` finding would describe the same error as both fixed and not
fixed.

Findings that do not involve a crash, and crashes without a reliable
signature, are **one finding per test**, because there is no evidence that two
such tests show the same problem.

Findings are built from the combined results of §7.5: one result per test per
build.

### 8.2 Crash findings

Crash findings use the **sanitized** builds, because only they give an error
type and a stack trace reliable enough to compare.

1. Collect every signature that appears in a stable `CRASH` result on
   `base-sanitized` or `patch-sanitized`, from tests of any kind.
2. For each signature S, find:
   - **B**: the tests whose `base-sanitized` result is a crash with S;
   - **P**: the tests whose `patch-sanitized` result is a crash with S.
3. Create one finding for S:

| B | P | Category |
|---|---|---|
| not empty | empty | `FIXED` |
| not empty | not empty | `INCOMPLETE_FIX` |
| empty | not empty | `NEW_ISSUE` |

The finding lists every test in B and P, with that test's result on all four
builds, including the release builds. The release results are reported next to
the sanitized ones and never merged with them (§3.2 of the spec).

Consequences of these rules:

- **The worst case decides.** If even one test still reaches S on patch, the
  finding is `INCOMPLETE_FIX`. The tests that are blocked on patch are listed
  in the same finding, marked as blocked.
- **A test can be in two findings.** If a test crashes on base with S1 and on
  patch with a different S2, it appears in the finding for S1 (where it is no
  longer reaching S1) and in a `NEW_ISSUE` finding for S2.
- **Comparison is by signature, not by "both crashed".** Two crashes are the
  same error only if their error type and top three functions are equal.

### 8.3 Crashes without a signature

A crash has no signature when its stack trace has no function names (§7.4).
Such crashes are never grouped. For each test, using its sanitized results:

| Base | Patch | Finding |
|---|---|---|
| crash without signature | no crash | `FIXED`. The base crash is gone, and nothing on patch needs to be compared. |
| no crash | crash without signature, known error type | `NEW_ISSUE` |
| no crash | crash without signature, error type `ABORT` or `UNKNOWN` | `INCONCLUSIVE`: an unclassified stop is not enough evidence of a security error (§3.5 of the spec, code 40). |
| crash without signature | crash (with or without signature) | `INCONCLUSIVE`: there is no way to tell whether it is the same error. |

A test whose **release** build crashes while its sanitized build of the same
version does not gets an `INCONCLUSIVE` finding, with the release and
sanitized results side by side. The release build is the real program, so the
crash must be reported, but without a sanitizer report it cannot be
classified.

### 8.4 Functional findings

These use the oracle results of runs that did **not** crash. Crashes are
always handled by §8.2 and §8.3, so a crash on a valid input is a security
finding (`NEW_ISSUE`), never a functional one. For each test:

| Test kind | Condition | Finding |
|---|---|---|
| `valid`, `boundary`, `invalid` | Matches the oracle on both base builds, and does not match it on at least one patch build. | `FUNCTIONAL_REGRESSION` |
| `valid`, `boundary`, `invalid` | Does not match the oracle on a base build. | `INCONCLUSIVE`: the test or its oracle is wrong, so it cannot judge the patch. |
| `security` | Does not crash on patch, but does not match its oracle there. | `INCONCLUSIVE`: the patch avoids the crash but does not behave as expected. This is not a functional regression, because the base never had the expected behavior (§3.1 of the spec). |

A `TIMEOUT` or `RESOURCE_LIMIT` result counts as "does not match the oracle".
So a valid input that runs normally on base and hangs on patch is a
`FUNCTIONAL_REGRESSION`, with the termination recorded as `TIMEOUT`. It is
never a crash (§7.3).

A `TIMEOUT` or `RESOURCE_LIMIT` on patch for a `security` or `regression` test
gets an `INCONCLUSIVE` finding: the spec says that not every stop is an
exploitable vulnerability (§3.2).

### 8.5 Flaky results

If any build of a test has a flaky result (§7.5), that test gets one
`INCONCLUSIVE` finding that lists the flaky builds and the differing repeats.
Flaky crash results are **not** used to build crash findings, because a
signature that appears only in some repeats could be grouped wrongly.

### 8.6 What is not a finding

- A test that behaves as expected on both versions. Its results are still in
  the execution logs (§12).
- A `security` test that does **not** crash on base. This means the
  vulnerability was not reproduced. It is a status condition with code `40`,
  not a finding (§13).
- A `regression` test that does not crash on base. In CI, base is often a
  commit that already contains an earlier fix, so this is expected. It is
  recorded as the warning `REGRESSION_BASE_CLEAN`. The test still runs on
  patch, where a crash with its stored signature is an `INCOMPLETE_FIX`.

### 8.7 Nothing is lost

Grouping only changes how results are presented. It never removes one. To
guarantee this, the tool checks at the end of every run that each abnormal
result (a crash, an oracle mismatch, a timeout, a resource limit, or a flaky
result, on any build) is referenced by at least one finding or status
condition, and that each crash result with a signature is in exactly one
crash finding. If the check fails, it is a bug in the tool: the run exits with
code `30` and the error `TOOL_INTERNAL`.

The raw results of every run are kept in any case (§12), independent of how
findings are built.

### 8.8 Contents of a finding

Each finding records:

- an **id**: `F-001`, `F-002`, …, numbered in the order the findings are first
  observed in the run order of §7.1;
- the **category**;
- the **signature** and **error type**, or none for functional findings;
- the **tests**: for each, its kind, and its outcome, detection mechanism,
  signal or exit code, and oracle result on each of the four builds;
- a **release** and a **sanitized** summary: what was observed on base and on
  patch in each profile;
- the **link to the patch** (§9);
- the **evidence**: paths of the raw run files it is based on;
- the **reproducer bundle** and **regression test**, if one was made (§10);
- **notes**: a one-sentence explanation in plain words.

The exact JSON format is defined in §12.

### 8.9 Expected findings for the `token_parser` scenarios

| Patch | Findings | Exit code |
|---|---|---|
| correct | F-001 `FIXED` `STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main`, tests `exploit_primary` and `exploit_secondary`, both blocked on patch. | `0` |
| incomplete | F-001 `INCOMPLETE_FIX`, same signature: `exploit_primary` blocked on patch, `exploit_secondary` still crashing. | `10` |
| regression | F-001 `FIXED` as for the correct patch; F-002 `FUNCTIONAL_REGRESSION` for `valid_set`, which is rejected by the new key-length check. | `20` |

These expectations go into the target's `scenarios.yaml` (§14), so that the
scenario script checks the findings, not only the exit code.

### 8.10 Change from current code

| Behavior | Current code | This spec |
|---|---|---|
| Unit of a finding | One finding per test, for every test, including tests that behave normally on both versions (reported as `Fixed`). | One finding per crash signature, or per test for other problems. Normal tests produce no finding. |
| Same error on base and patch | Both crashed with the same signal and detection mechanism. | Same signature: same error type and same top three functions. |
| Different error on patch | Reported as `Incomplete Fix`. | A `NEW_ISSUE` finding for the new signature. |
| Crash on a valid input on patch | `Functional Regression` (code 20). | `NEW_ISSUE` (code 10). |
| Release results | Not part of findings. | Reported next to the sanitized results. |
| Base fails a valid test's oracle | Not detected. | `INCONCLUSIVE`. |
| Flaky results | Not detected (one run per test). | `INCONCLUSIVE`. |
| Completeness check | None. | Every abnormal result must be referenced. |

---

## Sections still to be written

- 9. Linking findings to the patch
- 10. Minimization, reproducer bundles and regression tests
- 11. Binary hardening
- 12. Outputs and their formats
- 13. Status and exit codes
- 14. Repository layout and deliverables
