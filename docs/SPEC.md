# Zaraban Tool Specification

This document defines what Zaraban does, what it takes as input, and what it
produces. It is the single reference for the team and for anyone (human or
agent) implementing the tool.

The course specification is [`project1_spec.pdf`](project1_spec.pdf). This
document cites it as "the spec", with section numbers such as §3.1.

> **Status:** version 1.

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
| **Bug key** | Error type plus the function and file of the first non-runtime frame (the crashing location), for example `STACK_BUFFER_OVERFLOW @ handle_set_command (src/main.c)`. Two crashes with the same bug key are the same bug, even when they were reached through different callers (§8.2). |
| **Finding** | One reportable problem, built from one or more tests. Defined in §8. |

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
| `--out` | no | `out/` | Directory where all outputs of this run are written (§12). |
| `--no-promote` | no | off | Do not copy new regression tests into the target's `tests/regression/` directory. They are still written to the run's output directory. |
| `--keep-work` | no | off | Keep the temporary build directories after the run, for debugging. |
| `--check-config` | no | off | Only validate the config file and its referenced files, then exit with `0` (valid) or `30` (invalid). Nothing is built or run. |
| `-v`, `--verbose` | no | off | Print progress details. |
| `--version` | no | | Print the tool version and exit. |

The set of options is kept small on purpose. An option that can switch off a
required check (for example, skipping the release builds) could produce a
`PASS` that the spec would not accept, so no such option exists.

### 3.2 Forms of `--patch` and `--base`

The patched version can be given in two forms. The tool decides the form from
the argument itself:

| Form | How it is recognized | What the tool does |
|---|---|---|
| **Diff file** | The argument is an existing file. | Copies the base tree and applies the diff to the copy with `git apply`. |
| **Directory** | The argument is an existing directory. | Uses the directory as the complete patched source tree. It must have the same layout as the base (Makefile, `src/`, and so on). |

`--base` must be a directory. A diff file is not accepted for `--base`,
because a diff has nothing to apply to.

A patch that exists as a git commit is given as a diff file, for example
`git diff <base commit> <patch commit> -- targets/<target> > change.patch`,
with the base commit checked out as the base directory.

Rules for diff files:

- The format is unified diff, as produced by `git diff`, `diff -u`, or
  `git format-patch`. A diff may change, add, delete or rename several files.
- The diff is applied strictly (`git apply` with no fuzz). If it does not apply
  cleanly, the run stops with exit code `30`.
- The path prefix depth differs between tools (for example `a/src/main.c`
  versus `targets/target1_sample/src/main.c`). The tool tries strip levels
  `-p0` to `-p4` with `git apply --check` and uses the level that changes or
  deletes files existing in the base. If two levels would patch different
  existing files, the diff is ambiguous and the run stops with exit code `30`
  rather than risk patching the wrong file. A diff that only adds files uses
  `-p1` when its paths have git's `a/` `b/` prefixes, otherwise the lowest
  level that applies. The chosen level is recorded in the report.
- When a diff does not apply, the error lists `git apply`'s reason for each
  strip level.

Why accept both forms: at the defense session, unseen patches are given to us
through an agreed interface (§4 of the spec), most likely as diff files. For
the delivered scenarios, the repository stores both full version directories
and diff files (§14.2), and both must give the same result.

The tool must never depend on the file name or identity of the patch. Its
verdict comes only from building and running the code (§4 of the spec).

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

### 3.4 Examples

Validate a delivered scenario, giving the patch as a diff file:

```bash
python -m zaraban.cli -c targets/target1_sample/zaraban.yaml \
  --patch targets/target1_sample/patches/incomplete.patch
```

The same scenario, giving the patch as a full directory. The result must be
identical. (This requires the version directory to be a complete tree with
its own Makefile. On `main` today, `versions/patch_*` contain only `src/`;
see §14.2.)

```bash
python -m zaraban.cli -c targets/target1_sample/zaraban.yaml \
  --patch targets/target1_sample/versions/patch_incomplete
```

Check a config after editing it, without building anything:

```bash
python -m zaraban.cli -c targets/cjson/zaraban.yaml --check-config
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
| `build.coverage_cmd` | string | no | none | Shell command that produces a coverage build for the execution trace (§9.4), for example `make coverage`. Without it, no execution trace is made, and links that would need one are `UNDETERMINED`. |
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
| `output_match` | `contains` \| `exact` | no | `contains` | How `expected_output` is compared with the real output (§5). |

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
| `regression` | Must crash with the signature stored with the test, or must not crash if the test was created from a new issue (§10.6). | Must not crash. |

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
2. **Run `build.clean_cmd`**, if the config has one. It is run like the build
   command (step 3), and if it fails or times out, the build fails.
3. **Run the build command** with `sh -c`, in the root of the copy. The build
   environment is minimal and identical for all four builds: `PATH`, `HOME`,
   and `LANG=C`. Standard output and standard error go to `build.log`. A build
   that takes longer than 300 seconds is stopped and counts as failed. Each
   command runs in its own process group, and the whole group is killed when
   it ends or is stopped, so no `make` or compiler process outlives its build.
4. **Check the result.** The build fails if the command exits with a non-zero
   code, or if `build.binary_path` does not exist afterwards, or if it is not an
   x86-64 ELF executable (§2 of the spec). A shared library is not an
   executable.
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
| The binary contains UndefinedBehaviorSanitizer handlers (`__ubsan_handle_*`), or needs `libubsan` (GCC links it even when the code emits no handler). | sanitized builds | Error `SANITIZER_MISSING`, exit code `30`. |
| The binary does **not** contain the AddressSanitizer runtime. | release builds | Error `PROFILE_MIXED`, exit code `30`. The release build must show the real behavior of the program (§3.2 of the spec). |
| The binary has debug information for the program's own code (DWARF compile units other than the sanitizer runtime's; GCC links a runtime object with debug info into every ASan binary). | sanitized builds | Warning `NO_DEBUG_INFO`. Stack traces will have function names but no file and line, so links to the diff may be undetermined (§9). |
| The binary does not call `_FORTIFY_SOURCE` checking functions (`__*_chk`). Judged only when the sanitizer runtime is a shared library: a runtime linked into the binary (clang's default) defines and calls such functions itself, so they cannot be told apart from the program's own calls. | sanitized builds | Warning `FORTIFY_IN_SANITIZED`. Fortify checks can stop the program before AddressSanitizer reports the error, so the error type would be less precise. |

The last check comes from a real case: Ubuntu's GCC enables
`_FORTIFY_SOURCE` by default, and a "sanitized" build of `token_parser` made
with it reported a fortify abort instead of an AddressSanitizer stack buffer
overflow. Our targets build the sanitized profile with clang, which does not do
this.

### 6.4 What is recorded

For each build, the tool records the command, the environment, the working
directory, the exit code, the duration, the path of `build.log`, and the
binary's path, size and SHA-256 hash. The compiler versions are recorded once
per run, in the report's environment (§12.4), from the output of
`gcc --version` and `clang --version`. The exact file format is defined in
§12.

This information is required for the reproducer bundles (§3.3 of the spec:
"build settings" and "binary hash").

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
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=1:disable_coredump=1:max_allocation_size_mb=<limit>
UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1:symbolize=1
ASAN_SYMBOLIZER_PATH=<path of llvm-symbolizer>
```

- `abort_on_error=1` makes every sanitizer report end the program with
  `SIGABRT`, so a reported error always terminates the run.
- `halt_on_error=1` makes UndefinedBehaviorSanitizer stop at the first error
  instead of printing it and continuing.
- `detect_leaks=0`: memory leaks are not treated as crashes. A leak report
  appears only at exit and would turn every run of a leaky program into a
  failure, unrelated to the patch. Memory leaks are therefore out of the
  scope of this tool; this is a deliberate choice, not a missed bug class.
- If the config's `env` sets `ASAN_OPTIONS` or `UBSAN_OPTIONS`, the tool's
  options are appended after the config's, so the tool's values win.
- If `llvm-symbolizer` is not found, the tool still runs, but stack traces have
  no function names. It records the warning `NO_SYMBOLIZER`.

### 7.3 Limits

| Limit | How it is enforced | Outcome when hit |
|---|---|---|
| Wall-clock time (`timeout_seconds`) | The tool kills the program's whole process group with `SIGKILL` when the time is up. | `TIMEOUT` |
| CPU time | `RLIMIT_CPU` set to `timeout_seconds` rounded up, plus 1 second. The kernel sends `SIGXCPU`. | `RESOURCE_LIMIT` (cpu) |
| Memory, release builds | `RLIMIT_DATA` set to `memory_limit_mb`, as in the current code. | The program's allocations fail. How it then ends is judged by the normal rules of §7.4. |
| Memory, sanitized builds | An address-space limit cannot be used, because AddressSanitizer reserves terabytes of virtual address space. The tool sets `max_allocation_size_mb` instead, as in the current code. | `RESOURCE_LIMIT` (memory), when AddressSanitizer reports an allocation that exceeds the limit |
| Output | Standard output and standard error are each stored up to 1 MB; the rest is discarded. | Not a failure. The run is marked truncated, with the warning `OUTPUT_TRUNCATED`. |
| Core dumps | `RLIMIT_CORE` set to 0. | |

Each program runs in its own process group (`setsid`), so child processes are
killed with it.

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

A finding can come from **several tests**. Crashes are grouped by bug key
(§1, §8.2), so that one error reached by several inputs, possibly through
different callers, is one finding. This
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
2. **Same-bug rule.** Group the signatures by their bug key (§1): the error
   type and the function and file of the first non-runtime frame. Signatures
   with the same bug key describe the same bug and form one group G, even if
   the frames below the crashing one differ.
3. For each group G, find:
   - **B**: the tests whose `base-sanitized` result is a crash with a
     signature in G;
   - **P**: the tests whose `patch-sanitized` result is a crash with a
     signature in G.
4. Create one finding for G:

| B | P | Category |
|---|---|---|
| not empty | empty | `FIXED` |
| not empty | not empty | `INCOMPLETE_FIX` |
| empty | not empty | `NEW_ISSUE` |

The finding lists every test in B and P, with that test's result on all four
builds, including the release builds. The release results are reported next to
the sanitized ones and never merged with them (§3.2 of the spec).

Consequences of these rules:

- **The worst case decides.** If even one test still reaches the bug on
  patch, the finding is `INCOMPLETE_FIX`. The tests that are blocked on patch
  are listed in the same finding, marked as blocked.
- **A different call path is still the same bug.** An incomplete patch often
  blocks the public input in one caller, while another input reaches the same
  crashing code through a different caller. The signatures then differ, but
  the bug key is the same, so the result is one `INCOMPLETE_FIX`, not a
  `FIXED` plus a `NEW_ISSUE`. When a finding contains more than one signature,
  its notes say that the call paths differ and list the signatures.
- **A test can be in two findings.** If a test crashes on base with bug key K1
  and on patch with a different bug key K2, it appears in the finding for K1
  (where it no longer reaches K1) and in a `NEW_ISSUE` finding for K2.
- **Comparison is by bug key, not by "both crashed".** Two crashes are the
  same error only if their error type and crashing function and file are
  equal. Two crashes with the same signal or the same detection mechanism are
  not enough.

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
  patch, and a crash there is handled by the normal rules of §8.2: a
  `NEW_ISSUE` when base does not crash, which also gives exit code `10`.

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

---

## 9. Linking findings to the patch

### 9.1 What the spec requires

Section 3.1 of the spec calls this the core of the project. The tool must show
how each fixed, remaining or new error relates to the changes in the diff:

- Valid evidence is the stack trace or execution path, matched against the
  changed file, function and section, **together with** the comparison of the
  two versions' runs.
- The error is not always on a changed line. For example, a changed length
  check in a calling function can affect an error in another function.
- The mere closeness of a warning to a changed location is not enough. When
  the evidence is insufficient, the link must be reported as undetermined.

So the tool reports a link only when it has **location evidence** from an
actual execution and **comparative evidence** from running both versions on
the same input. Otherwise the link is `UNDETERMINED`.

### 9.2 Reading the diff

The diff (§3.3) is parsed with the `unidiff` library into files and hunks.
For each changed file the tool knows:

- on the **base side**: the line range of each hunk and the removed lines, in
  base line numbers;
- on the **patch side**: the line range of each hunk and the added lines, in
  patch line numbers.

A hunk's line range includes its unchanged context lines. A crash on such a
line is still "inside the changed hunk": in the incomplete `token_parser`
patch, the overflowing `strcpy` line is unchanged context directly below the
inserted, insufficient check.

**Changed functions** are found from the source code, not from the hunk
headers. Hunk headers name the function only when the diff was made with
`git diff` and only for the function that precedes the hunk, and `diff -u`
does not name functions at all. The tool runs `universal-ctags` on the base and
patch trees to get the start and end line of every function, and marks a
function as changed when any changed line falls inside it. `universal-ctags`
is added to the Docker image.

**Paths** in stack traces are absolute paths inside the build copy, such as
`/…/work/patch-sanitized/src/main.c`. The tool removes the build copy prefix
to get `src/main.c`, which is the path used in the diff after stripping.

### 9.3 Location evidence

The tool checks the stack trace of the relevant crash against the diff, on
the matching side:

| Finding | Crash used | Side of the diff |
|---|---|---|
| `FIXED` | A crash with the signature on `base-sanitized` | base |
| `INCOMPLETE_FIX` | A crash with the signature on `patch-sanitized` | patch |
| `NEW_ISSUE` | A crash with the signature on `patch-sanitized` | patch |

Every frame of that stack trace that is not a runtime frame (§7.4) is
checked, not only the top one. The strongest level found in any frame is
reported:

| Level | Condition |
|---|---|
| `IN_CHANGED_HUNK` | The frame's file and line are inside the line range of a hunk on that side. |
| `IN_CHANGED_FUNCTION` | The frame is inside a function that the patch changed. |
| `CHANGED_FUNCTION_IN_STACK` | A function that the patch changed appears lower in the stack, as a caller of the crashing code. This covers the spec's example of a check in a calling function. |
| `CHANGED_CODE_EXECUTED` | No frame matches, but the execution trace (§9.4) shows that the input ran through changed lines. |
| `UNDETERMINED` | None of the above. |

Two cases are always `UNDETERMINED`, because they are only closeness:

- The crash is in a file the patch changed, but not in a changed hunk or
  function, and no changed function is in the stack.
- The stack trace has no file and line information and no function names.

### 9.4 Execution trace

For findings without a crash stack, and for crash findings where the stack
gives no location evidence, the tool records which changed lines the input
actually executes:

- When a trace is needed, the tool makes one extra **coverage build** of the
  relevant version with `build.coverage_cmd` (§4.3), in its own fresh copy
  `work/<version>-coverage/`, exactly like the builds of §6.2. The target's
  `coverage` rule compiles with clang at `-O0 -g -fprofile-instr-generate
  -fcoverage-mapping`, so no line is optimized away.
- It runs the finding's test once on that build, with the same input,
  environment and limits as the normal runs, and with `LLVM_PROFILE_FILE`
  pointing into the run directory.
- It reads the executed lines with `llvm-profdata merge` and
  `llvm-cov export`, and records which changed lines of that side were
  executed (added lines on patch, removed lines on base), with their hit
  counts.
- Coverage builds are not among the four builds of §6.1: tests are not run on
  them, and they do not count for `builds_ok`. If the config has no
  `coverage_cmd`, or the coverage build or its profile fails, the tool records
  the warning `TRACE_UNAVAILABLE` and the link falls back to the other
  evidence, or `UNDETERMINED`.

Why coverage and not `gdb` breakpoints: the sanitized build uses `-O1`, where
changed lines can be merged or optimized out, so breakpoints silently miss.
`gdb` also needs `ptrace` inside the container and is slow with one breakpoint
per changed line. Source-based coverage is deterministic, gives hit counts
directly, and `llvm-profdata` and `llvm-cov` are already in the Docker image.
The order in which lines ran is not recorded; the hit counts and the changed
hunks are enough to show which branch the input took.

This trace is the "execution path" evidence of §3.1 of the spec. It is the
only location evidence available for a `FUNCTIONAL_REGRESSION`, which has no
crash. For example, in the regression `token_parser` patch, the trace of
`valid_set` shows that the new key-length check was executed, and that the
program returned through its error branch.

### 9.5 Comparative evidence

Comparative evidence means: the same input, run with the same settings,
behaves differently on the two versions in the way the category claims.
Because categories are defined by that comparison (§8), every finding already
has it. The link records which tests provide it:

| Finding | Comparative evidence |
|---|---|
| `FIXED` | Tests that crash with the signature on base and do not crash on patch. |
| `INCOMPLETE_FIX` | Tests that crash with the signature on both versions, plus any tests that the patch blocks. A blocked test shows the patch acts on this error; a still-crashing test shows it does not act enough. |
| `NEW_ISSUE` | Tests that do not crash on base and crash on patch. |
| `FUNCTIONAL_REGRESSION` | The test matches its oracle on base and does not on patch. |

### 9.6 What is recorded

For every finding, the link records:

- the **level** (§9.3);
- the **side** of the diff (`base` or `patch`);
- the matched **file**, **function**, **line** and **hunk header**, and the
  **frame number** in the stack trace, when a frame matched;
- the **changed lines executed**, when an execution trace was made;
- the **tests** that provide the comparative evidence (§9.5);
- an **explanation**: one or two sentences built only from the recorded facts,
  for example: "Frame #1 `handle_set_command` (src/main.c:37) of the crash on
  patch lies inside hunk `@@ -21,14 +21,19 @@`. The patch blocks
  `exploit_primary` but `exploit_secondary` still reaches the same error."

The link never changes a finding's category or the exit code. An
`UNDETERMINED` link is reported as such; it does not turn a finding into
`INCONCLUSIVE` (§13).

---

## 10. Minimization, reproducer bundles and regression tests

### 10.1 Which findings get them

Section 3.3 of the spec requires every confirmed error to be reproducible.

| Finding | Reproducer bundle | Minimization | Regression test |
|---|---|---|---|
| `INCOMPLETE_FIX`, `NEW_ISSUE` | yes, on `patch-sanitized` | yes, if the crash has a signature | yes |
| `FIXED` | yes, on `base-sanitized` | yes, if the crash has a signature | yes |
| `FUNCTIONAL_REGRESSION` | no; there is no crash to reproduce | no | no |
| `INCONCLUSIVE` | no | no | no |

Each bundle starts from one **source test**: the first test of the finding, in
config order, that crashes on the bundle's build. A finding has at most one
bundle.

### 10.2 Minimization

The tool reduces the source test's input with **delta debugging** (`ddmin`),
working on bytes:

- **Binary**: the bundle's build (§10.1).
- **A candidate input is accepted** when one run of it (same command,
  environment and limits as in §7) ends in a `CRASH` with **the same
  signature** as the finding: the same error type and the same top three
  functions. A different error, a crash without signature, or a non-zero exit
  code is not accepted (§3.3 of the spec: "a non-zero exit code is not enough
  to preserve the same error").
- **Result**: the smallest accepted input found. With enough budget this is
  1-minimal: removing any single byte makes it rejected.
- **Budget**: at most 500 candidate runs or 120 seconds. If the budget runs
  out, the smallest input found so far is used, and the warning
  `MINIMIZE_LIMIT` is recorded.
- Both the original and the minimized input are saved (§10.3).

If the crash has no signature, minimization is skipped, because there is
nothing to check that the same error is preserved. The bundle then uses the
original input only.

### 10.3 Contents of a bundle

Each bundle is a directory `reproducers/<finding id>/` in the run's output:

| File | Content |
|---|---|
| `input.orig.<ext>` | The source test's input, byte for byte. |
| `input.min.<ext>` | The minimized input. |
| `bin/<binary>` | A copy of the binary, so that the bundle is self-contained. |
| `metadata.json` | Everything needed to reproduce the error (below). |
| `replays.json` | The results of the replays (§10.4). |
| `minimize.log` | Each minimization step: candidate size and whether it was accepted. |
| `reproduce.sh` | A script that replays the error (§10.5). |

`metadata.json` contains, as §3.3 of the spec requires:

- the finding id, the source test, the version (`base` or `patch`) and build;
- the **exact version identifier**: the commit of the repository at run time,
  plus a SHA-256 hash of the source tree, plus the SHA-256 hash of the diff;
- the **binary hash** (SHA-256);
- the **build settings**: build command, build environment, and compiler
  versions;
- the **environment variables** of the run, exactly as passed;
- the **full run command**, the input method, and the input file name;
- the **expected signature**, error type and detection mechanism;
- the original and minimized sizes and the number of minimization runs.

### 10.4 Replays

The minimized input is replayed **three times** on the bundle's binary, with
the bundle's environment and command:

- Each replay records whether it reproduced the error (a crash with the same
  signature), the signal or exit code, the error type, the top functions, and
  the duration.
- The bundle is **stable** when all three replays reproduce the error.
- If the minimized input is not stable, the tool replays the original input
  three times instead. If that is stable, the bundle uses the original input
  and records that minimization produced an unstable input. If it is not
  stable either, the finding becomes `INCONCLUSIVE` and the bundle is kept,
  marked unstable (§3.3 of the spec: "unstable cases must be identified").

The behavior of the release build is not replayed in the bundle. It is already
recorded for every test of the finding (§8.2).

### 10.5 `reproduce.sh`

The script works from any location, using only paths relative to itself:

1. Checks the SHA-256 hash of `bin/<binary>` against `metadata.json`. If it
   differs, it stops with exit code `2`.
2. Creates an empty temporary working directory and places the input there
   under the same file name used during the run (§5.3).
3. Runs the binary with exactly the recorded environment (`env -i`) and
   command, giving the input by the recorded input method.
4. Looks for the expected error type and function names in standard error.
5. Prints the program's output and exits with `0` if the error was reproduced,
   or `1` if it was not.

By default it replays `input.min.<ext>`; `./reproduce.sh orig` replays the
original input. It needs only `bash`, `sha256sum` and the sanitizer runtime
libraries, so it runs inside the project's Docker image.

### 10.6 Regression tests

Section 3.3 of the spec requires the minimized input to be added
automatically to the project's regression suite, so that later pipeline runs
check it. The test must show the expected error on base, and check the absence
of the same error and the expected behavior on patch.

**When one is created**: for every bundle with a stable replay (§10.4).

**Verification before adding**: the input is run once on `base-sanitized`.

- For `FIXED` and `INCOMPLETE_FIX` findings, base must crash with the
  finding's signature. This holds even when the input was minimized on the
  patch binary.
- For `NEW_ISSUE` findings, base must not crash.

If the check fails, the test is not added, and the warning
`REGRESSION_NOT_ADDED` is recorded.

**Duplicates**: before adding, the tool compares the SHA-256 hash of the input
with every input already in `regression_dir`. If the same bytes are already
there, nothing is added, and the report marks the test as already present.
Inputs that come from a regression test are never added again. Two different
inputs that reach the same error are both kept, because each is a different
way to reach it (for example, the input that bypasses an incomplete patch).

**Files**: two files per test, named after the source test and the first 8
hex digits of the input's SHA-256 hash:

```
reg-exploit_secondary-3f2a91c0.txt    the input, byte for byte, with the original extension
reg-exploit_secondary-3f2a91c0.yaml   what the test expects
```

```yaml
name: reg-exploit_secondary-3f2a91c0
input_file: reg-exploit_secondary-3f2a91c0.txt
expect_base_crash: true
signature: "STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main"
created_by:
  tool_version: "0.2.0"
  run_id: "20261111-183002-3f2a91c0"
  finding: "F-001"
  source_test: "exploit_secondary"
created_on:
  base_version: "c76e9ca"
  base_binary_sha256: "…"
```

`created_on` records the base version on which the error was shown when the
test was created. This is the proof required by the spec, and it stays valid
in later CI runs where base may already contain a fix (§8.6).

**Where they are written**: to `regression/` in the run's output directory,
and also to the target's `regression_dir`, unless `--no-promote` is given.

**In later runs**, every `.yaml` file in `regression_dir` is loaded as a test
of kind `regression` (§5) and validated like the config (§4.5). It runs on all
four builds. Its expectation is: on base, a crash with `signature` if
`expect_base_crash` is true, or no crash if it is false; on patch, no crash.

---

## 11. Binary hardening

### 11.1 What is checked

Section 3.4 of the spec requires the tool to check NX, PIE, RELRO and the stack
canary of the normal (release) build, with evidence for each, and to warn when
a protection is unintentionally lost in the new version, for example because
the build script changed.

The tool checks the two **release** binaries, `base-release` and
`patch-release`. Sanitized builds are not checked: they are instrumented and do
not represent the delivered program.

### 11.2 Checks and evidence

All checks read the ELF file directly (program headers, dynamic section and
symbol tables). Each result records the evidence it was based on.

| Protection | Result | Rule | Evidence recorded |
|---|---|---|---|
| NX | enabled / disabled | Enabled when a `PT_GNU_STACK` header exists and does not have the execute flag. Disabled when the flag is set, or when the header is missing (the stack is then executable by default). | Presence and flags of `PT_GNU_STACK`. |
| PIE | enabled / disabled | Enabled when the ELF type is `ET_DYN` and the file has a `PT_INTERP` header (an executable, not a shared library). Disabled for `ET_EXEC`. | ELF type, presence of `PT_INTERP`, `DF_1_PIE` flag if present. |
| RELRO | none / partial / full | None without a `PT_GNU_RELRO` header. Full with `PT_GNU_RELRO` and immediate binding (`DT_BIND_NOW`, or `DF_BIND_NOW` in `DT_FLAGS`, or `DF_1_NOW` in `DT_FLAGS_1`). Partial otherwise. | Presence of `PT_GNU_RELRO` and the binding tag found. |
| Stack canary | present / absent | Present when the symbol tables reference `__stack_chk_fail`. | The symbol and the table it was found in. |

### 11.3 Comparison and warnings

For each protection, the patch result is compared with the base result.
Protections are ordered from weak to strong: disabled < enabled for NX, PIE
and the canary, and none < partial < full for RELRO.

- **Weaker on patch**: the warning `HARDENING_DOWNGRADE`, naming the
  protection, both values and both pieces of evidence.
- **Stronger on patch**: recorded as an improvement, without a warning.
- **Equal**: recorded as unchanged.

Hardening results never change the exit code: the spec asks for a warning, and
none of the exit codes of §3.5 covers hardening.

The report always includes two notes required by §3.4 of the spec:

- A PIE binary does not prove that ASLR is active at runtime.
- Evidence of a stack canary does not mean every function is protected.

---

## 12. Outputs and their formats

### 12.1 Output directory

Every run writes all its outputs to one new directory:

```
out/<target name>/<run id>/
```

The run id is the UTC start time and the first 8 hex digits of the diff's
SHA-256 hash, for example `20261111-183002-3f2a91c0`. Its contents:

```
report.json                       the full structured report (§12.4)
summary.txt                       the human-readable summary (§12.5)
errors.log                        full error details, only if the tool itself failed
inputs/
  config.yaml                     copy of the config used
  patch.diff                      the diff used
builds/<build>/                   one per build (§6)
  build.json
  build.log
  bin/<binary>
runs/<test>/<build>/              one per test and build (§7)
  <n>.json  <n>.stdout  <n>.stderr        n = 1 … repeats
reproducers/<finding id>/         one per bundle (§10.3)
regression/                       new regression tests of this run (§10.6)
```

The temporary build copies (`work/`) are deleted at the end of the run, unless
`--keep-work` is given. `out/` is listed in `.gitignore`.

### 12.2 Conventions

- JSON files are UTF-8 and start with `"schema_version": 1`.
- Paths inside JSON files are relative to the run directory.
- Times are ISO 8601 in UTC. Durations are in seconds. Sizes are in bytes.
- Hashes are SHA-256, written as lowercase hex.
- A value that does not apply is `null`, never omitted.
- Program output (standard output and standard error) is never placed inside
  JSON. It is stored byte for byte in its own files.

### 12.3 Build and run records

**`builds/<build>/build.json`** has the fields listed in §6.4: `build`,
`version`, `profile`, `status` (`ok` or `failed`), `cmd`, `env`, `cwd`,
`exit_code`, `duration_s`, `log`, `binary` (`path`, `size`,
`sha256`) and `sanitizers_verified`.

**`runs/<test>/<build>/<n>.json`** has one record per run:

| Field | Content |
|---|---|
| `test`, `kind`, `build`, `repeat` | Which run this is. |
| `cmd`, `env`, `cwd` | The exact command, environment and working directory. |
| `input` | `method`, file `name`, `size`, `sha256`. |
| `exit_code`, `signal` | How the program ended. One of the two is `null`. |
| `timed_out`, `limit_hit` | `true`/`false`, and `cpu`, `memory` or `null`. |
| `duration_s` | Duration of the run. |
| `stdout`, `stderr` | `path`, `bytes`, `sha256`, `truncated`. |
| `analysis` | `outcome`, `detection`, `error_type`, `summary` (the first line of the sanitizer or runtime report), `frames` (list of `index`, `function`, `file`, `line`, `runtime`), `signature`. |
| `oracle` | `checked`, `passed`, and `reasons` (for example `exit code 1, expected 0`). |

### 12.4 `report.json`

Top-level fields, in this order:

| Field | Content |
|---|---|
| `schema_version`, `tool` | Format version; tool name and version. |
| `run_id`, `started_at`, `duration_s` | The run. |
| `target` | `name`, `config` (path of the copy), `config_sha256`. |
| `versions` | `base` and `patch`: `form` (`directory` or `diff`), `ref` (as given), `git_commit` (of the repository at run time), `tree_sha256`, and for a diff `strip_level`. `diff`: `path`, `sha256`, changed `files`, number of `hunks`. |
| `environment` | `os`, `kernel`, `arch`, `docker_image`, `python`, `gcc`, `clang`, `llvm_symbolizer` (path or `null`). |
| `settings` | `repeats`, `limits`, `sanitizer_options`. |
| `builds` | For each build: `status`, `binary_sha256`, `details` (path of `build.json`). |
| `hardening` | `base` and `patch`: for each protection its value and evidence; `changes` (protection, from, to, `downgrade` or `improvement`); `notes` (§11.3). |
| `execution_logs` | For each build, for each test: the combined result (below). |
| `findings` | List of findings (below). |
| `regression_added` | List of regression tests handled in this run (below). |
| `status` | Checks, conditions and exit code (§13). |
| `warnings`, `errors` | Lists of `{code, message, details}` (§12.6). |

**`execution_logs`**: keyed by build (`base-release`, `base-sanitized`,
`patch-release`, `patch-sanitized`), then by test name. Each entry is the
combined result of the repeats (§7.5):

```json
"patch-sanitized": {
  "exploit_secondary": {
    "kind": "security", "outcome": "CRASH", "exit_code": null, "signal": "SIGABRT",
    "detection": "ASAN", "error_type": "STACK_BUFFER_OVERFLOW",
    "signature": "STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main",
    "top_frame": "handle_set_command src/main.c:37",
    "oracle_passed": null, "flaky": false,
    "runs": "runs/exploit_secondary/patch-sanitized/"
  }
}
```

**`findings`**: one object per finding, with the contents of §8.8:

```json
{
  "id": "F-001",
  "category": "INCOMPLETE_FIX",
  "signature": "STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main",
  "error_type": "STACK_BUFFER_OVERFLOW",
  "tests": [
    {"test": "exploit_primary", "kind": "security", "on_patch": "blocked",
     "results": {"base-release": {"outcome": "CRASH", "detection": "FORTIFY", "signal": "SIGABRT"},
                 "base-sanitized": {"outcome": "CRASH", "detection": "ASAN", "signal": "SIGABRT"},
                 "patch-release": {"outcome": "NORMAL", "exit_code": 1},
                 "patch-sanitized": {"outcome": "NORMAL", "exit_code": 1}}},
    {"test": "exploit_secondary", "kind": "security", "on_patch": "reaches", "results": {"…": "…"}}
  ],
  "release":   {"base": "CRASH FORTIFY SIGABRT", "patch": "CRASH FORTIFY SIGABRT"},
  "sanitized": {"base": "CRASH ASAN SIGABRT",    "patch": "CRASH ASAN SIGABRT"},
  "link": {
    "level": "IN_CHANGED_HUNK", "side": "patch",
    "file": "src/main.c", "function": "handle_set_command", "line": 37, "frame": 1,
    "hunk": "@@ -21,14 +21,19 @@", "executed_changed_lines": null,
    "comparative_tests": ["exploit_primary", "exploit_secondary"],
    "explanation": "Frame #1 handle_set_command (src/main.c:37) of the crash on patch lies inside hunk @@ -21,14 +21,19 @@. The patch blocks exploit_primary but exploit_secondary still reaches the same error."
  },
  "evidence": ["runs/exploit_primary/", "runs/exploit_secondary/"],
  "reproducer": "reproducers/F-001/",
  "regression_test": "regression/reg-exploit_secondary-3f2a91c0.yaml",
  "notes": "The added length check (>= 100) does not protect the 64-byte buffer."
}
```

`on_patch` is `reaches` (the test still shows the signature on patch),
`blocked` (it no longer crashes), or `other_error` (it crashes on patch with a
different signature, reported in another finding).

**`regression_added`**: one object per regression test considered in this
run: `name`, `from_finding`, `path`, `input_sha256`, `status` (`added`,
`already_present` or `not_added`), and `promoted_to` (the target directory, or
`null` with `--no-promote`).

### 12.5 `summary.txt`

The same text is printed at the end of the run. It has these parts, in order:
the target and run id; base and patch; the state of the four builds; the
hardening comparison; the number of tests, builds and repeats, and how many
results were flaky; one block per finding; the final exit code and name; the
path of `report.json`. Tests without findings are only counted, not listed.

```
ZARABAN 0.2.0  token_parser  run 20261111-183002-3f2a91c0
base:  targets/target1_sample (directory)
patch: targets/target1_sample/patches/incomplete.patch (diff, -p2)

BUILDS     base-release ok · base-sanitized ok · patch-release ok · patch-sanitized ok
HARDENING  NX on→on · PIE on→on · RELRO full→full · canary on→on   (no changes)
TESTS      9 tests × 4 builds × 3 repeats   flaky: 0

FINDINGS
  F-001 INCOMPLETE_FIX  STACK_BUFFER_OVERFLOW @ handle_set_command < process_input < main
        tests:     exploit_primary blocked · exploit_secondary reaches
        release:   FORTIFY/SIGABRT → FORTIFY/SIGABRT
        sanitized: ASAN/SIGABRT → ASAN/SIGABRT
        link:      IN_CHANGED_HUNK  src/main.c:37 handle_set_command (patch side)
        bundle:    reproducers/F-001  94 → 69 bytes, replay 3/3

RESULT     exit 10  VULN_REMAINS
report:    out/token_parser/20261111-183002-3f2a91c0/report.json
```

### 12.6 Warning and error codes

Every entry in `warnings` and `errors` has a fixed `code`, a `message` for
people, and `details` with the relevant values and paths. Warnings never change
the exit code. Every error gives exit code `30`.

| Warning | Meaning | Defined in |
|---|---|---|
| `NO_INVALID_TESTS` | The config has no invalid tests. | §4.5 |
| `NO_DEBUG_INFO` | A sanitized binary has no debug information. | §6.3 |
| `FORTIFY_IN_SANITIZED` | A sanitized binary uses fortify checks. | §6.3 |
| `NO_SYMBOLIZER` | `llvm-symbolizer` was not found. | §7.2 |
| `OUTPUT_TRUNCATED` | A run's output was cut at 1 MB. | §7.3 |
| `REPEATS_TOO_LOW` | `repeats` is 1. | §7.5 |
| `REGRESSION_BASE_CLEAN` | A regression test does not crash on the current base. | §8.6 |
| `MINIMIZE_LIMIT` | Minimization stopped at its budget. | §10.2 |
| `REGRESSION_NOT_ADDED` | A minimized input failed its check on base. | §10.6 |
| `HARDENING_DOWNGRADE` | A protection is weaker on patch. | §11.3 |
| `TRACE_UNAVAILABLE` | No execution trace could be made (no `coverage_cmd`, or its build failed). | §9.4 |

| Error | Meaning | Defined in |
|---|---|---|
| `ARGUMENT_INVALID` | Invalid command-line arguments. | §3.3 |
| `SOURCE_NOT_FOUND` | A `--base` or `--patch` that does not exist, or a `--base` that is not a directory. | §3.2 |
| `PATCH_APPLY_FAILED` | The diff does not apply with any strip level. | §3.2 |
| `CONFIG_INVALID` | The config, or a regression test file, is invalid. All problems are listed in `details`. | §4.5 |
| `BUILD_FAILED` | A build command failed, timed out, or did not produce the binary. | §6.2 |
| `SANITIZER_MISSING` | A sanitized binary lacks a sanitizer. | §6.3 |
| `PROFILE_MIXED` | A release binary contains AddressSanitizer. | §6.3 |
| `TOOL_INTERNAL` | A bug in the tool, including a failed completeness check. Details are in `errors.log`. | §8.7 |

---

## 13. Status and exit codes

### 13.1 Exit codes

The exit codes and their names are exactly those of §3.5 of the spec:

| Code | Name | Meaning |
|---|---|---|
| `0` | `PASS` | The error was reproduced on base and is not observed on patch within the tests; no other confirmed security error was recorded; all functional tests and required checks succeeded. |
| `10` | `VULN_REMAINS` or `NEW_ISSUE` | The original error still occurs, or another security error with valid evidence was confirmed. |
| `20` | `FUNC_REGRESSION` | At least one valid functional test that succeeded on base fails on patch. |
| `30` | `BUILD_OR_CONFIG_ERROR` | The target did not build, the config is invalid, or the environment or the tool itself failed. |
| `40` | `INCONCLUSIVE` | A required check could not be completed with sufficient evidence. |

When several conditions hold at once, the exit code is the first in the
order `30`, `10`, `20`, `40`, `0`.

### 13.2 Required checks

`PASS` is only possible when every required check succeeded. The report lists
each check with its result:

| Check | Succeeds when | If it fails |
|---|---|---|
| `builds_ok` | All four builds succeeded (§6.2). | Error, code `30`. |
| `profiles_verified` | All four binaries passed profile verification (§6.3). | Error, code `30`. |
| `all_runs_completed` | Every test ran `repeats` times on every build. | `TOOL_INTERNAL`, code `30`. |
| `base_reproduced` | Every `security` test crashes on `base-sanitized` (§5.5). | Condition `INCONCLUSIVE`, code `40`, naming the tests. |
| `results_stable` | No result is flaky (§7.5). | Covered by the `INCONCLUSIVE` findings of §8.5. |
| `bundles_replayed` | Every reproducer bundle is stable (§10.4). | Covered by the `INCONCLUSIVE` findings of §10.4. |
| `hardening_checked` | Both release binaries were inspected (§11). | Error `TOOL_INTERNAL`, code `30`. |

### 13.3 Conditions

A **condition** is one reason for an exit code. The tool collects all of them:

| Condition | Code | Created when |
|---|---|---|
| `BUILD_OR_CONFIG_ERROR` | `30` | There is at least one error (§12.6). |
| `VULN_REMAINS` | `10` | There is at least one `INCOMPLETE_FIX` finding. |
| `NEW_ISSUE` | `10` | There is at least one `NEW_ISSUE` finding. |
| `FUNC_REGRESSION` | `20` | There is at least one `FUNCTIONAL_REGRESSION` finding. |
| `INCONCLUSIVE` | `40` | There is at least one `INCONCLUSIVE` finding, or `base_reproduced` failed. |
| `PASS` | `0` | None of the above, and there is at least one `FIXED` finding. |

If there are no conditions at all and no `FIXED` finding, which cannot happen
when `base_reproduced` succeeded, the result is `INCONCLUSIVE`.

Each condition records its code, its name, a reason in plain words, and the
findings and tests that caused it.

### 13.4 Final status

The final exit code is the highest-priority condition (§13.1). If both
`VULN_REMAINS` and `NEW_ISSUE` are present, the exit name is `VULN_REMAINS`.
All conditions stay in the report, including those that did not decide the
exit code (§3.5 of the spec).

```json
"status": {
  "checks": {"builds_ok": true, "profiles_verified": true, "all_runs_completed": true,
             "base_reproduced": true, "results_stable": true, "bundles_replayed": true,
             "hardening_checked": true},
  "conditions": [
    {"code": 10, "name": "VULN_REMAINS", "reason": "F-001: the overflow is still reached by exploit_secondary",
     "findings": ["F-001"], "tests": ["exploit_secondary"]}
  ],
  "exit_code": 10,
  "exit_name": "VULN_REMAINS",
  "reason": "VULN_REMAINS (F-001) has the highest priority among: VULN_REMAINS."
}
```

What does **not** change the exit code: warnings (§12.6), and an
`UNDETERMINED` link to the patch (§9.6).

If the tool itself fails, it still writes the report with everything collected
so far, adds the error `TOOL_INTERNAL`, and exits with `30`.

---

## 14. Repository layout and deliverables

### 14.1 Repository

```
zaraban/                      the tool (Python package; existing packages are kept)
tests/                        unit tests of the tool (pytest)
targets/<target>/             one directory per target (§14.2)
scripts/run_matrix.py         runs and checks all delivered scenarios (§14.3)
results/<target>/<scenario>/  committed outputs of the delivered scenarios
docs/SPEC.md                  this document
docs/DECISIONS.md             design decisions and their reasons
README.md                     overview and the independent run guide
Dockerfile, docker-compose.yml
.github/workflows/zaraban.yml the CI pipeline (§14.4)
out/                          run outputs (ignored by git)
```

### 14.2 Target directory

```
targets/<target>/
  zaraban.yaml               the config (§4)
  ORACLE.md                  the source of every expected behavior (§5.6)
  scenarios.yaml             the delivered scenarios and their expected results (§14.3)
  Makefile                   with `release` and `sanitized` rules
  src/                       the base version
  patches/correct.patch      the diff of each patched version against src/
  patches/incomplete.patch
  patches/regression.patch
  versions/patch_correct/    each patched version as a complete tree: Makefile and src/
  versions/patch_incomplete/
  versions/patch_regression/
  tests/valid/  tests/boundary/  tests/invalid/  tests/exploits/
  tests/regression/          generated regression tests (§10.6)
```

**Which targets.** Section 4 of the spec requires two independent C/C++
programs, at least one of them a real project or library, not a toy. Both
delivered targets are real open-source projects with a public CVE, and the
Correct patch of each is the upstream fix:

| Target | Upstream | Vulnerability | Base | Correct patch |
|---|---|---|---|---|
| `cjson` | DaveGamble/cJSON | CVE-2019-11835, heap buffer over-read in `cJSON_Minify` | `v1.7.10` | upstream commit `a43fa56` (in `v1.7.11`) |
| `md4c` | mity/md4c | CVE-2021-30027, heap buffer over-read in `md_analyze_line` | `release-0.4.7` | upstream fix, in `release-0.4.8` |

The Incomplete and Regression patches are written by the team, and the
`ORACLE.md` of each target says how. The reproduction of each CVE is recorded
in `docs/repro/`. `token_parser` (`targets/target1_sample`) is written by the
team, so it is a development fixture for the tool's own tests, and is not one
of the two delivered targets.

Section 4 of the spec requires the four versions of each target to be ready in
the repository. Each patched version is stored both as a complete tree, which
is easy to read and build, and as a diff, which is the form used at the defense
and for linking findings. The two must always agree (§14.3).

### 14.3 Scenarios

`scenarios.yaml` lists the delivered scenarios of a target. The tool never
reads it; it is used only by `scripts/run_matrix.py`.

```yaml
- name: correct
  patch: patches/correct.patch
  version_dir: versions/patch_correct
  expect_exit: 0
  expect_findings:
    - {category: FIXED, tests: [exploit_primary, exploit_secondary]}
- name: incomplete
  patch: patches/incomplete.patch
  version_dir: versions/patch_incomplete
  expect_exit: 10
  expect_findings:
    - {category: INCOMPLETE_FIX, tests: [exploit_primary, exploit_secondary]}
```

For each scenario of each target, `scripts/run_matrix.py`:

1. checks that `patch` equals the diff between `src/` and `version_dir`, so
   that the two forms describe the same version and running the tool once is
   enough;
2. runs the tool with `--patch` set to the diff file;
3. checks that the run gives `expect_exit` and the expected findings
   (category and tests);
4. with `--save`, copies the run's output to `results/<target>/<scenario>/`,
   without the `builds/*/bin/` binaries (the bundles keep their own copy);
5. exits with `0` only if every scenario matched.

### 14.4 CI pipeline

`.github/workflows/zaraban.yml` runs on every push and pull request:

1. Build the Docker image.
2. Inside the image, run the tool's unit tests with `pytest`.
3. Inside the image, run `scripts/run_matrix.py`.
4. Upload `out/` as a build artifact, so every report and bundle can be
   downloaded.

The job fails when any step fails, so the tool's exit codes decide the
pipeline result (§3.5 of the spec).

### 14.5 Docker image

The image is the isolated test environment required by §5 of the spec:

- Ubuntu 22.04 on x86-64, with gcc, clang, llvm (for `llvm-symbolizer`,
  `llvm-profdata` and `llvm-cov`), binutils, `universal-ctags`, git and
  Python 3 with the tool's dependencies. `gdb` is included for manual
  debugging only; the tool does not use it.
- The tool runs as a non-root user.
- `docker-compose.yml` sets resource limits on the container: memory
  (`mem_limit`), CPU (`cpus`) and number of processes (`pids_limit`), and
  disables networking (`network_mode: none`).

### 14.6 Deliverables

Section 5 of the spec lists what must be delivered. Where each one is:

| Deliverable | Location |
|---|---|
| Tool code | `zaraban/` |
| Configuration | `targets/<target>/zaraban.yaml` |
| Exact versions of the targets | `targets/<target>/src/`, `versions/`, `patches/` |
| Tests | `targets/<target>/tests/`, with `ORACLE.md` |
| Reproducer bundles | `results/<target>/<scenario>/reproducers/` |
| Generated reports | `results/<target>/<scenario>/report.json` and `summary.txt` |
| Pipeline file | `.github/workflows/zaraban.yml` |
| Independent run guide | `README.md` |

Both targets, their four versions and their oracles must be approved by the
instructor during the design phase (§4 of the spec).
