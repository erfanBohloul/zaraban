# Review of `docs/SPEC.md` against the course spec

Reviewed: `SPEC.md` (draft on branch `docs/spec`, based on commit `fe43c75`).
Reference: `project1_spec.pdf` (Data & Network Security, Project 1).

## Verdict

SPEC.md is precise and faithful to the course spec. It covers every required
capability (§3.1 to §3.5 of the PDF), the four scenarios (§4), and the
deliverables (§5). In several places it is stricter than the PDF, which is
good for grading. It also fixes real bugs in the current code: the patched
release build is never tested, timeouts are counted as crashes, and a test
can be deleted by the patch itself.

I found **no contradictions** with the PDF. I found **one requirement gap**
(targets), **three design risks** that could cost points, and a few small
points.

## Coverage map

| PDF requirement | SPEC.md section | Status |
|---|---|---|
| §2 Targets: C/C++ ELF x86_64, file/args/stdin input | §4, §5.3, §6.2 step 4 | Covered |
| §2 Dynamic execution mandatory | §2, §7 | Covered |
| §2 Generality: new target = new config only | §4.1, §4.5 | Covered |
| §2 Oracle defined beforehand, independent, approved | §5.6 `ORACLE.md` | Covered |
| §3.1 Patch-to-finding correlation, undetermined when weak | §9 | Covered, see risk 2 |
| §3.1 Five finding categories | §8.1 | Covered |
| §3.1 Same settings on both versions; regression needs base to pass | §7.1, §8.4 | Covered |
| §3.2 Error type, detection, termination, release vs sanitized | §7.4, §8.2, §8.8 | Covered |
| §3.2 Timeouts and limits reported separately | §7.3 | Covered |
| §3.3 Reproducer bundle, 3 replays, unstable flagged | §10.3, §10.4 | Covered |
| §3.3 Minimization keeps the same error, non-zero exit is not enough | §10.2 | Covered |
| §3.3 Automatic regression test | §10.6 | Covered |
| §3.4 NX, PIE, RELRO (none/partial/full), canary, downgrade warning, two caveats | §11 | Covered |
| §3.5 CLI, summary, JSON, exit codes and priority 30 > 10 > 20 > 40 > 0 | §3, §12, §13 | Covered |
| §4 Two independent programs, at least one real, not a toy | §14 (implicit) | **Gap, see below** |
| §4 Four versions per program in the repo | §14.2 | Covered |
| §4 Unseen patches; no decision by file name | §3.2 | Covered |
| §5 Isolated environment with resource limits | §14.5 | Covered |
| §5 Deliverables list | §14.6 | Covered |
| §6 Grading and individual defense | Not in SPEC (belongs in README) | Covered in README |

## Requirement gap: targets

The PDF (§4) says at least one of the two programs must be **a real project or
library, not a toy**. `token_parser` is written by the team, so it is a toy.
The SPEC names `cjson` as the second target, which is real, but it does not
say which vulnerability or patch is used. The PDF allows a known public
vulnerability with its real fix.

What to add to SPEC §14:

- One sentence stating the real-target rule.
- For each target: upstream project, version or commit, CVE id, the upstream
  fix commit used as the Correct patch, and how the Incomplete and Regression
  patches were derived.

You asked for both targets to be official projects. See the target section of
the README for the shortlist. I suggest keeping `token_parser` only as a
development fixture and unit-test target, not as a delivered target.

## Design risks

### Risk 1: signature matching may be too strict for incomplete patches

§8.2 groups crashes by error type plus the **top three** non-runtime frames.
An Incomplete patch often lets a different input reach the same bug through a
different caller. In that case the top three frames differ. The tool would
report `FIXED` for the old signature plus `NEW_ISSUE` for the new one. The
exit code is still `10`, but the category is wrong. That costs points in the
15-point scenario row and the 25-point correlation row.

Suggestion: keep the three-frame signature for grouping. Add a second
"same bug" rule: the same error type **and** the same crashing frame (frame 0
function plus file). When the base has signature S1 and the patch has S2, and
they match on this rule, report one `INCOMPLETE_FIX` and note that the call
path differs.

### Risk 2: the `gdb` execution trace (§9.4) is fragile

- The sanitized build uses `-O1`. Changed lines can be optimized out or
  merged, so breakpoints silently miss and the link becomes `UNDETERMINED`.
- `gdb` inside Docker needs `ptrace`. With the hardened compose file
  (non-root, limits) you may need `cap_add: [SYS_PTRACE]`.
- One breakpoint per changed line is slow on large diffs.

Suggestion: build a third, trace-only binary of each version with
`-O0 -g -fprofile-instr-generate -fcoverage-mapping` (clang source-based
coverage). Read executed lines with `llvm-profdata` and `llvm-cov export`.
This is deterministic, needs no `ptrace`, and gives line hit counts directly.
If you keep `gdb`, build the traced binary at `-O0`.

### Risk 3: unseen patches at the defense

The verdict is limited to the configured tests (the PDF allows this: "within
the defined test scope"). An unseen **incomplete** patch that blocks both of
your exploit inputs will be reported `PASS`. The SPEC has no step that looks
for other inputs.

Suggestion: an optional, bounded **variant step**. Mutate each security input
(length sweep around the buffer sizes, byte flips, repetition) on
`patch-sanitized` for a fixed budget, for example 300 runs or 30 seconds. Any
crash goes through the normal rules. This is not required by the PDF, so keep
it behind a config flag with a fixed seed so results stay deterministic.

## Smaller points

1. **Exit-name mismatch between docs.** `DECISIONS.md` (ADR-004) still says
   `REMAINS_VULN` and `ERROR_CONFIG_OR_BUILD`. SPEC §13 uses the PDF's names.
   Update the ADR.
2. **Repeats on every build** (§7.1) are correct, but say in the README how
   long a full matrix takes on a real target. Real libraries are slower than
   `token_parser`.
3. **`detect_leaks=0`** (§7.2) is a sound choice. Add a sentence that leaks are
   out of scope, so the examiner does not read it as a missed bug class.
4. **Release-only crash = `INCONCLUSIVE`** (§8.3) is defensible. Make sure the
   summary shows the release crash clearly, because §3.2 of the PDF asks how
   the bug shows in the final binary.
5. **Hardening never changes the exit code** (§11.3). This matches the PDF.
   Mention it in the README so nobody "fixes" it later.
6. **Defense on a sibling program.** The PDF says unseen patches may target a
   sibling program in the same domain. Keep a commented template
   `zaraban.yaml` ready so a new config takes minutes.
7. **Deadline.** The PDF's due date is 18 Aban 1405, which has passed. I
   assume you have an extension. The plan in the README orders the work
   without dates.
