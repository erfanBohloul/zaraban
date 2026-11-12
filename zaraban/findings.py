"""Findings: comparing how the tests behave on base and on patch (SPEC §8).

Input is the combined results of §7.5, one per test per build
(``results[test][build]``, made by the runner). Output is a list of
:class:`Finding`. This module never runs anything.

Section numbers such as §8.2 refer to docs/SPEC.md.
"""

from __future__ import annotations

from typing import NamedTuple, Optional

from zaraban.models import (
    BUILD_ORDER,
    Analysis,
    BuildName,
    BuildSummary,
    Category,
    CombinedResult,
    ErrorType,
    Finding,
    FindingTest,
    Frame,
    OnPatch,
    Outcome,
    Profile,
    Results,
    Version,
)

# ---------------------------------------------------------------------------
# Bug key (§1, §8.2)
# ---------------------------------------------------------------------------


class BugKey(NamedTuple):
    """Error type plus the function and file of the crashing frame (§1).

    Two crashes with the same bug key are the same bug, even when they were
    reached through different callers (§8.2).
    """

    error_type: ErrorType
    function: str
    file: Optional[str]  # None when the trace has no file information

    def __str__(self) -> str:
        where = f" ({self.file})" if self.file else ""
        return f"{self.error_type.value} @ {self.function}{where}"


def crash_frame(analysis: Analysis) -> Optional[Frame]:
    """The crashing location: the first non-runtime frame with a function name.

    Frames without a name are skipped, exactly as for the signature (§7.4), so
    a crash has a bug key if and only if it has a signature.
    """
    for f in analysis.app_frames:
        if f.function:
            return f
    return None


def bug_key(analysis: Analysis) -> Optional[BugKey]:
    """The bug key of a crash, or None for a non-crash or a crash without
    a signature (§8.3)."""
    if not analysis.is_crash or analysis.error_type is None:
        return None
    frame = crash_frame(analysis)
    if frame is None:
        return None
    return BugKey(analysis.error_type, frame.function, frame.file)


# ---------------------------------------------------------------------------
# What one test did on each build (§8.8, §12.4)
# ---------------------------------------------------------------------------


def build_summary(result: CombinedResult) -> BuildSummary:
    """Short view of one combined result, for a finding's test list."""
    run = result.first
    a = run.analysis
    return BuildSummary(
        outcome=a.outcome,
        detection=a.detection,
        signal=run.signal,
        exit_code=run.exit_code,
        error_type=a.error_type,
        signature=a.signature,
        oracle_passed=run.oracle.passed,
        flaky=result.flaky,
    )


def finding_test(per_build: dict[BuildName, CombinedResult],
                 on_patch: Optional[OnPatch] = None) -> FindingTest:
    """One test of a finding, with its result on every build (§8.2: all four
    builds, the release ones included)."""
    first = next(per_build[b] for b in BUILD_ORDER if b in per_build)
    return FindingTest(
        test=first.test,
        kind=first.kind,
        results={b: build_summary(per_build[b]) for b in BUILD_ORDER if b in per_build},
        on_patch=on_patch,
    )


def describe(result: CombinedResult) -> str:
    """One result in a few words: ``CRASH ASAN SIGABRT``, ``NORMAL exit 1``,
    ``TIMEOUT``, ``RESOURCE_LIMIT memory``. ``(flaky)`` is added when the
    repeats differ (§7.5)."""
    run = result.first
    a = run.analysis
    words = [a.outcome.value]
    if a.outcome is Outcome.CRASH:
        if a.detection is not None:
            words.append(a.detection.value)
        words.append(run.signal if run.signal else f"exit {run.exit_code}")
    elif a.outcome is Outcome.NORMAL:
        words.append(f"exit {run.exit_code}")
    elif a.outcome is Outcome.RESOURCE_LIMIT and run.limit_hit is not None:
        words.append(run.limit_hit.value)
    if result.flaky:
        words.append("(flaky)")
    return " ".join(words)


# Worst first, so the summary of a finding starts with what matters most.
_SEVERITY = {Outcome.CRASH: 0, Outcome.TIMEOUT: 1, Outcome.RESOURCE_LIMIT: 2, Outcome.NORMAL: 3}


def build_text(results: list[CombinedResult]) -> str:
    """What the tests of a finding did on one build, as one line.

    If every test did the same, this is that one description, for example
    ``CRASH ASAN SIGABRT``. Otherwise each different description is listed,
    worst first, with the tests that showed it:
    ``CRASH ASAN SIGABRT (exploit_secondary); NORMAL exit 1 (exploit_primary)``.
    """
    groups: dict[str, list[CombinedResult]] = {}
    for r in results:
        groups.setdefault(describe(r), []).append(r)
    if len(groups) == 1:
        return next(iter(groups))
    ordered = sorted(groups.items(), key=lambda kv: _SEVERITY[kv[1][0].outcome])  # stable
    return "; ".join(f"{text} ({', '.join(r.test for r in rs)})" for text, rs in ordered)


def profile_summary(per_test: list[dict[BuildName, CombinedResult]],
                    profile: Profile) -> dict[str, str]:
    """``{"base": ..., "patch": ...}`` for one profile (§8.8): the finding's
    ``release`` or ``sanitized`` field. The two profiles are never merged."""
    out: dict[str, str] = {}
    for version in (Version.BASE, Version.PATCH):
        build = BuildName.of(version, profile)
        rs = [t[build] for t in per_test if build in t]
        if rs:
            out[version.value] = build_text(rs)
    return out


# ---------------------------------------------------------------------------
# Crash findings (§8.2)
# ---------------------------------------------------------------------------

_BS = BuildName.BASE_SANITIZED
_PS = BuildName.PATCH_SANITIZED


def stable_key(result: Optional[CombinedResult]) -> Optional[BugKey]:
    """The bug key of a stable crash, or None.

    Flaky results are never used to build crash findings, because a
    signature that appears only in some repeats could be grouped wrongly
    (§8.5).
    """
    if result is None or not result.stable_crash:
        return None
    return bug_key(result.first.analysis)


def crash_findings(results: Results, tests: Optional[list[str]] = None) -> list[Finding]:
    """One finding per bug key seen in a stable sanitized crash (§8.2).

    ``tests`` is the run order of §7.1 (default: the order of ``results``).
    Findings come out in the order their bug key is first seen in that order;
    their ``id`` is left empty and given when all findings are known (§8.8).

    For each bug key K, B is the tests whose ``base-sanitized`` result is a
    stable crash with key K, and P the same on ``patch-sanitized``:
    B and not P is ``FIXED``, B and P is ``INCOMPLETE_FIX``, only P is
    ``NEW_ISSUE``. The finding lists every test of B and P with its results
    on all four builds.
    """
    order = list(tests) if tests is not None else list(results)

    # 1-3. Group by bug key, in first-seen order; keep each group's signatures.
    groups: dict[BugKey, tuple[list[str], list[str], list[str]]] = {}
    for test in order:
        for build in (_BS, _PS):
            r = results[test].get(build)
            key = stable_key(r)
            if key is None:
                continue
            base_tests, patch_tests, sigs = groups.setdefault(key, ([], [], []))
            (base_tests if build is _BS else patch_tests).append(test)
            if r.signature not in sigs:
                sigs.append(r.signature)

    # 4. One finding per group.
    findings: list[Finding] = []
    for key, (base_tests, patch_tests, sigs) in groups.items():
        if base_tests and patch_tests:
            category = Category.INCOMPLETE_FIX
        elif base_tests:
            category = Category.FIXED
        else:
            category = Category.NEW_ISSUE
        names = [t for t in order if t in base_tests or t in patch_tests]
        per_test = [results[t] for t in names]
        findings.append(Finding(
            id="",
            category=category,
            tests=[finding_test(results[t], _on_patch(results[t], key)) for t in names],
            signature=sigs[0],
            error_type=key.error_type,
            release=profile_summary(per_test, Profile.RELEASE),
            sanitized=profile_summary(per_test, Profile.SANITIZED),
            evidence=[f"runs/{t}/" for t in names],
            notes=_crash_notes(category, key, base_tests, patch_tests, sigs,
                               [t for t in names
                                if any(results[t][b].flaky for b in (_BS, _PS) if b in results[t])]),
        ))
    return findings


def _on_patch(per_build: dict[BuildName, CombinedResult], key: BugKey) -> Optional[OnPatch]:
    """What a test of the finding for ``key`` does on patch (§12.4).

    ``reaches``: still a stable crash with this bug key. ``other_error``: a
    crash with another key, or without one (reported elsewhere). ``blocked``:
    no crash. None when the patch result is flaky, because then it is not
    known (the test has its own ``INCONCLUSIVE`` finding, §8.5).
    """
    r = per_build.get(_PS)
    if r is None or r.flaky:
        return None
    if r.outcome is not Outcome.CRASH:
        return OnPatch.BLOCKED
    return OnPatch.REACHES if stable_key(r) == key else OnPatch.OTHER_ERROR


def _crash_notes(category: Category, key: BugKey, base_tests: list[str],
                 patch_tests: list[str], sigs: list[str], flaky: list[str]) -> str:
    """One or two plain sentences, built only from the grouping."""
    if category is Category.FIXED:
        text = f"{key} occurs on base with {_names(base_tests)} and on patch with none of them."
    elif category is Category.INCOMPLETE_FIX:
        blocked = [t for t in base_tests if t not in patch_tests]
        text = f"{key} still occurs on patch with {_names(patch_tests)}"
        text += f"; the patch blocks {_names(blocked)}." if blocked else "."
    else:
        text = f"{key} occurs on patch with {_names(patch_tests)} and on base with none of them."
    if len(sigs) > 1:
        text += " Call paths differ: " + " | ".join(sigs) + "."
    if flaky:
        text += (f" A sanitized result of {_names(flaky)} is flaky and is not counted"
                 " here; it has its own INCONCLUSIVE finding.")
    return text


def _names(tests: list[str]) -> str:
    return ", ".join(tests)


# ---------------------------------------------------------------------------
# Crashes without a signature, and release-only crashes (§8.3)
# ---------------------------------------------------------------------------

# A stop the runner could not classify is not evidence of a security error
# (course spec §3.5, code 40).
_UNCLASSIFIED = (ErrorType.ABORT, ErrorType.UNKNOWN)


def unsigned_crash_findings(results: Results, tests: Optional[list[str]] = None) -> list[Finding]:
    """One finding per test for sanitized crashes that cannot be grouped (§8.3).

    Only stable results are used; a flaky test is handled by §8.5.

    | base-sanitized          | patch-sanitized                        | finding        |
    |-------------------------|----------------------------------------|----------------|
    | crash, no signature     | no crash                               | FIXED          |
    | no crash                | crash, no signature, known error type  | NEW_ISSUE      |
    | no crash                | crash, no signature, ABORT or UNKNOWN  | INCONCLUSIVE   |
    | crash, no signature     | crash (with or without signature)      | INCONCLUSIVE   |
    | crash with a signature  | crash, no signature                    | INCONCLUSIVE   |

    The last row is not in the table of §8.3: the base crash is in a crash
    finding of §8.2 (marked ``other_error`` on patch), but nothing would say
    that the patch still crashes. As in the row above it, there is no way to
    tell whether it is the same error, so it is ``INCONCLUSIVE``.
    """
    findings: list[Finding] = []
    for test in (list(tests) if tests is not None else list(results)):
        per_build = results[test]
        b, p = per_build.get(_BS), per_build.get(_PS)
        if b is None or p is None or b.flaky or p.flaky:
            continue
        b_crash, p_crash = b.outcome is Outcome.CRASH, p.outcome is Outcome.CRASH
        b_unsigned = b_crash and bug_key(b.first.analysis) is None
        p_unsigned = p_crash and bug_key(p.first.analysis) is None
        if not (b_unsigned or p_unsigned):
            continue

        if b_unsigned and not p_crash:
            findings.append(_test_finding(
                Category.FIXED, per_build, _etype(b), OnPatch.BLOCKED,
                f"The base crash ({describe(b)}) has no stack trace with function names; "
                f"it no longer occurs on patch ({describe(p)})."))
        elif b_unsigned:
            also = " The patch crash is also in its own crash finding." \
                if not p_unsigned else ""
            findings.append(_test_finding(
                Category.INCONCLUSIVE, per_build, _etype(b), None,
                f"The base crash ({describe(b)}) has no stack trace with function names and "
                f"patch also crashes ({describe(p)}), so it cannot be told whether it is "
                f"the same error.{also}"))
        elif not b_crash:
            etype = _etype(p)
            if etype in _UNCLASSIFIED:
                findings.append(_test_finding(
                    Category.INCONCLUSIVE, per_build, etype, None,
                    f"The patch stops with {etype.value} ({describe(p)}) and no stack trace "
                    f"with function names, and base does not crash; an unclassified stop "
                    f"is not enough evidence of a security error."))
            else:
                findings.append(_test_finding(
                    Category.NEW_ISSUE, per_build, etype, OnPatch.REACHES,
                    f"The patch crashes with {etype.value} ({describe(p)}) and no stack "
                    f"trace with function names; base does not crash ({describe(b)})."))
        else:  # base crash with a signature, patch crash without one
            findings.append(_test_finding(
                Category.INCONCLUSIVE, per_build, _etype(p), None,
                f"Base crashes with {b.signature}, but the patch crash ({describe(p)}) has "
                f"no stack trace with function names, so it cannot be told whether it is "
                f"the same error."))
    return findings


def release_only_findings(results: Results, tests: Optional[list[str]] = None) -> list[Finding]:
    """``INCONCLUSIVE`` for a test whose release build crashes while the
    sanitized build of the same version does not (§8.3).

    The release build is the real program, so the crash must be reported, but
    without a sanitizer report it cannot be classified. One finding per test,
    naming every version where this happens. Flaky results are left to §8.5.
    """
    findings: list[Finding] = []
    for test in (list(tests) if tests is not None else list(results)):
        per_build = results[test]
        parts: list[str] = []
        etype: Optional[ErrorType] = None
        for version in (Version.BASE, Version.PATCH):
            rel = per_build.get(BuildName.of(version, Profile.RELEASE))
            san = per_build.get(BuildName.of(version, Profile.SANITIZED))
            if rel is None or san is None or rel.flaky or san.flaky:
                continue
            if rel.outcome is Outcome.CRASH and san.outcome is not Outcome.CRASH:
                parts.append(f"on {version.value} the release build crashes ({describe(rel)}) "
                             f"but the sanitized build does not ({describe(san)})")
                etype = etype or _etype(rel)
        if parts:
            text = "; ".join(parts)
            findings.append(_test_finding(
                Category.INCONCLUSIVE, per_build, etype, None,
                text[0].upper() + text[1:] + ". Without a sanitizer report the crash "
                "cannot be classified."))
    return findings


def _etype(result: CombinedResult) -> ErrorType:
    return result.first.analysis.error_type or ErrorType.UNKNOWN


def _test_finding(category: Category, per_build: dict[BuildName, CombinedResult],
                  error_type: Optional[ErrorType], on_patch: Optional[OnPatch],
                  notes: str) -> Finding:
    """A finding about one test, with no signature (§8.1: one finding per test)."""
    ft = finding_test(per_build, on_patch)
    per_test = [per_build]
    return Finding(
        id="",
        category=category,
        tests=[ft],
        signature=None,
        error_type=error_type,
        release=profile_summary(per_test, Profile.RELEASE),
        sanitized=profile_summary(per_test, Profile.SANITIZED),
        evidence=[f"runs/{ft.test}/"],
        notes=notes,
    )
