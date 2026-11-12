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
    CombinedResult,
    ErrorType,
    FindingTest,
    Frame,
    OnPatch,
    Outcome,
    Profile,
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
