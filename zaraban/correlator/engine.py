"""Patch-to-Finding Correlation Engine for Zaraban (Section 3.1).

Maps runtime crash stack traces, modified files, and functions against
the Git diff to determine correlation strength and classify findings into:
- Fixed (برطرف‌شده در محدودۀ آزمون‌ها)
- Incomplete Fix (وصلۀ ناقص یا باقی‌مانده)
- New Issue (خطای تازه مشاهده‌شده)
- Functional Regression (پسرفت عملکردی)
- Inconclusive (وضعیت نامشخص)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from zaraban.correlator.diff_parser import PatchDiff, DiffHunk, FileDiff
from zaraban.correlator.crash_parser import CrashReport, StackFrame


class CorrelationStrength(str, Enum):
    DIRECT_HUNK_MATCH = "DirectHunkMatch"          # Exact file & line in modified hunk
    MODIFIED_FUNCTION_MATCH = "ModifiedFunctionMatch" # Crash inside modified function
    CALLER_CALLEE_MATCH = "CallerCalleeMatch"        # Crash in caller/callee of modified function
    UNRELATED_OR_INCONCLUSIVE = "Inconclusive"      # Insufficient evidence to correlate


class FindingCategory(str, Enum):
    FIXED = "Fixed"
    INCOMPLETE_FIX = "Incomplete Fix"
    NEW_ISSUE = "New Issue"
    FUNCTIONAL_REGRESSION = "Functional Regression"
    INCONCLUSIVE = "Inconclusive"


@dataclass
class CorrelationEvidence:
    strength: CorrelationStrength
    matched_frame: Optional[StackFrame] = None
    matched_file: Optional[str] = None
    matched_function: Optional[str] = None
    matched_hunk: Optional[DiffHunk] = None
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "strength": self.strength.value,
            "matched_file": self.matched_file,
            "matched_function": self.matched_function,
            "matched_line": self.matched_frame.line if self.matched_frame else None,
            "details": self.details
        }


@dataclass
class PatchFinding:
    test_name: str
    category: FindingCategory
    evidence: CorrelationEvidence
    base_crash: Optional[CrashReport] = None
    patch_crash: Optional[CrashReport] = None
    is_regression: bool = False
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_name": self.test_name,
            "category": self.category.value,
            "is_regression": self.is_regression,
            "correlation": self.evidence.to_dict(),
            "details": self.details,
            "base_crash": self.base_crash.to_dict() if self.base_crash else None,
            "patch_crash": self.patch_crash.to_dict() if self.patch_crash else None,
        }


class CorrelationEngine:
    """Correlates crash stack traces with git diff hunks and modified functions."""

    @classmethod
    def correlate_crash_with_diff(
        cls,
        crash: CrashReport,
        diff: Optional[PatchDiff]
    ) -> CorrelationEvidence:
        """Analyze crash call stack against diff hunks and modified functions."""
        if not diff or not diff.files:
            return CorrelationEvidence(
                strength=CorrelationStrength.UNRELATED_OR_INCONCLUSIVE,
                details="No diff provided or diff is empty"
            )

        if not crash.stack_frames:
            # If no stack frames available (e.g. signal without symbolication)
            return CorrelationEvidence(
                strength=CorrelationStrength.UNRELATED_OR_INCONCLUSIVE,
                details="No symbolized stack frames available to establish correlation"
            )

        # 1. First pass: Look for direct line-level hunk matches in top stack frames
        for frame in crash.stack_frames:
            if not frame.filename:
                continue

            file_diff = diff.get_file(frame.filename)
            if file_diff and frame.line is not None:
                for hunk in file_diff.hunks:
                    if hunk.contains_new_line(frame.line):
                        return CorrelationEvidence(
                            strength=CorrelationStrength.DIRECT_HUNK_MATCH,
                            matched_frame=frame,
                            matched_file=file_diff.filename,
                            matched_function=frame.function,
                            matched_hunk=hunk,
                            details=f"Crash frame #{frame.index} ({frame.function} at {frame.filename}:{frame.line}) is directly inside modified diff hunk [+{hunk.new_start},{hunk.new_count}]"
                        )

        # 2. Second pass: Look for function-level matches in modified functions
        all_mod_funcs = diff.all_modified_functions
        for frame in crash.stack_frames:
            if frame.function in all_mod_funcs:
                return CorrelationEvidence(
                    strength=CorrelationStrength.MODIFIED_FUNCTION_MATCH,
                    matched_frame=frame,
                    matched_file=frame.basename,
                    matched_function=frame.function,
                    details=f"Crash frame #{frame.index} ({frame.function}) is one of the functions modified in the patch diff"
                )

        # 3. Third pass: Check caller-callee relationship (stack frames within depth 3)
        for i, frame in enumerate(crash.stack_frames[:4]):
            for other_frame in crash.stack_frames:
                if other_frame.function in all_mod_funcs and other_frame.function != frame.function:
                    return CorrelationEvidence(
                        strength=CorrelationStrength.CALLER_CALLEE_MATCH,
                        matched_frame=frame,
                        matched_file=frame.basename,
                        matched_function=other_frame.function,
                        details=f"Crash frame #{frame.index} ({frame.function}) called by or in call chain of modified function {other_frame.function}"
                    )

        # 4. If frame file matches modified file even if line/func is slightly displaced
        for frame in crash.stack_frames:
            if frame.filename and diff.get_file(frame.filename):
                return CorrelationEvidence(
                    strength=CorrelationStrength.CALLER_CALLEE_MATCH,
                    matched_frame=frame,
                    matched_file=frame.basename,
                    matched_function=frame.function,
                    details=f"Crash occurred in file {frame.filename} which was modified by the patch, but outside directly modified hunks"
                )

        return CorrelationEvidence(
            strength=CorrelationStrength.UNRELATED_OR_INCONCLUSIVE,
            details="Crash location shows no verifiable connection to files or functions modified in the patch diff"
        )

    @classmethod
    def classify_finding(
        cls,
        test_name: str,
        base_crash: Optional[CrashReport],
        patch_crash: Optional[CrashReport],
        diff: Optional[PatchDiff],
        is_valid_test: bool = False,
        base_exit_code: int = 0,
        patch_exit_code: int = 0
    ) -> PatchFinding:
        """Classify a test result into one of the 5 standard categories."""
        # 1. Functional Regression check on valid tests:
        if is_valid_test:
            if base_exit_code == 0 and patch_exit_code != 0:
                return PatchFinding(
                    test_name=test_name,
                    category=FindingCategory.FUNCTIONAL_REGRESSION,
                    evidence=CorrelationEvidence(
                        strength=CorrelationStrength.DIRECT_HUNK_MATCH if diff else CorrelationStrength.UNRELATED_OR_INCONCLUSIVE,
                        details=f"Valid functional test passed on Base (exit 0) but failed on Patched version (exit {patch_exit_code})"
                    ),
                    base_crash=base_crash,
                    patch_crash=patch_crash,
                    is_regression=True,
                    details=f"Functional regression detected in test '{test_name}'"
                )

        # 2. If Base crashed, but Patch did NOT crash:
        if base_crash and not patch_crash:
            return PatchFinding(
                test_name=test_name,
                category=FindingCategory.FIXED,
                evidence=CorrelationEvidence(
                    strength=CorrelationStrength.DIRECT_HUNK_MATCH,
                    details="Base vulnerability successfully reproduced; patched version executed safely without crash"
                ),
                base_crash=base_crash,
                patch_crash=None,
                is_regression=False,
                details=f"Vulnerability resolved in '{test_name}' within test boundaries"
            )

        # 3. If Patch crashed:
        if patch_crash:
            evidence = cls.correlate_crash_with_diff(patch_crash, diff)

            if base_crash is not None:
                # Base crashed AND Patch crashed
                same_signal = (base_crash.signal_num == patch_crash.signal_num and base_crash.signal_num is not None)
                same_mech = (base_crash.detection_mechanism == patch_crash.detection_mechanism)

                is_correlated = evidence.strength in (
                    CorrelationStrength.DIRECT_HUNK_MATCH,
                    CorrelationStrength.MODIFIED_FUNCTION_MATCH,
                    CorrelationStrength.CALLER_CALLEE_MATCH
                ) or (same_signal and same_mech)

                if is_correlated:
                    if evidence.strength == CorrelationStrength.UNRELATED_OR_INCONCLUSIVE:
                        evidence.strength = CorrelationStrength.CALLER_CALLEE_MATCH
                        evidence.details = f"Comparative execution evidence: Both Base and Patched versions trigger matching crash signature ({patch_crash.detection_mechanism})"
                    return PatchFinding(
                        test_name=test_name,
                        category=FindingCategory.INCOMPLETE_FIX,
                        evidence=evidence,
                        base_crash=base_crash,
                        patch_crash=patch_crash,
                        is_regression=False,
                        details=f"Vulnerability remains or incomplete patch bypass in '{test_name}' ({evidence.details})"
                    )
                else:
                    return PatchFinding(
                        test_name=test_name,
                        category=FindingCategory.INCONCLUSIVE,
                        evidence=evidence,
                        base_crash=base_crash,
                        patch_crash=patch_crash,
                        is_regression=False,
                        details=f"Crash observed in '{test_name}', but correlation evidence with patch diff is insufficient"
                    )
            else:
                # Base did NOT crash, but Patch DID crash
                if evidence.strength != CorrelationStrength.UNRELATED_OR_INCONCLUSIVE:
                    return PatchFinding(
                        test_name=test_name,
                        category=FindingCategory.NEW_ISSUE,
                        evidence=evidence,
                        base_crash=base_crash,
                        patch_crash=patch_crash,
                        is_regression=True,
                        details=f"New crash introduced in patched version in '{test_name}' ({evidence.details})"
                    )
                else:
                    return PatchFinding(
                        test_name=test_name,
                        category=FindingCategory.INCONCLUSIVE,
                        evidence=evidence,
                        base_crash=base_crash,
                        patch_crash=patch_crash,
                        is_regression=False,
                        details=f"Newly observed crash in '{test_name}', but correlation evidence with patch diff is inconclusive"
                    )

        # 4. Neither Base nor Patch crashed:
        return PatchFinding(
            test_name=test_name,
            category=FindingCategory.FIXED if not is_valid_test else FindingCategory.FIXED,
            evidence=CorrelationEvidence(
                strength=CorrelationStrength.UNRELATED_OR_INCONCLUSIVE,
                details="Test executed cleanly on both versions without abnormal crash"
            ),
            base_crash=None,
            patch_crash=None,
            is_regression=False,
            details="No error observed"
        )
