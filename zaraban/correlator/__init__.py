"""Patch-to-Finding Correlation package for Zaraban."""

from zaraban.correlator.diff_parser import DiffParser, PatchDiff, DiffHunk, FileDiff
from zaraban.correlator.crash_parser import CrashParser, CrashReport, StackFrame, ErrorType
from zaraban.correlator.engine import (
    CorrelationEngine,
    CorrelationStrength,
    FindingCategory,
    CorrelationEvidence,
    PatchFinding
)

__all__ = [
    "DiffParser",
    "PatchDiff",
    "DiffHunk",
    "FileDiff",
    "CrashParser",
    "CrashReport",
    "StackFrame",
    "ErrorType",
    "CorrelationEngine",
    "CorrelationStrength",
    "FindingCategory",
    "CorrelationEvidence",
    "PatchFinding"
]
