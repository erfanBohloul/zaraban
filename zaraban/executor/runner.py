"""Executor runner compatibility module for Zaraban."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

from zaraban.runner import (
    SafeRunner,
    run_once,
    run_env,
    combine,
    MAX_OUTPUT_BYTES,
)


@dataclass
class ExecutionResult:
    """Detailed result of a binary execution run (backward-compatibility model)."""
    stdout: str
    stderr: str
    exit_code: int
    signal_num: Optional[int] = None
    signal_name: Optional[str] = None
    timed_out: bool = False
    cpu_limit_exceeded: bool = False
    memory_limit_exceeded: bool = False
    peak_rss_kb: int = 0
    duration_seconds: float = 0.0
    detection_mechanism: Optional[str] = None
    error_summary: Optional[str] = None

    @property
    def is_crash(self) -> bool:
        """Determines if the termination represents an abnormal crash or signal."""
        if self.signal_num is not None or self.signal_name is not None:
            return True
        if "AddressSanitizer" in self.stderr or "UndefinedBehaviorSanitizer" in self.stderr:
            return True
        if "*** buffer overflow detected ***" in self.stderr or "__stack_chk_fail" in self.stderr:
            return True
        if "*** stack smashing detected ***" in self.stderr:
            return True
        return False


__all__ = [
    "SafeRunner",
    "ExecutionResult",
    "run_once",
    "run_env",
    "combine",
    "MAX_OUTPUT_BYTES",
]
