"""Crash analysis and stack trace parser for Zaraban (Section 3.1 & 3.2).

Parses execution stderr/stdout, signals, and sanitizer reports to extract:
- Error Type (e.g. StackBufferOverflow, HeapBufferOverflow, UAF, NullDeref)
- Detection Mechanism (ASan, UBSan, Stack Canary, OS Signal, ResourceLimit)
- Stack Trace Frames (Frame#, Function, File, Line, Address)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
import re


class ErrorType:
    STACK_BUFFER_OVERFLOW = "StackBufferOverflow"
    HEAP_BUFFER_OVERFLOW = "HeapBufferOverflow"
    GLOBAL_BUFFER_OVERFLOW = "GlobalBufferOverflow"
    USE_AFTER_FREE = "UseAfterFree"
    DOUBLE_FREE = "DoubleFree"
    NULL_POINTER_DEREF = "NullPointerDereference"
    DIVISION_BY_ZERO = "DivisionByZero"
    STACK_CANARY_CORRUPTION = "StackCanaryCorruption"
    SEGMENTATION_FAULT = "SegmentationFault"
    CPU_LIMIT_EXCEEDED = "CPULimitExceeded"
    TIMEOUT_EXCEEDED = "TimeoutExceeded"
    UNKNOWN_CRASH = "UnknownCrash"


@dataclass
class StackFrame:
    index: int
    function: str
    filename: Optional[str] = None
    line: Optional[int] = None
    address: Optional[str] = None
    raw_frame: str = ""

    @property
    def basename(self) -> Optional[str]:
        return Path(self.filename).name if self.filename else None


@dataclass
class CrashReport:
    error_type: str
    detection_mechanism: str
    signal_name: Optional[str] = None
    signal_num: Optional[int] = None
    exit_code: int = 0
    stack_frames: list[StackFrame] = field(default_factory=list)
    raw_summary: str = ""
    is_flaky: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "error_type": self.error_type,
            "detection_mechanism": self.detection_mechanism,
            "signal_name": self.signal_name,
            "signal_num": self.signal_num,
            "exit_code": self.exit_code,
            "summary": self.raw_summary,
            "stack_frames": [
                {
                    "index": f.index,
                    "function": f.function,
                    "filename": f.basename,
                    "line": f.line,
                    "address": f.address
                }
                for f in self.stack_frames
            ]
        }


class CrashParser:
    """Extracts structured crash data and call stacks from execution output."""

    # ASan stack line pattern:
    # #0 0x10484be48 in handle_set_command /workspace/targets/src/main.c:32:5
    # or #0 0x7f... in func (binary+0x...)
    ASAN_FRAME_RE = re.compile(
        r"^\s*#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+([a-zA-Z0-9_:~]+)(?:\s+([^\s:]+):(\d+)(?::\d+)?)?"
    )

    # Simplified frame pattern: #0 0x... in func file:line
    GENERIC_FRAME_RE = re.compile(
        r"^\s*#(\d+)\s+(?:0x[0-9a-fA-F]+\s+in\s+)?([a-zA-Z0-9_:~]+)(?:\s+([^\s:]+):(\d+))?"
    )

    @classmethod
    def parse_execution(
        cls,
        stdout: str,
        stderr: str,
        exit_code: int,
        signal_num: Optional[int] = None,
        signal_name: Optional[str] = None,
        timed_out: bool = False,
        cpu_exceeded: bool = False
    ) -> Optional[CrashReport]:
        """Parse execution outputs and identify if an abnormal crash occurred."""
        combined = (stderr + "\n" + stdout).strip()

        # 1. Resource limits
        if timed_out:
            return CrashReport(
                error_type=ErrorType.TIMEOUT_EXCEEDED,
                detection_mechanism="ResourceLimit/Timeout",
                exit_code=exit_code,
                raw_summary="Execution exceeded wall-clock timeout limit"
            )

        if cpu_exceeded or signal_num == 24:  # SIGXCPU
            return CrashReport(
                error_type=ErrorType.CPU_LIMIT_EXCEEDED,
                detection_mechanism="ResourceLimit/CPU",
                signal_name="SIGXCPU",
                signal_num=24,
                exit_code=exit_code,
                raw_summary="Execution exceeded CPU time limit (SIGXCPU)"
            )

        # 2. AddressSanitizer detections
        if "AddressSanitizer" in combined:
            error_type = ErrorType.UNKNOWN_CRASH
            if "stack-buffer-overflow" in combined:
                error_type = ErrorType.STACK_BUFFER_OVERFLOW
            elif "heap-buffer-overflow" in combined:
                error_type = ErrorType.HEAP_BUFFER_OVERFLOW
            elif "global-buffer-overflow" in combined:
                error_type = ErrorType.GLOBAL_BUFFER_OVERFLOW
            elif "heap-use-after-free" in combined:
                error_type = ErrorType.USE_AFTER_FREE
            elif "attempting double-free" in combined:
                error_type = ErrorType.DOUBLE_FREE
            elif "SEGV on unknown address 0x000000000000" in combined or "null-dereference" in combined:
                error_type = ErrorType.NULL_POINTER_DEREF
            elif "SEGV on unknown address" in combined:
                error_type = ErrorType.SEGMENTATION_FAULT

            frames = cls._extract_stack_frames(combined)
            summary_line = cls._find_summary_line(combined, "AddressSanitizer")

            return CrashReport(
                error_type=error_type,
                detection_mechanism="Sanitizer/ASan",
                signal_name=signal_name,
                signal_num=signal_num,
                exit_code=exit_code,
                stack_frames=frames,
                raw_summary=summary_line
            )

        # 3. UndefinedBehaviorSanitizer detections
        if "UndefinedBehaviorSanitizer" in combined or "runtime error:" in combined:
            error_type = ErrorType.UNKNOWN_CRASH
            if "division by zero" in combined:
                error_type = ErrorType.DIVISION_BY_ZERO
            elif "null pointer" in combined:
                error_type = ErrorType.NULL_POINTER_DEREF
            elif "index out of bounds" in combined:
                error_type = ErrorType.STACK_BUFFER_OVERFLOW

            frames = cls._extract_stack_frames(combined)
            summary_line = cls._find_summary_line(combined, "runtime error:")

            return CrashReport(
                error_type=error_type,
                detection_mechanism="Sanitizer/UBSan",
                signal_name=signal_name,
                signal_num=signal_num,
                exit_code=exit_code,
                stack_frames=frames,
                raw_summary=summary_line
            )

        # 4. Binary Stack Canary protection (__stack_chk_fail)
        if "*** buffer overflow detected ***" in combined or "__stack_chk_fail" in combined:
            frames = cls._extract_stack_frames(combined)
            return CrashReport(
                error_type=ErrorType.STACK_CANARY_CORRUPTION,
                detection_mechanism="BinaryProtection/StackCanary",
                signal_name=signal_name or "SIGABRT",
                signal_num=signal_num or 6,
                exit_code=exit_code,
                stack_frames=frames,
                raw_summary="Stack canary corruption detected (__stack_chk_fail)"
            )

        # 5. Native OS Signals
        if signal_num is not None or exit_code < 0 or exit_code in (139, 134, 136, 138, 133):
            # Translate exit codes > 128 to signals: 139 -> 11 (SIGSEGV), 134 -> 6 (SIGABRT), 136 -> 8 (SIGFPE)
            effective_sig = signal_num if signal_num is not None else (-exit_code if exit_code < 0 else exit_code - 128)
            effective_name = signal_name

            if effective_sig == 11:
                effective_name = "SIGSEGV"
                error_type = ErrorType.SEGMENTATION_FAULT
            elif effective_sig == 6:
                effective_name = "SIGABRT"
                error_type = ErrorType.STACK_CANARY_CORRUPTION if "abort" in combined else ErrorType.UNKNOWN_CRASH
            elif effective_sig == 8:
                effective_name = "SIGFPE"
                error_type = ErrorType.DIVISION_BY_ZERO
            elif effective_sig == 5:
                effective_name = "SIGTRAP"
                error_type = ErrorType.UNKNOWN_CRASH
            else:
                error_type = ErrorType.UNKNOWN_CRASH

            frames = cls._extract_stack_frames(combined)
            return CrashReport(
                error_type=error_type,
                detection_mechanism=f"OS_Signal/{effective_name or effective_sig}",
                signal_name=effective_name,
                signal_num=effective_sig,
                exit_code=exit_code,
                stack_frames=frames,
                raw_summary=f"Process terminated by OS signal {effective_name} (signal {effective_sig})"
            )

        # Non-zero exit code alone is NOT an abnormal memory crash per spec!
        # "هر کد خروج غیرصفر، معیار حفظ همان خطا نیست."
        return None

    @classmethod
    def _extract_stack_frames(cls, text: str) -> list[StackFrame]:
        frames = []
        for line in text.splitlines():
            m = cls.ASAN_FRAME_RE.match(line)
            if m:
                idx = int(m.group(1))
                addr = m.group(2)
                func = m.group(3)
                filename = m.group(4)
                lineno = int(m.group(5)) if m.group(5) else None
                frames.append(StackFrame(
                    index=idx,
                    function=func,
                    filename=filename,
                    line=lineno,
                    address=addr,
                    raw_frame=line.strip()
                ))
            else:
                gm = cls.GENERIC_FRAME_RE.match(line)
                if gm:
                    idx = int(gm.group(1))
                    func = gm.group(2)
                    filename = gm.group(3)
                    lineno = int(gm.group(4)) if gm.group(4) else None
                    frames.append(StackFrame(
                        index=idx,
                        function=func,
                        filename=filename,
                        line=lineno,
                        raw_frame=line.strip()
                    ))
        return frames

    @classmethod
    def _find_summary_line(cls, text: str, keyword: str) -> str:
        for line in text.splitlines():
            if keyword in line:
                return line.strip()
        return ""
