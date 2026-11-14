"""Crash and termination analysis for Zaraban.

Decides the run outcome, detection mechanism, error type, parses sanitizer
stack traces, and computes crash signatures.
"""

from __future__ import annotations

import re
from typing import Optional, Sequence

from .models import Analysis, Detection, ErrorType, Frame, LimitKind, Outcome

ASAN_ERROR_RE = re.compile(r"ERROR: AddressSanitizer: ([\w-]+)")
ASAN_SEGV_ADDR_RE = re.compile(r"SEGV on unknown address (0x[0-9a-fA-F]+)")
UBSAN_RE = re.compile(r"runtime error: (.*)")
FRAME_RE = re.compile(
    r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)(?:\s+(?:(\S+?):(\d+)(?::\d+)?|\(([^)]+)\)))?",
    re.M,
)

RUNTIME_PREFIX = ("__asan_", "__interceptor_", "__sanitizer_", "__ubsan_", "__libc_")
RUNTIME_LIBS = ("libasan", "libubsan", "libc.", "libc-", "ld-linux")

# C library functions that AddressSanitizer intercepts. clang links the ASan
# runtime into the program, so these interceptors show up in the program's own
# module, without a source location: "#0 0x… in free (/path/prog+0x…)". They
# are runtime frames, not application code.
LIBC_INTERCEPTED = frozenset({
    "malloc", "calloc", "realloc", "free", "cfree", "reallocarray", "memalign",
    "posix_memalign", "aligned_alloc", "valloc", "pvalloc", "malloc_usable_size",
    "memcpy", "memmove", "memset", "memcmp", "bcmp", "memchr", "memrchr", "memmem",
    "strcpy", "strncpy", "stpcpy", "strcat", "strncat", "strlen", "strnlen", "strdup",
    "strndup", "strcmp", "strncmp", "strcasecmp", "strncasecmp", "strchr", "strrchr",
    "strstr", "strcasestr", "strspn", "strcspn", "strpbrk", "strtok", "strtol", "strtoul",
    "strtoll", "strtoull", "atoi", "atol", "atoll", "sprintf", "snprintf", "vsprintf",
    "vsnprintf", "printf", "vprintf", "fprintf", "vfprintf", "puts", "fputs", "fwrite",
    "fread", "fgets", "read", "write", "sscanf", "vsscanf", "scanf", "fscanf",
})
_OPERATOR_NEW_DELETE = ("operator new", "operator delete", "_Znw", "_Zna", "_Zdl", "_Zda")

# The C library's start-up code, linked into every program (crt1.o): it calls
# main, so it is below main in every stack and is not application code.
C_STARTUP = frozenset({"_start", "__libc_start_main", "__libc_start_call_main"})

ASAN_TYPE_MAP: dict[str, ErrorType] = {
    "stack-buffer-overflow": ErrorType.STACK_BUFFER_OVERFLOW,
    "dynamic-stack-buffer-overflow": ErrorType.STACK_BUFFER_OVERFLOW,
    "heap-buffer-overflow": ErrorType.HEAP_BUFFER_OVERFLOW,
    "global-buffer-overflow": ErrorType.GLOBAL_BUFFER_OVERFLOW,
    "heap-use-after-free": ErrorType.USE_AFTER_FREE,
    "stack-use-after-scope": ErrorType.USE_AFTER_SCOPE,
    "stack-use-after-return": ErrorType.USE_AFTER_SCOPE,
    "stack-overflow": ErrorType.STACK_EXHAUSTION,
}

ZERO_PAGE = 0x1000  # first page; a SEGV there is a NULL dereference

# AddressSanitizer's report when an allocation exceeds max_allocation_size_mb,
# the memory limit of sanitized builds.
ASAN_MEMORY_LIMIT = ("allocation-size-too-big", "exceeds maximum supported size",
                     "allocator is out of memory", "out-of-memory")


def is_memory_limit(stderr: str) -> bool:
    """True when a sanitized run hit its memory limit (rule 2 of :func:`outcome`)."""
    return "ERROR: AddressSanitizer" in stderr and any(s in stderr for s in ASAN_MEMORY_LIMIT)

ALLOCATOR_CHECK_STRINGS = (
    "double free detected",
    "double free or corruption",
    "free(): invalid pointer",
    "malloc(): corrupted",
    "corrupted double-linked list",
    "corrupted size vs. prev_size",
    "munmap_chunk(): invalid pointer",
)


def outcome(
    stderr: str,
    sig: Optional[str] = None,
    timed_out: bool = False,
    limit_hit: Optional[LimitKind] = None,
) -> tuple[Outcome, Optional[Detection]]:
    """Determine the run outcome and detection mechanism.

    We agreed on this rule order; the first match wins:
    1. Timed out -> TIMEOUT
    2. SIGXCPU or memory limit hit -> RESOURCE_LIMIT
    3. AddressSanitizer report in stderr -> CRASH, ASAN
    4. UndefinedBehaviorSanitizer report in stderr and stopped -> CRASH, UBSAN
    5. Stack smashing detected -> CRASH, STACK_CANARY
    6. Buffer overflow detected -> CRASH, FORTIFY
    7. Glibc allocator check -> CRASH, ALLOCATOR_CHECK
    8. Fatal signal (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT, SIGTRAP) -> CRASH, SIGNAL
    9. Anything else (including non-zero exit codes) -> NORMAL, None
    """
    if timed_out:
        return Outcome.TIMEOUT, None

    if sig == "SIGXCPU" or limit_hit is not None:
        return Outcome.RESOURCE_LIMIT, None

    if "ERROR: AddressSanitizer" in stderr:
        return Outcome.CRASH, Detection.ASAN

    if "runtime error:" in stderr and sig:
        return Outcome.CRASH, Detection.UBSAN

    if "*** stack smashing detected ***" in stderr:
        return Outcome.CRASH, Detection.STACK_CANARY

    if "*** buffer overflow detected ***" in stderr:
        return Outcome.CRASH, Detection.FORTIFY

    if any(s in stderr for s in ALLOCATOR_CHECK_STRINGS):
        return Outcome.CRASH, Detection.ALLOCATOR_CHECK

    if sig in ("SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL", "SIGABRT", "SIGTRAP"):
        return Outcome.CRASH, Detection.SIGNAL

    # Any other exit, including non-zero without fatal signal or sanitizer
    return Outcome.NORMAL, None


def classify_error_type(
    stderr: str,
    sig: Optional[str] = None,
    detection: Optional[Detection] = None,
) -> Optional[ErrorType]:
    """Classify the crash error type from the sanitizer or runtime message.

    The mapping is in ``ASAN_TYPE_MAP`` and the branches below; it names the
    kind of error only and is not a root-cause analysis."""
    if detection is None:
        return None

    if detection is Detection.ASAN:
        m = ASAN_ERROR_RE.search(stderr)
        raw_type = m.group(1) if m else ""
        if raw_type in ASAN_TYPE_MAP:
            return ASAN_TYPE_MAP[raw_type]
        if "attempting double-free" in stderr:
            return ErrorType.DOUBLE_FREE
        if "attempting free on address which was not malloc()-ed" in stderr:
            return ErrorType.INVALID_FREE
        if raw_type == "SEGV":
            # NULL_DEREF only for an address in the zero page: ASan's own
            # hint, or an address below the 4 KiB page size.
            if "address points to the zero page" in stderr:
                return ErrorType.NULL_DEREF
            segv = ASAN_SEGV_ADDR_RE.search(stderr)
            if segv and int(segv.group(1), 16) < ZERO_PAGE:
                return ErrorType.NULL_DEREF
            return ErrorType.SEGV
        return ErrorType.UNKNOWN

    if detection is Detection.UBSAN:
        lower_err = stderr.lower()
        if "division by zero" in lower_err:
            return ErrorType.DIV_BY_ZERO
        if "signed integer overflow" in lower_err:
            return ErrorType.INTEGER_OVERFLOW
        if "index out of bounds" in lower_err or "out of bounds" in lower_err:
            return ErrorType.OUT_OF_BOUNDS_INDEX
        if "null pointer" in lower_err or "null dereference" in lower_err:
            return ErrorType.NULL_DEREF
        return ErrorType.UB_OTHER

    if detection is Detection.STACK_CANARY:
        return ErrorType.STACK_BUFFER_OVERFLOW

    if detection is Detection.FORTIFY:
        return ErrorType.BUFFER_OVERFLOW

    if detection is Detection.ALLOCATOR_CHECK:
        if "double free" in stderr:
            return ErrorType.DOUBLE_FREE
        if "invalid pointer" in stderr:
            return ErrorType.INVALID_FREE
        return ErrorType.HEAP_CORRUPTION

    if detection is Detection.SIGNAL:
        if sig in ("SIGSEGV", "SIGBUS"):
            if "zero page" in stderr or "address 0x0" in stderr:
                return ErrorType.NULL_DEREF
            return ErrorType.SEGV
        if sig == "SIGFPE":
            return ErrorType.DIV_BY_ZERO
        if sig == "SIGABRT":
            return ErrorType.ABORT
        return ErrorType.UNKNOWN

    return ErrorType.UNKNOWN


def frames(stderr: str, source_root: str = "") -> list[Frame]:
    """Parse stack frames from sanitizer stderr.

    Only frames up to the first blank line after #0 are parsed,
    preventing 'allocated by' or 'freed by' frames from leaking into the crash.
    """
    out: list[Frame] = []
    lines = stderr.splitlines()

    # Find the start of the first crash stack trace (marked by #0)
    start_idx = -1
    for i, line in enumerate(lines):
        if re.search(r"^\s*#0\s+0x", line):
            start_idx = i
            break

    if start_idx == -1:
        return out

    # Collect consecutive frames until the first empty line or section header
    relevant_lines: list[str] = []
    for line in lines[start_idx:]:
        if not line.strip():
            break
        # If line indicates a subsequent section (e.g. allocated by, freed by, Address is located)
        if any(line.strip().startswith(p) for p in ("allocated by", "freed by", "previously allocated", "Address 0x")):
            break
        relevant_lines.append(line)

    chunk = "\n".join(relevant_lines)
    for m in FRAME_RE.finditer(chunk):
        idx = int(m.group(1))
        fn = m.group(2)
        file_path = m.group(3)
        line_num = int(m.group(4)) if m.group(4) else None
        lib_path = m.group(5) if m.lastindex >= 5 else None

        # Determine if this frame is in runtime or standard libraries
        is_runtime = fn.startswith(RUNTIME_PREFIX) or fn in C_STARTUP or (
            file_path is None and (fn in LIBC_INTERCEPTED or fn.startswith(_OPERATOR_NEW_DELETE)))
        check_path = (file_path or lib_path or "").lower()
        if not is_runtime and check_path:
            if any(lib in check_path for lib in RUNTIME_LIBS):
                is_runtime = True

        # Strip source root from file path if present
        if file_path and source_root:
            if file_path.startswith(source_root):
                file_path = file_path[len(source_root):].lstrip("/")

        out.append(Frame(
            index=idx,
            function=fn,
            file=file_path,
            line=line_num,
            runtime=is_runtime,
        ))

    return out


def signature(error_type: Optional[ErrorType], frame_list: Sequence[Frame]) -> Optional[str]:
    """Compute the crash signature: ErrorType @ f1 < f2 < f3."""
    if error_type is None:
        return None

    names = [f.function for f in frame_list if not f.runtime and f.function][:3]
    if not names:
        return None

    return f"{error_type.value} @ {' < '.join(names)}"


def extract_summary(stderr: str, sig: Optional[str] = None) -> Optional[str]:
    """Extract a concise one-line summary from stderr or signal."""
    for line in stderr.splitlines():
        line_s = line.strip()
        if "ERROR: AddressSanitizer" in line_s or "runtime error:" in line_s:
            return line_s
        if "*** stack smashing detected ***" in line_s:
            return line_s
        if "*** buffer overflow detected ***" in line_s:
            return line_s
        if any(s in line_s for s in ALLOCATOR_CHECK_STRINGS):
            return line_s

    if sig:
        return f"Terminated by signal {sig}"
    return None


def analyse(
    stderr: str,
    stdout: str = "",
    exit_code: Optional[int] = None,
    sig: Optional[str] = None,
    timed_out: bool = False,
    limit_hit: Optional[LimitKind] = None,
    source_root: str = "",
) -> Analysis:
    """Analyze a single execution run and produce an Analysis model object."""
    out_outcome, detection = outcome(stderr, sig=sig, timed_out=timed_out, limit_hit=limit_hit)

    err_type = None
    stack_frames: list[Frame] = []
    sig_str = None
    summary = None

    if out_outcome is Outcome.CRASH:
        err_type = classify_error_type(stderr, sig=sig, detection=detection)
        stack_frames = frames(stderr, source_root=source_root)
        sig_str = signature(err_type, stack_frames)
        summary = extract_summary(stderr, sig=sig)
    elif out_outcome is Outcome.TIMEOUT:
        summary = "Execution timed out"
    elif out_outcome is Outcome.RESOURCE_LIMIT:
        summary = f"Resource limit exceeded ({limit_hit.value if limit_hit else 'cpu'})"

    return Analysis(
        outcome=out_outcome,
        detection=detection,
        error_type=err_type,
        summary=summary,
        frames=stack_frames,
        signature=sig_str,
    )
