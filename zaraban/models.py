"""Shared data types of Zaraban.

Every module exchanges data through these types, and ``report.json`` is a dump
of them (SPEC §12). They hold data only: no building, running or analysis
logic lives here. A change to this file needs review by all four members.

Section numbers such as §7.4 refer to docs/SPEC.md.

Ownership (who produces each type):
    A  TestCase, BuildRecord, HardeningResult, VersionInfo, EnvironmentInfo
    B  RunRecord, Analysis, Frame, OracleResult, CombinedResult
    C  Hunk, Finding, FindingTest, Link
    D  Bundle, Replay, RegressionTest, Condition, Status, Report
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from pathlib import Path
from typing import Any, Optional

SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class StrEnum(str, Enum):
    """String enum whose JSON form is its value (Python 3.10 has no enum.StrEnum)."""

    def __str__(self) -> str:
        return self.value


class Version(StrEnum):
    BASE = "base"
    PATCH = "patch"


class Profile(StrEnum):
    RELEASE = "release"
    SANITIZED = "sanitized"


class BuildName(StrEnum):
    """The four builds, in the order they are built and run (§6.1)."""

    BASE_RELEASE = "base-release"
    BASE_SANITIZED = "base-sanitized"
    PATCH_RELEASE = "patch-release"
    PATCH_SANITIZED = "patch-sanitized"

    @property
    def version(self) -> Version:
        return Version.BASE if self.value.startswith("base") else Version.PATCH

    @property
    def profile(self) -> Profile:
        return Profile.RELEASE if self.value.endswith("release") else Profile.SANITIZED

    @classmethod
    def of(cls, version: Version, profile: Profile) -> "BuildName":
        return cls(f"{version.value}-{profile.value}")


BUILD_ORDER: tuple[BuildName, ...] = (
    BuildName.BASE_RELEASE,
    BuildName.BASE_SANITIZED,
    BuildName.PATCH_RELEASE,
    BuildName.PATCH_SANITIZED,
)


class TestKind(StrEnum):
    """Kinds of test, in the order they run (§5.1, §7.1)."""

    __test__ = False  # not a pytest test class

    VALID = "valid"
    BOUNDARY = "boundary"
    INVALID = "invalid"
    SECURITY = "security"
    REGRESSION = "regression"


class InputMethod(StrEnum):
    FILE = "file"
    STDIN = "stdin"
    ARGS = "args"


class OutputMatch(StrEnum):
    CONTAINS = "contains"
    EXACT = "exact"


class Outcome(StrEnum):
    """How one run ended (§7.4). Only CRASH is a crash."""

    NORMAL = "NORMAL"
    CRASH = "CRASH"
    TIMEOUT = "TIMEOUT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"


class LimitKind(StrEnum):
    CPU = "cpu"
    MEMORY = "memory"


class Detection(StrEnum):
    """What detected a crash (§7.4)."""

    ASAN = "ASAN"
    UBSAN = "UBSAN"
    STACK_CANARY = "STACK_CANARY"
    FORTIFY = "FORTIFY"
    ALLOCATOR_CHECK = "ALLOCATOR_CHECK"
    SIGNAL = "SIGNAL"


class ErrorType(StrEnum):
    """What kind of error a crash was (§7.4). Not a root-cause analysis."""

    STACK_BUFFER_OVERFLOW = "STACK_BUFFER_OVERFLOW"
    HEAP_BUFFER_OVERFLOW = "HEAP_BUFFER_OVERFLOW"
    GLOBAL_BUFFER_OVERFLOW = "GLOBAL_BUFFER_OVERFLOW"
    BUFFER_OVERFLOW = "BUFFER_OVERFLOW"
    USE_AFTER_FREE = "USE_AFTER_FREE"
    USE_AFTER_SCOPE = "USE_AFTER_SCOPE"
    DOUBLE_FREE = "DOUBLE_FREE"
    INVALID_FREE = "INVALID_FREE"
    NULL_DEREF = "NULL_DEREF"
    SEGV = "SEGV"
    STACK_EXHAUSTION = "STACK_EXHAUSTION"
    DIV_BY_ZERO = "DIV_BY_ZERO"
    INTEGER_OVERFLOW = "INTEGER_OVERFLOW"
    OUT_OF_BOUNDS_INDEX = "OUT_OF_BOUNDS_INDEX"
    UB_OTHER = "UB_OTHER"
    HEAP_CORRUPTION = "HEAP_CORRUPTION"
    ABORT = "ABORT"
    UNKNOWN = "UNKNOWN"


class Category(StrEnum):
    """Finding categories (§8.1)."""

    FIXED = "FIXED"
    INCOMPLETE_FIX = "INCOMPLETE_FIX"
    NEW_ISSUE = "NEW_ISSUE"
    FUNCTIONAL_REGRESSION = "FUNCTIONAL_REGRESSION"
    INCONCLUSIVE = "INCONCLUSIVE"


class OnPatch(StrEnum):
    """What a test of a crash finding does on the patched version (§12.4)."""

    REACHES = "reaches"
    BLOCKED = "blocked"
    OTHER_ERROR = "other_error"


class LinkLevel(StrEnum):
    """Strength of the link between a finding and the diff, strongest first (§9.3)."""

    IN_CHANGED_HUNK = "IN_CHANGED_HUNK"
    IN_CHANGED_FUNCTION = "IN_CHANGED_FUNCTION"
    CHANGED_FUNCTION_IN_STACK = "CHANGED_FUNCTION_IN_STACK"
    CHANGED_CODE_EXECUTED = "CHANGED_CODE_EXECUTED"
    UNDETERMINED = "UNDETERMINED"


class Relro(StrEnum):
    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"


class HardeningChangeKind(StrEnum):
    DOWNGRADE = "downgrade"
    IMPROVEMENT = "improvement"


class RegressionStatus(StrEnum):
    ADDED = "added"
    ALREADY_PRESENT = "already_present"
    NOT_ADDED = "not_added"


class ExitCode(IntEnum):
    """Process exit codes (course spec §3.5, SPEC §13.1)."""

    PASS = 0
    VULN_REMAINS = 10  # also used for NEW_ISSUE
    FUNC_REGRESSION = 20
    BUILD_OR_CONFIG_ERROR = 30
    INCONCLUSIVE = 40


# When several conditions hold, the first code in this order wins (§13.1).
EXIT_PRIORITY: tuple[ExitCode, ...] = (
    ExitCode.BUILD_OR_CONFIG_ERROR,
    ExitCode.VULN_REMAINS,
    ExitCode.FUNC_REGRESSION,
    ExitCode.INCONCLUSIVE,
    ExitCode.PASS,
)


class ConditionName(StrEnum):
    """Reasons for an exit code (§13.3). NEW_ISSUE shares code 10."""

    BUILD_OR_CONFIG_ERROR = "BUILD_OR_CONFIG_ERROR"
    VULN_REMAINS = "VULN_REMAINS"
    NEW_ISSUE = "NEW_ISSUE"
    FUNC_REGRESSION = "FUNC_REGRESSION"
    INCONCLUSIVE = "INCONCLUSIVE"
    PASS = "PASS"

    @property
    def code(self) -> ExitCode:
        return {
            "BUILD_OR_CONFIG_ERROR": ExitCode.BUILD_OR_CONFIG_ERROR,
            "VULN_REMAINS": ExitCode.VULN_REMAINS,
            "NEW_ISSUE": ExitCode.VULN_REMAINS,
            "FUNC_REGRESSION": ExitCode.FUNC_REGRESSION,
            "INCONCLUSIVE": ExitCode.INCONCLUSIVE,
            "PASS": ExitCode.PASS,
        }[self.value]


class WarningCode(StrEnum):
    """Warnings never change the exit code (§12.6)."""

    NO_INVALID_TESTS = "NO_INVALID_TESTS"
    NO_DEBUG_INFO = "NO_DEBUG_INFO"
    FORTIFY_IN_SANITIZED = "FORTIFY_IN_SANITIZED"
    NO_SYMBOLIZER = "NO_SYMBOLIZER"
    OUTPUT_TRUNCATED = "OUTPUT_TRUNCATED"
    REPEATS_TOO_LOW = "REPEATS_TOO_LOW"
    REGRESSION_BASE_CLEAN = "REGRESSION_BASE_CLEAN"
    MINIMIZE_LIMIT = "MINIMIZE_LIMIT"
    REGRESSION_NOT_ADDED = "REGRESSION_NOT_ADDED"
    HARDENING_DOWNGRADE = "HARDENING_DOWNGRADE"
    TRACE_UNAVAILABLE = "TRACE_UNAVAILABLE"


class ErrorCode(StrEnum):
    """Every error gives exit code 30 (§12.6)."""

    ARGUMENT_INVALID = "ARGUMENT_INVALID"
    SOURCE_NOT_FOUND = "SOURCE_NOT_FOUND"
    PATCH_APPLY_FAILED = "PATCH_APPLY_FAILED"
    CONFIG_INVALID = "CONFIG_INVALID"
    BUILD_FAILED = "BUILD_FAILED"
    SANITIZER_MISSING = "SANITIZER_MISSING"
    PROFILE_MIXED = "PROFILE_MIXED"
    TOOL_INTERNAL = "TOOL_INTERNAL"


# ---------------------------------------------------------------------------
# Warnings, errors and the tool's own exception
# ---------------------------------------------------------------------------


@dataclass
class Issue:
    """One entry of report.json's ``warnings`` or ``errors`` (§12.6)."""

    code: str  # a WarningCode or ErrorCode value
    message: str
    details: dict[str, Any] = field(default_factory=dict)


class ZarabanError(Exception):
    """Raised by any module for a condition that must end the run with exit 30."""

    def __init__(self, code: ErrorCode, message: str, details: Optional[dict[str, Any]] = None):
        super().__init__(f"{code.value}: {message}")
        self.code = code
        self.message = message
        self.details = details or {}

    def to_issue(self) -> Issue:
        return Issue(self.code.value, self.message, self.details)


# ---------------------------------------------------------------------------
# Tests (producer: A, from the config and regression_dir)
# ---------------------------------------------------------------------------


@dataclass
class TestCase:
    """One test, ready to run: the config entry resolved to bytes (§4.4, §5)."""

    __test__ = False  # not a pytest test class

    name: str
    kind: TestKind
    input_bytes: Optional[bytes]  # None = no input
    input_ext: str = ""  # ".txt", ".json", ... used for input.<ext> (§5.3)
    args: list[str] = field(default_factory=list)
    description: Optional[str] = None
    source_path: Optional[str] = None  # where the input came from, for the report
    expected_exit_code: Optional[int] = None  # None = not checked
    expected_output: Optional[str] = None  # None = not checked
    output_match: OutputMatch = OutputMatch.CONTAINS
    # regression tests only (§10.6)
    expect_base_crash: Optional[bool] = None
    expected_signature: Optional[str] = None

    @property
    def has_oracle(self) -> bool:
        return self.expected_exit_code is not None or self.expected_output is not None


# ---------------------------------------------------------------------------
# Sources and builds (producer: A)
# ---------------------------------------------------------------------------


@dataclass
class VersionInfo:
    """``report.versions.base`` / ``.patch`` (§12.4)."""

    form: str  # "directory" | "diff"
    ref: str  # as given on the command line
    git_commit: Optional[str]
    tree_sha256: Optional[str]
    strip_level: Optional[int] = None  # only for form == "diff"


@dataclass
class DiffInfo:
    path: str
    sha256: str
    files: list[str]
    hunks: int


@dataclass
class BinaryInfo:
    path: str  # relative to the run directory
    size: int
    sha256: str


@dataclass
class BuildRecord:
    """``builds/<build>/build.json`` (§6.4, §12.3)."""

    build: BuildName
    status: str  # "ok" | "failed"
    cmd: str
    env: dict[str, str]
    cwd: str
    exit_code: Optional[int]  # None if the build timed out
    duration_s: float
    log: str  # path of build.log, relative to the run directory
    binary: Optional[BinaryInfo] = None
    sanitizers_verified: Optional[bool] = None  # None for release builds
    has_debug_info: Optional[bool] = None
    schema_version: int = SCHEMA_VERSION

    @property
    def version(self) -> Version:
        return self.build.version

    @property
    def profile(self) -> Profile:
        return self.build.profile

    @property
    def ok(self) -> bool:
        return self.status == "ok"


@dataclass
class EnvironmentInfo:
    """``report.environment`` (§12.4)."""

    os: str
    kernel: str
    arch: str
    docker_image: Optional[str]
    python: str
    gcc: Optional[str]
    clang: Optional[str]
    llvm_symbolizer: Optional[str]


# ---------------------------------------------------------------------------
# Hardening (producer: A, §11)
# ---------------------------------------------------------------------------


@dataclass
class ProtectionResult:
    value: Any  # bool for nx/pie/canary, Relro for relro
    evidence: str


@dataclass
class HardeningResult:
    """Protections of one release binary."""

    nx: ProtectionResult
    pie: ProtectionResult
    relro: ProtectionResult
    canary: ProtectionResult


@dataclass
class HardeningChange:
    protection: str  # "nx" | "pie" | "relro" | "canary"
    from_value: Any
    to_value: Any
    kind: HardeningChangeKind


HARDENING_NOTES: tuple[str, ...] = (
    "A PIE binary does not prove that ASLR is active at runtime.",
    "Evidence of a stack canary does not mean every function is protected.",
)


@dataclass
class HardeningReport:
    base: HardeningResult
    patch: HardeningResult
    changes: list[HardeningChange] = field(default_factory=list)
    notes: list[str] = field(default_factory=lambda: list(HARDENING_NOTES))


# ---------------------------------------------------------------------------
# Runs and their analysis (producer: B, §7)
# ---------------------------------------------------------------------------


@dataclass
class Frame:
    """One stack frame of a sanitizer report."""

    index: int
    function: Optional[str]
    file: Optional[str]  # relative to the source root, e.g. "src/main.c"
    line: Optional[int]
    runtime: bool  # inside the sanitizer runtime or libc (§7.4)


@dataclass
class Analysis:
    outcome: Outcome
    detection: Optional[Detection] = None  # set only for CRASH
    error_type: Optional[ErrorType] = None  # set only for CRASH
    summary: Optional[str] = None  # first line of the sanitizer/runtime report
    frames: list[Frame] = field(default_factory=list)
    signature: Optional[str] = None  # "ERROR_TYPE @ f1 < f2 < f3", or None

    @property
    def is_crash(self) -> bool:
        return self.outcome is Outcome.CRASH

    @property
    def app_frames(self) -> list[Frame]:
        """Frames outside the sanitizer runtime and libc."""
        return [f for f in self.frames if not f.runtime]


@dataclass
class OracleResult:
    checked: bool  # False when the test has no oracle fields
    passed: Optional[bool]  # None when not checked
    reasons: list[str] = field(default_factory=list)

    def __iter__(self):
        return iter((self.checked, self.passed, self.reasons))


@dataclass
class InputInfo:
    method: InputMethod
    name: Optional[str]  # "input.txt" for the file method
    size: int
    sha256: str


@dataclass
class StreamInfo:
    path: str  # relative to the run directory
    bytes: int
    sha256: str
    truncated: bool = False


@dataclass
class RunRecord:
    """``runs/<test>/<build>/<n>.json``: one execution (§12.3)."""

    test: str
    kind: TestKind
    build: BuildName
    repeat: int  # 1 ... repeats
    cmd: list[str]
    env: dict[str, str]
    cwd: str
    input: InputInfo
    exit_code: Optional[int]  # None when killed by a signal
    signal: Optional[str]  # "SIGSEGV", ... None when exited normally
    timed_out: bool
    limit_hit: Optional[LimitKind]
    duration_s: float
    stdout: StreamInfo
    stderr: StreamInfo
    analysis: Analysis
    oracle: OracleResult
    schema_version: int = SCHEMA_VERSION


@dataclass
class CombinedResult:
    """The repeats of one test on one build, combined (§7.5)."""

    test: str
    kind: TestKind
    build: BuildName
    runs: list[RunRecord]
    flaky: bool

    @property
    def first(self) -> RunRecord:
        return self.runs[0]

    @property
    def outcome(self) -> Outcome:
        return self.first.analysis.outcome

    @property
    def signature(self) -> Optional[str]:
        return self.first.analysis.signature

    @property
    def oracle_passed(self) -> Optional[bool]:
        return self.first.oracle.passed

    @property
    def stable_crash(self) -> bool:
        return not self.flaky and self.outcome is Outcome.CRASH


# results[test_name][build] -> CombinedResult
Results = dict[str, dict[BuildName, CombinedResult]]


# ---------------------------------------------------------------------------
# Diff (producer: C, §9.2)
# ---------------------------------------------------------------------------


@dataclass
class Hunk:
    file: str  # path after strip, e.g. "src/main.c"
    header: str  # "@@ -21,14 +21,19 @@"
    base_start: int
    base_end: int  # inclusive, includes context lines
    patch_start: int
    patch_end: int
    removed_lines: list[int] = field(default_factory=list)  # base line numbers
    added_lines: list[int] = field(default_factory=list)  # patch line numbers

    def contains(self, side: Version, file: str, line: int) -> bool:
        lo, hi = (
            (self.base_start, self.base_end)
            if side is Version.BASE
            else (self.patch_start, self.patch_end)
        )
        return file == self.file and lo <= line <= hi


# ---------------------------------------------------------------------------
# Findings and links (producer: C, §8, §9)
# ---------------------------------------------------------------------------


@dataclass
class BuildSummary:
    """Short per-build view of one test inside a finding (§12.4)."""

    outcome: Outcome
    detection: Optional[Detection] = None
    signal: Optional[str] = None
    exit_code: Optional[int] = None
    error_type: Optional[ErrorType] = None
    signature: Optional[str] = None
    oracle_passed: Optional[bool] = None
    flaky: bool = False


@dataclass
class FindingTest:
    test: str
    kind: TestKind
    results: dict[BuildName, BuildSummary]
    on_patch: Optional[OnPatch] = None  # crash findings only


@dataclass
class Link:
    """How a finding relates to the diff (§9.6)."""

    level: LinkLevel
    side: Optional[Version] = None
    file: Optional[str] = None
    function: Optional[str] = None
    line: Optional[int] = None
    frame: Optional[int] = None
    hunk: Optional[str] = None
    executed_changed_lines: Optional[list[int]] = None
    comparative_tests: list[str] = field(default_factory=list)
    explanation: str = ""


@dataclass
class Finding:
    """One reportable problem (§8.8)."""

    id: str  # "F-001"
    category: Category
    tests: list[FindingTest]
    signature: Optional[str] = None
    error_type: Optional[ErrorType] = None
    release: dict[str, str] = field(default_factory=dict)  # {"base": "...", "patch": "..."}
    sanitized: dict[str, str] = field(default_factory=dict)
    link: Optional[Link] = None
    evidence: list[str] = field(default_factory=list)  # paths of raw run files
    reproducer: Optional[str] = None  # "reproducers/F-001/"
    regression_test: Optional[str] = None
    notes: str = ""

    @property
    def test_names(self) -> list[str]:
        return [t.test for t in self.tests]


def finding_id(n: int) -> str:
    """1 -> "F-001"."""
    return f"F-{n:03d}"


# ---------------------------------------------------------------------------
# Reproducers and regression tests (producer: D, §10)
# ---------------------------------------------------------------------------


@dataclass
class Replay:
    n: int
    reproduced: bool
    signal: Optional[str]
    exit_code: Optional[int]
    error_type: Optional[ErrorType]
    top_functions: list[str]
    duration_s: float


@dataclass
class Bundle:
    """``reproducers/<finding id>/`` (§10.3)."""

    finding: str
    source_test: str
    build: BuildName
    path: str
    original_size: int
    minimized_size: Optional[int]  # None when minimization was skipped
    minimize_runs: int
    minimize_limit_hit: bool
    replayed_input: str  # "min" | "orig"
    replays: list[Replay]
    stable: bool


@dataclass
class RegressionTest:
    """``regression_added`` entry of report.json (§10.6, §12.4)."""

    name: str
    from_finding: str
    path: str
    input_sha256: str
    status: RegressionStatus
    promoted_to: Optional[str]


# ---------------------------------------------------------------------------
# Status and the report (producer: D, §12, §13)
# ---------------------------------------------------------------------------


@dataclass
class Condition:
    """One reason for an exit code (§13.3)."""

    name: ConditionName
    reason: str
    findings: list[str] = field(default_factory=list)
    tests: list[str] = field(default_factory=list)

    @property
    def code(self) -> ExitCode:
        return self.name.code


@dataclass
class Checks:
    """Required checks; PASS needs all of them (§13.2)."""

    builds_ok: bool = False
    profiles_verified: bool = False
    all_runs_completed: bool = False
    base_reproduced: bool = False
    results_stable: bool = False
    bundles_replayed: bool = False
    hardening_checked: bool = False

    @property
    def all_ok(self) -> bool:
        return all(dataclasses.astuple(self))


@dataclass
class Status:
    checks: Checks
    conditions: list[Condition]
    exit_code: ExitCode
    exit_name: str
    reason: str


@dataclass
class Report:
    """``report.json`` (§12.4). Field order is the order in the file."""

    tool: dict[str, str]  # {"name": "zaraban", "version": "0.2.0"}
    run_id: str
    started_at: str  # ISO 8601 UTC
    duration_s: float
    target: dict[str, str]  # name, config, config_sha256
    versions: dict[str, Any]  # {"base": VersionInfo, "patch": VersionInfo, "diff": DiffInfo}
    environment: EnvironmentInfo
    settings: dict[str, Any]  # repeats, limits, sanitizer_options
    builds: dict[BuildName, dict[str, Any]]
    hardening: Optional[HardeningReport]
    execution_logs: dict[BuildName, dict[str, dict[str, Any]]]
    findings: list[Finding]
    regression_added: list[RegressionTest]
    status: Status
    warnings: list[Issue] = field(default_factory=list)
    errors: list[Issue] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Serialization (§12.2)
# ---------------------------------------------------------------------------


def to_jsonable(obj: Any) -> Any:
    """Convert any model to plain JSON types.

    Enums become their values, Paths become strings, bytes are never written
    (program output lives in its own files, §12.2), None stays null, and
    ``schema_version`` is moved to the front of every object that has it.
    """
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (bytes, bytearray)):
        raise TypeError("bytes must not be placed in JSON; store them in a file")
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out: dict[str, Any] = {}
        names = [f.name for f in dataclasses.fields(obj)]
        if "schema_version" in names:
            names.remove("schema_version")
            names.insert(0, "schema_version")
        for name in names:
            if name == "input_bytes":
                continue
            value = getattr(obj, name)
            key = {"from_value": "from", "to_value": "to"}.get(name, name)
            out[key] = to_jsonable(value)
        return out
    if isinstance(obj, dict):
        return {to_jsonable(k) if isinstance(k, Enum) else str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    return obj


def dump_json(obj: Any, path: Path) -> None:
    """Write a model as UTF-8 JSON, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_jsonable(obj), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
