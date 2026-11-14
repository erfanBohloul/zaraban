"""The four isolated builds and their profile checks.

Every run makes exactly four builds, in a fixed order:
``base-release``, ``base-sanitized``, ``patch-release``, ``patch-sanitized``.
Each is made in its own fresh copy of its source tree, under the work
directory, so nothing is ever built inside the repository and no ``clean`` step
is needed between builds. Base and patch are built with the same
commands and the same minimal environment, so the only difference is the
source tree.

After building, each binary is kept, hashed, and checked: the sanitized
builds must contain both sanitizers, the release builds must not contain
AddressSanitizer, and two profile warnings may be raised.

A build or profile failure is an exit-30 condition. This module
does not raise it; it records the failed :class:`~zaraban.models.BuildRecord`,
stops (remaining builds are skipped), and returns the failure as an
:class:`~zaraban.models.Issue` in :class:`BuildSet`, so the caller can still
write the report before exiting with code 30.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import models
from .config import Target
from .elf import ElfView
from .sources import copy_tree
from .util import kill_group
from .models import (
    BUILD_ORDER,
    BinaryInfo,
    BuildName,
    BuildRecord,
    ErrorCode,
    Issue,
    Profile,
    Version,
    WarningCode,
)

# Minimal, identical build environment for all four builds, so base and patch
# cannot differ because of the caller's shell.
MIN_ENV: dict[str, str] = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp",
    "LANG": "C",
}
BUILD_TIMEOUT_S = 300  # a step (clean or build) longer than this is stopped and fails


@dataclass
class BuildSet:
    """The result of building all four builds (or stopping at the first failure)."""

    records: dict[BuildName, BuildRecord] = field(default_factory=dict)
    warnings: list[Issue] = field(default_factory=list)
    error: Optional[Issue] = None  # BUILD_FAILED / SANITIZER_MISSING / PROFILE_MIXED

    @property
    def ok(self) -> bool:
        return self.error is None and len(self.records) == len(BUILD_ORDER)


def build_all(
    base_tree: str | Path,
    patch_tree: str | Path,
    target: Target,
    work_dir: str | Path,
    out_dir: str | Path,
) -> BuildSet:
    """Build the four builds in order, stopping at the first failure."""
    trees = {Version.BASE: Path(base_tree), Version.PATCH: Path(patch_tree)}
    work = Path(work_dir)
    out = Path(out_dir)
    result = BuildSet()

    for name in BUILD_ORDER:
        record, warnings, error = _build_one(name, trees[name.version], target, work, out)
        result.records[name] = record
        result.warnings.extend(warnings)
        if error is not None:
            result.error = error
            break  # remaining builds are skipped
    return result


# ---------------------------------------------------------------------------
# One build
# ---------------------------------------------------------------------------


def _build_one(
    name: BuildName, src_tree: Path, target: Target, work: Path, out: Path,
) -> tuple[BuildRecord, list[Issue], Optional[Issue]]:
    build = target.spec.build
    cmd = build.release_cmd if name.profile is Profile.RELEASE else build.sanitized_cmd

    tree = work / name.value
    copy_tree(src_tree, tree)

    build_dir = out / "builds" / name.value
    build_dir.mkdir(parents=True, exist_ok=True)
    log_path = build_dir / "build.log"
    log_rel = f"builds/{name.value}/build.log"

    t0 = time.monotonic()
    exit_code: Optional[int] = None  # of the build command; None if it timed out or never ran
    failure: Optional[str] = None
    with open(log_path, "wb") as log:
        if build.clean_cmd:
            clean_code = _run_step(build.clean_cmd, tree, log)
            if clean_code != 0:
                failure = _step_failure("clean command", clean_code)
        if failure is None:
            exit_code = _run_step(cmd, tree, log)
    duration = time.monotonic() - t0

    def record(status: str, binary: Optional[BinaryInfo],
               sanitizers_verified: Optional[bool], has_debug: Optional[bool]) -> BuildRecord:
        return BuildRecord(
            build=name, status=status, cmd=cmd, env=dict(MIN_ENV), cwd=str(tree),
            exit_code=exit_code, duration_s=round(duration, 4), log=log_rel,
            binary=binary, sanitizers_verified=sanitizers_verified, has_debug_info=has_debug,
        )

    binary_path = tree / build.binary_path
    elf = ElfView.load(binary_path) if binary_path.exists() else None

    # Build failure: the clean or build command failed or timed out, the
    # binary is missing, or it is not an x86-64 ELF executable.
    if failure is None and exit_code != 0:
        failure = _step_failure("build command", exit_code)
    elif failure is None and (elf is None or not elf.is_x86_64_exec):
        failure = _binary_failure(binary_path, elf)
    if failure is not None:
        reason = failure
        rec = record("failed", None, None, None)
        models.dump_json(rec, build_dir / "build.json")
        return rec, [], Issue(ErrorCode.BUILD_FAILED.value,
                              f"{name.value}: {reason}",
                              {"build": name.value, "log": log_rel, "reason": reason})

    # Keep and hash the binary that will actually be run.
    bin_dir = build_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    kept = bin_dir / binary_path.name
    shutil.copy2(binary_path, kept)
    data = kept.read_bytes()
    binary = BinaryInfo(
        path=f"builds/{name.value}/bin/{binary_path.name}",
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )

    # Profile verification on the kept binary.
    error, warnings = _verify_profile(name, elf)
    sanitized = name.profile is Profile.SANITIZED
    rec = record("ok", binary,
                 sanitizers_verified=(error is None) if sanitized else None,
                 has_debug=elf.has_debug_info if sanitized else None)
    models.dump_json(rec, build_dir / "build.json")
    return rec, warnings, error


def _verify_profile(name: BuildName, elf: ElfView) -> tuple[Optional[Issue], list[Issue]]:
    """Check a built binary against its profile."""
    warnings: list[Issue] = []
    if name.profile is Profile.SANITIZED:
        if not (elf.has_asan and elf.has_ubsan):
            missing = ", ".join(
                m for m, present in (("AddressSanitizer", elf.has_asan),
                                     ("UndefinedBehaviorSanitizer", elf.has_ubsan)) if not present)
            return Issue(ErrorCode.SANITIZER_MISSING.value,
                         f"{name.value}: sanitized binary is missing {missing}",
                         {"build": name.value, "missing": missing}), []
        if not elf.has_debug_info:
            warnings.append(Issue(WarningCode.NO_DEBUG_INFO.value,
                                  f"{name.value}: sanitized binary has no debug information; "
                                  "stack traces will have no file and line",
                                  {"build": name.value}))
        if elf.uses_fortify:
            warnings.append(Issue(WarningCode.FORTIFY_IN_SANITIZED.value,
                                  f"{name.value}: sanitized binary uses _FORTIFY_SOURCE checks, "
                                  "which can abort before AddressSanitizer reports the error",
                                  {"build": name.value}))
    else:  # release build must not contain AddressSanitizer
        if elf.has_asan:
            return Issue(ErrorCode.PROFILE_MIXED.value,
                         f"{name.value}: release binary contains AddressSanitizer; "
                         "it must show the real behavior of the program",
                         {"build": name.value}), []
    return None, warnings


def _run_step(cmd: str, cwd: Path, log) -> Optional[int]:
    """Run one shell command of a build, logging its output; return its exit
    code, or None if it ran longer than BUILD_TIMEOUT_S.

    The command runs in its own process group, and the whole group is killed
    when the command ends or times out. Killing only ``sh`` would leave
    ``make``, the compiler or anything a Makefile started still running.
    """
    log.write(f"$ {cmd}\n".encode())
    log.flush()
    proc = subprocess.Popen(["sh", "-c", cmd], cwd=cwd, env=MIN_ENV,
                            stdout=log, stderr=subprocess.STDOUT,
                            start_new_session=True)
    try:
        code: Optional[int] = proc.wait(timeout=BUILD_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        code = None
    kill_group(proc.pid)
    if code is None:
        proc.wait()
        log.write(f"\n[zaraban] stopped after {BUILD_TIMEOUT_S}s\n".encode())
        log.flush()
    return code


def _step_failure(what: str, code: Optional[int]) -> str:
    if code is None:
        return f"{what} timed out after {BUILD_TIMEOUT_S}s"
    return f"{what} exited with code {code}"


def _binary_failure(binary_path: Path, elf: Optional[ElfView]) -> str:
    if elf is None:
        return f"binary not found: {binary_path.name}"
    return f"binary is not an x86-64 ELF executable: {binary_path.name}"
