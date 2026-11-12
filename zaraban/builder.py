"""The four isolated builds and their profile checks (SPEC §6).

Every run makes exactly four builds, in a fixed order (§6.1):
``base-release``, ``base-sanitized``, ``patch-release``, ``patch-sanitized``.
Each is made in its own fresh copy of its source tree, under the work
directory, so nothing is ever built inside the repository and no ``clean`` step
is needed between builds (§3.3, §6.2). Base and patch are built with the same
commands and the same minimal environment, so the only difference is the
source tree.

After building, each binary is kept, hashed, and checked (§6.3): the sanitized
builds must contain both sanitizers, the release builds must not contain
AddressSanitizer, and two profile warnings may be raised.

A build or profile failure is an exit-30 condition (§6.2, §13.2). This module
does not raise it; it records the failed :class:`~zaraban.models.BuildRecord`,
stops (remaining builds are skipped), and returns the failure as an
:class:`~zaraban.models.Issue` in :class:`BuildSet`, so the caller can still
write the report before exiting (§6.2: "records the failure ... writes the
report, and exits with code 30").
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

# Minimal, identical build environment for all four builds (§6.2 step 3).
MIN_ENV: dict[str, str] = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp",
    "LANG": "C",
}
BUILD_TIMEOUT_S = 300  # a build longer than this is stopped and counts as failed (§6.2)


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
    """Build the four builds in order, stopping at the first failure (§6.2)."""
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
            break  # remaining builds are skipped (§6.2)
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
    exit_code: Optional[int] = None
    with open(log_path, "wb") as log:
        if build.clean_cmd:
            log.write(f"$ {build.clean_cmd}\n".encode())
            log.flush()
            subprocess.run(["sh", "-c", build.clean_cmd], cwd=tree, env=MIN_ENV,
                           stdout=log, stderr=subprocess.STDOUT)
        log.write(f"$ {cmd}\n".encode())
        log.flush()
        try:
            proc = subprocess.run(["sh", "-c", cmd], cwd=tree, env=MIN_ENV,
                                  stdout=log, stderr=subprocess.STDOUT,
                                  timeout=BUILD_TIMEOUT_S)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            log.write(f"\n[zaraban] build stopped after {BUILD_TIMEOUT_S}s\n".encode())
            exit_code = None  # timed out
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

    # Build failure: non-zero or timed-out exit, missing binary, or not an
    # x86-64 ELF executable (§6.2 step 4).
    if exit_code != 0 or elf is None or not elf.is_x86_64_exec:
        reason = _failure_reason(exit_code, binary_path, elf)
        rec = record("failed", None, None, None)
        models.dump_json(rec, build_dir / "build.json")
        return rec, [], Issue(ErrorCode.BUILD_FAILED.value,
                              f"{name.value}: {reason}",
                              {"build": name.value, "log": log_rel, "reason": reason})

    # Keep and hash the binary that will actually be run (§6.2 step 5).
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

    # Profile verification (§6.3) on the kept binary.
    error, warnings = _verify_profile(name, elf)
    sanitized = name.profile is Profile.SANITIZED
    rec = record("ok", binary,
                 sanitizers_verified=(error is None) if sanitized else None,
                 has_debug=elf.has_debug_info if sanitized else None)
    models.dump_json(rec, build_dir / "build.json")
    return rec, warnings, error


def _verify_profile(name: BuildName, elf: ElfView) -> tuple[Optional[Issue], list[Issue]]:
    """Check a built binary against its profile (§6.3)."""
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


def _failure_reason(exit_code: Optional[int], binary_path: Path, elf: Optional[ElfView]) -> str:
    if exit_code is None:
        return f"build timed out after {BUILD_TIMEOUT_S}s"
    if exit_code != 0:
        return f"build command exited with code {exit_code}"
    if not binary_path.exists():
        return f"binary not found: {binary_path.name}"
    return f"binary is not an x86-64 ELF executable: {binary_path.name}"
