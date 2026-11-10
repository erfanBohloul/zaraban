"""Reproducer Bundle generator and 3x stability replayer (Section 3.3).

Generates standalone reproducer packages containing:
- Crashing input file (both original and minimized)
- Program commit hash and binary SHA-256 hash
- Build flags & compilation settings
- Effective environment variables
- Full reproduction execution command
- 3x replay results and flakiness detection
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Optional
import hashlib
import json
import os
import shutil
import subprocess

from zaraban.correlator.crash_parser import CrashReport
from zaraban.minimizer.delta_debugger import MinimizationResult


@dataclass
class ReplayRun:
    run_index: int
    reproduced: bool
    exit_code: int
    signal_name: Optional[str] = None
    duration_seconds: float = 0.0
    error_summary: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReproducerMetadata:
    target_name: str
    test_name: str
    commit_hash: str
    binary_sha256: str
    build_type: str
    build_cmd: str
    execution_cmd: list[str]
    effective_env: dict[str, str]
    error_type: str
    detection_mechanism: str
    signal_name: Optional[str]
    signal_num: Optional[int]
    replays: list[ReplayRun] = field(default_factory=list)
    is_flaky: bool = False
    original_size_bytes: int = 0
    minimized_size_bytes: int = 0
    reduction_percent: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["replays"] = [r.to_dict() for r in self.replays]
        return d


class ReproducerBundleManager:
    """Creates reproducible test packages with automated 3x replay verification."""

    @staticmethod
    def get_commit_hash(repo_dir: Optional[str | Path] = None) -> str:
        """Retrieve git commit hash or fallback to clean placeholder."""
        try:
            cmd = ["git", "rev-parse", "HEAD"]
            res = subprocess.run(cmd, cwd=repo_dir or ".", capture_output=True, text=True, check=True)
            return res.stdout.strip()
        except Exception:
            return "unknown-commit-hash"

    @classmethod
    def create_bundle(
        cls,
        output_dir: str | Path,
        target_name: str,
        test_name: str,
        binary_path: str | Path,
        build_type: str,
        build_cmd: str,
        execution_cmd: list[str],
        original_input_bytes: bytes,
        minimized_result: Optional[MinimizationResult],
        crash_report: CrashReport,
        runner_fn: Callable[[bytes], Any],
        repo_dir: Optional[str | Path] = None,
        effective_env: Optional[dict[str, str]] = None
    ) -> ReproducerMetadata:
        """Build reproducer bundle folder and execute 3 replay checks."""
        bundle_path = Path(output_dir) / f"{target_name}_{test_name}"
        bundle_path.mkdir(parents=True, exist_ok=True)

        # 1. Save original input
        orig_file = bundle_path / "input_original.bin"
        orig_file.write_bytes(original_input_bytes)

        # 2. Save minimized input
        min_bytes = minimized_result.minimized_data if minimized_result else original_input_bytes
        min_file = bundle_path / "input_minimized.bin"
        min_file.write_bytes(min_bytes)

        # If text-like, save .txt copies for convenience
        try:
            min_bytes.decode("utf-8")
            (bundle_path / "input_minimized.txt").write_bytes(min_bytes)
            (bundle_path / "input_original.txt").write_bytes(original_input_bytes)
        except UnicodeDecodeError:
            pass

        # 3. Calculate binary SHA256
        bin_p = Path(binary_path)
        sha256 = ""
        if bin_p.is_file():
            h = hashlib.sha256()
            h.update(bin_p.read_bytes())
            sha256 = h.hexdigest()

        commit_hash = cls.get_commit_hash(repo_dir)
        env_dict = effective_env or {
            "ASAN_OPTIONS": os.environ.get("ASAN_OPTIONS", "symbolize=1:abort_on_error=1"),
            "UBSAN_OPTIONS": os.environ.get("UBSAN_OPTIONS", "symbolize=1:print_stacktrace=1")
        }

        # 4. Perform at least 3 replay runs per Section 3.3:
        # "نتیجۀ حداقل سه بازپخش ثبت و موارد ناپایدار مشخص شوند."
        replays: list[ReplayRun] = []
        flaky = False

        for i in range(1, 4):
            try:
                res = runner_fn(min_bytes)
                is_repro = bool(res.is_crash and (
                    (crash_report.error_type and res.error_summary and crash_report.error_type in res.error_summary) or
                    (crash_report.signal_name and res.signal_name == crash_report.signal_name) or
                    (res.detection_mechanism == crash_report.detection_mechanism)
                ))
                replays.append(ReplayRun(
                    run_index=i,
                    reproduced=is_repro,
                    exit_code=res.exit_code,
                    signal_name=res.signal_name,
                    duration_seconds=round(res.duration_seconds, 4),
                    error_summary=res.error_summary
                ))
                if not is_repro:
                    flaky = True
            except Exception as e:
                replays.append(ReplayRun(
                    run_index=i,
                    reproduced=False,
                    exit_code=-1,
                    duration_seconds=0.0,
                    error_summary=str(e)
                ))
                flaky = True

        metadata = ReproducerMetadata(
            target_name=target_name,
            test_name=test_name,
            commit_hash=commit_hash,
            binary_sha256=sha256,
            build_type=build_type,
            build_cmd=build_cmd,
            execution_cmd=execution_cmd,
            effective_env=env_dict,
            error_type=crash_report.error_type,
            detection_mechanism=crash_report.detection_mechanism,
            signal_name=crash_report.signal_name,
            signal_num=crash_report.signal_num,
            replays=replays,
            is_flaky=flaky,
            original_size_bytes=len(original_input_bytes),
            minimized_size_bytes=len(min_bytes),
            reduction_percent=minimized_result.reduction_percent if minimized_result else 0.0
        )

        # 5. Write metadata.json
        meta_file = bundle_path / "metadata.json"
        meta_file.write_text(json.dumps(metadata.to_dict(), indent=2), encoding="utf-8")

        # 6. Generate run_reproduce.sh script
        script_lines = [
            "#!/bin/bash",
            "# Standalone reproduction script generated by Zaraban",
            f"# Target: {target_name} ({build_type})",
            f"# Error Type: {crash_report.error_type} via {crash_report.detection_mechanism}",
            f"# Binary SHA-256: {sha256}",
            "",
            "set -e",
            "",
            "# Export relevant sanitizer/environment options"
        ]
        for k, v in env_dict.items():
            script_lines.append(f'export {k}="{v}"')

        cmd_str = " ".join(execution_cmd)
        script_lines.append("")
        script_lines.append(f'echo "[*] Replaying crash for {test_name}..."')
        script_lines.append(f"{cmd_str} < input_minimized.bin")

        script_file = bundle_path / "run_reproduce.sh"
        script_file.write_text("\n".join(script_lines) + "\n", encoding="utf-8")
        try:
            script_file.chmod(0o755)
        except Exception:
            pass

        return metadata
