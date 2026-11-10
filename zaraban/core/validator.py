"""Core Patch Validator and Pipeline Orchestrator for Zaraban.

Implements the complete verification workflow matching all specifications:
- Dual-build execution (Release vs Sanitized kept strictly separate)
- Binary hardening inspection and regression warnings
- Base vulnerability reproduction verification
- Dynamic functional and boundary testing (detecting regressions)
- Finding-to-Patch correlation with Git diff
- Automated input minimization and reproducer bundle generation
- Strict exit code resolution with priority: 30 > 10 > 20 > 40 > 0
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Optional
import os
import shutil
import subprocess

from zaraban.constants import ExitCode, resolve_exit_code
from zaraban.config import TargetConfig, TestCase, InputMethod
from zaraban.executor.runner import SafeRunner, ExecutionResult
from zaraban.hardening.inspector import (
    HardeningReport,
    HardeningComparison,
    inspect_binary_hardening,
    compare_hardening
)
from zaraban.correlator.diff_parser import DiffParser, PatchDiff
from zaraban.correlator.crash_parser import CrashParser, CrashReport
from zaraban.correlator.engine import CorrelationEngine, PatchFinding, FindingCategory
from zaraban.minimizer.delta_debugger import DeltaDebugger, MinimizationResult
from zaraban.reproducer.bundle import ReproducerBundleManager, ReproducerMetadata
from zaraban.regression.generator import RegressionGenerator, RegressionTestResult


@dataclass
class ValidationSummary:
    target_name: str
    exit_code: ExitCode
    verdict: str
    candidate_codes: list[ExitCode] = field(default_factory=list)
    base_reproduced: bool = False
    findings: list[PatchFinding] = field(default_factory=list)
    hardening_comparison: Optional[HardeningComparison] = None
    reproducer_bundles: list[ReproducerMetadata] = field(default_factory=list)
    regression_tests: list[dict[str, Any]] = field(default_factory=list)
    execution_logs: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "exit_code": int(self.exit_code),
            "exit_code_name": self.exit_code.name,
            "verdict": self.verdict,
            "candidate_codes": [int(c) for c in self.candidate_codes],
            "base_reproduced": self.base_reproduced,
            "hardening": self.hardening_comparison.to_dict() if self.hardening_comparison else None,
            "findings": [f.to_dict() for f in self.findings],
            "reproducer_bundles": [b.to_dict() for b in self.reproducer_bundles],
            "regression_tests": self.regression_tests,
            "execution_logs": self.execution_logs,
            "errors": self.errors
        }


class PatchValidator:
    """End-to-end patch validation engine."""

    def __init__(
        self,
        config: TargetConfig,
        base_dir: str | Path,
        patch_dir: str | Path,
        diff_file: Optional[str | Path] = None,
        artifacts_dir: str | Path = "artifacts"
    ):
        self.config = config
        self.base_dir = Path(base_dir).resolve()
        self.patch_dir = Path(patch_dir).resolve()
        self.diff_file = Path(diff_file).resolve() if diff_file else None
        self.artifacts_dir = Path(artifacts_dir).resolve()
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

        self.candidate_codes: list[ExitCode] = []
        self.errors: list[str] = []
        self.findings: list[PatchFinding] = []
        self.reproducer_bundles: list[ReproducerMetadata] = []
        self.regression_tests: list[dict[str, Any]] = []
        self.execution_logs: dict[str, Any] = {
            "base_release": {},
            "base_sanitized": {},
            "patch_release": {},
            "patch_sanitized": {}
        }
        self.patch_diff: Optional[PatchDiff] = None

    def _build_target(self, working_dir: Path, cmd: str) -> bool:
        """Execute a build command in the target directory."""
        if not cmd:
            return True
        try:
            res = subprocess.run(
                cmd,
                shell=True,
                cwd=working_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
            if res.returncode != 0:
                self.errors.append(
                    f"Build failed in {working_dir} with command '{cmd}':\n"
                    f"STDOUT: {res.stdout}\nSTDERR: {res.stderr}"
                )
                return False
            return True
        except Exception as e:
            self.errors.append(f"Build command exception in {working_dir} ('{cmd}'): {str(e)}")
            return False

    def _resolve_binary_path(self, working_dir: Path) -> Path:
        bin_rel = self.config.build.binary_path
        p = working_dir / bin_rel
        if not p.is_file():
            # If not in subpath, check directly in working_dir
            if (working_dir / Path(bin_rel).name).is_file():
                return working_dir / Path(bin_rel).name
        return p

    def _load_or_generate_diff(self) -> Optional[PatchDiff]:
        """Load provided diff or compute diff between base_dir and patch_dir."""
        if self.diff_file and self.diff_file.is_file():
            try:
                return DiffParser.parse_file(self.diff_file)
            except Exception as e:
                self.errors.append(f"Failed to parse diff file {self.diff_file}: {e}")

        # Try automatic git diff or diff command
        try:
            diff_res = subprocess.run(
                ["diff", "-u", "-r", str(self.base_dir), str(self.patch_dir)],
                capture_output=True,
                text=True
            )
            if diff_res.stdout:
                return DiffParser.parse_string(diff_res.stdout)
        except Exception:
            pass
        return None

    def _execute_test(
        self,
        binary_path: Path,
        test: TestCase,
        is_sanitized: bool,
        input_override_bytes: Optional[bytes] = None
    ) -> ExecutionResult:
        """Run target binary against a testcase respecting configured input method."""
        cmd = [str(binary_path)]
        if test.args:
            cmd.extend(test.args)

        test_file_path = None
        input_data = test.input_data

        if test.input_file:
            # Resolve test file relative to base_dir or project root
            cand1 = self.base_dir / test.input_file
            cand2 = Path(test.input_file)
            if cand1.is_file():
                test_file_path = str(cand1)
            elif cand2.is_file():
                test_file_path = str(cand2)
            else:
                test_file_path = str(test.input_file)

        # Handle custom input methods
        if self.config.input_method == InputMethod.FILE:
            if input_override_bytes is not None:
                # Write override bytes to temp file
                tmp_file = self.artifacts_dir / f"tmp_input_{test.name}.bin"
                tmp_file.write_bytes(input_override_bytes)
                cmd.append(str(tmp_file))
                test_file_path = None
                input_data = None
            elif test_file_path:
                cmd.append(test_file_path)
                test_file_path = None
                input_data = None
        elif self.config.input_method == InputMethod.ARGS:
            if input_data:
                cmd.append(input_data)
                input_data = None

        return SafeRunner.run(
            cmd=cmd,
            input_data=input_data if input_override_bytes is None else input_override_bytes.decode("utf-8", errors="replace"),
            input_file=test_file_path if input_override_bytes is None else None,
            timeout_seconds=self.config.limits.timeout_seconds,
            memory_limit_mb=self.config.limits.memory_limit_mb,
            is_sanitized=is_sanitized,
            cwd=str(binary_path.parent)
        )

    def validate(self) -> ValidationSummary:
        """Execute complete validation pipeline."""
        self.patch_diff = self._load_or_generate_diff()

        # Step 1: Build Base and Patch (Release & Sanitized separately per Section 3.2)
        # Ensure clean
        if self.config.build.clean_cmd:
            self._build_target(self.base_dir, self.config.build.clean_cmd)
            self._build_target(self.patch_dir, self.config.build.clean_cmd)

        # 1.1 Base Release
        if not self._build_target(self.base_dir, self.config.build.release_cmd):
            self.candidate_codes.append(ExitCode.ERROR_CONFIG_OR_BUILD)
            return self._finalize(ExitCode.ERROR_CONFIG_OR_BUILD, "Base release compilation failed")
        base_release_bin = self._resolve_binary_path(self.base_dir)

        # 1.2 Patch Release
        if not self._build_target(self.patch_dir, self.config.build.release_cmd):
            self.candidate_codes.append(ExitCode.ERROR_CONFIG_OR_BUILD)
            return self._finalize(ExitCode.ERROR_CONFIG_OR_BUILD, "Patch release compilation failed")
        patch_release_bin = self._resolve_binary_path(self.patch_dir)

        # Step 2: Binary Hardening Inspection (Section 3.4)
        hardening_comp = None
        try:
            base_hr = inspect_binary_hardening(base_release_bin)
            patch_hr = inspect_binary_hardening(patch_release_bin)
            hardening_comp = compare_hardening(base_hr, patch_hr)
            if hardening_comp.has_regression:
                self.errors.extend(hardening_comp.regressions)
        except Exception as e:
            self.errors.append(f"Binary hardening inspection warning: {e}")

        # Step 3: Base Vulnerability Reproduction (Section 3.5: کد 40 اگر بازتولید نشود)
        base_reproduced = False
        repro_crashes: dict[str, CrashReport] = {}

        for test in self.config.security_tests:
            # Test on release binary
            res_rel = self._execute_test(base_release_bin, test, is_sanitized=False)
            self.execution_logs["base_release"][test.name] = {
                "exit_code": res_rel.exit_code,
                "is_crash": res_rel.is_crash,
                "detection": res_rel.detection_mechanism,
                "summary": res_rel.error_summary
            }
            if res_rel.is_crash:
                base_reproduced = True
                if res_rel.crash_report:
                    repro_crashes[test.name] = res_rel.crash_report

        # Now build Sanitized versions to test sanitized reproduction
        if self.config.build.clean_cmd:
            self._build_target(self.base_dir, self.config.build.clean_cmd)
            self._build_target(self.patch_dir, self.config.build.clean_cmd)

        if not self._build_target(self.base_dir, self.config.build.sanitized_cmd):
            self.candidate_codes.append(ExitCode.ERROR_CONFIG_OR_BUILD)
            return self._finalize(ExitCode.ERROR_CONFIG_OR_BUILD, "Base sanitized compilation failed")
        base_sanitized_bin = self._resolve_binary_path(self.base_dir)

        if not self._build_target(self.patch_dir, self.config.build.sanitized_cmd):
            self.candidate_codes.append(ExitCode.ERROR_CONFIG_OR_BUILD)
            return self._finalize(ExitCode.ERROR_CONFIG_OR_BUILD, "Patch sanitized compilation failed")
        patch_sanitized_bin = self._resolve_binary_path(self.patch_dir)

        for test in self.config.security_tests:
            res_san = self._execute_test(base_sanitized_bin, test, is_sanitized=True)
            self.execution_logs["base_sanitized"][test.name] = {
                "exit_code": res_san.exit_code,
                "is_crash": res_san.is_crash,
                "detection": res_san.detection_mechanism,
                "summary": res_san.error_summary
            }
            if res_san.is_crash:
                base_reproduced = True
                if res_san.crash_report:
                    repro_crashes[test.name] = res_san.crash_report

        if not base_reproduced:
            # As mandated in Section 3.5:
            # "مانند بازتولید نشدن خطای پایه... کد ۴۰ INCONCLUSIVE"
            self.candidate_codes.append(ExitCode.INCONCLUSIVE)

        # Step 4: Functional Testing & Regression Check on Valid Tests (Section 3.1 & 3.2)
        for test in self.config.valid_tests:
            b_res = self._execute_test(base_sanitized_bin, test, is_sanitized=True)
            p_res = self._execute_test(patch_sanitized_bin, test, is_sanitized=True)

            self.execution_logs["patch_sanitized"][test.name] = {
                "exit_code": p_res.exit_code,
                "is_crash": p_res.is_crash,
                "stdout": p_res.stdout
            }

            finding = CorrelationEngine.classify_finding(
                test_name=test.name,
                base_crash=b_res.crash_report,
                patch_crash=p_res.crash_report,
                diff=self.patch_diff,
                is_valid_test=True,
                base_exit_code=b_res.exit_code,
                patch_exit_code=p_res.exit_code
            )

            # Check expected output match if specified
            if test.expected_output and test.expected_output.strip() not in p_res.stdout:
                if b_res.exit_code == 0 and test.expected_output.strip() in b_res.stdout:
                    finding.category = FindingCategory.FUNCTIONAL_REGRESSION
                    finding.is_regression = True
                    finding.details = f"Functional regression: output mismatch in valid test '{test.name}'. Expected '{test.expected_output}'"

            self.findings.append(finding)
            if finding.category == FindingCategory.FUNCTIONAL_REGRESSION:
                self.candidate_codes.append(ExitCode.FUNC_REGRESSION)

        # Step 5: Boundary Tests
        for test in self.config.boundary_tests:
            b_res = self._execute_test(base_sanitized_bin, test, is_sanitized=True)
            p_res = self._execute_test(patch_sanitized_bin, test, is_sanitized=True)
            finding = CorrelationEngine.classify_finding(
                test_name=test.name,
                base_crash=b_res.crash_report,
                patch_crash=p_res.crash_report,
                diff=self.patch_diff,
                is_valid_test=False,
                base_exit_code=b_res.exit_code,
                patch_exit_code=p_res.exit_code
            )
            self.findings.append(finding)
            if p_res.is_crash:
                self.candidate_codes.append(ExitCode.VULN_OR_NEW_ISSUE)

        # Step 6: Security Tests on Patched Version (Check if fixed, incomplete, or new issue)
        for test in self.config.security_tests:
            b_crash = repro_crashes.get(test.name)
            p_res = self._execute_test(patch_sanitized_bin, test, is_sanitized=True)

            self.execution_logs["patch_sanitized"][test.name] = {
                "exit_code": p_res.exit_code,
                "is_crash": p_res.is_crash,
                "detection": p_res.detection_mechanism,
                "summary": p_res.error_summary
            }

            finding = CorrelationEngine.classify_finding(
                test_name=test.name,
                base_crash=b_crash,
                patch_crash=p_res.crash_report,
                diff=self.patch_diff,
                is_valid_test=False,
                base_exit_code=1 if b_crash else 0,
                patch_exit_code=p_res.exit_code
            )
            self.findings.append(finding)

            if p_res.is_crash:
                # Patch still crashed!
                if finding.category in (FindingCategory.INCOMPLETE_FIX, FindingCategory.NEW_ISSUE):
                    self.candidate_codes.append(ExitCode.VULN_OR_NEW_ISSUE)
                elif finding.category == FindingCategory.INCONCLUSIVE:
                    self.candidate_codes.append(ExitCode.INCONCLUSIVE)

                # Step 7: Testcase Minimization & Reproducer Bundle Generation (Section 3.3)
                self._handle_crash_reproducer_and_minimization(
                    target_name=self.config.name,
                    test=test,
                    binary_path=patch_sanitized_bin,
                    crash_report=p_res.crash_report or CrashReport(
                        error_type="Unknown",
                        detection_mechanism=p_res.detection_mechanism or "Signal",
                        exit_code=p_res.exit_code
                    )
                )

        # Step 8: If no regressions, no remaining vulns, and base was reproduced -> PASS (ExitCode 0)
        has_vuln_or_new = any(f.category in (FindingCategory.INCOMPLETE_FIX, FindingCategory.NEW_ISSUE) for f in self.findings)
        has_func_reg = any(f.category == FindingCategory.FUNCTIONAL_REGRESSION for f in self.findings)

        if base_reproduced and not has_vuln_or_new and not has_func_reg and not self.candidate_codes:
            self.candidate_codes.append(ExitCode.PASS)

        final_code = resolve_exit_code(self.candidate_codes)
        verdict = self._get_verdict_summary(final_code)

        return ValidationSummary(
            target_name=self.config.name,
            exit_code=final_code,
            verdict=verdict,
            candidate_codes=self.candidate_codes,
            base_reproduced=base_reproduced,
            findings=self.findings,
            hardening_comparison=hardening_comp,
            reproducer_bundles=self.reproducer_bundles,
            regression_tests=self.regression_tests,
            execution_logs=self.execution_logs,
            errors=self.errors
        )

    def _handle_crash_reproducer_and_minimization(
        self,
        target_name: str,
        test: TestCase,
        binary_path: Path,
        crash_report: CrashReport
    ):
        """Minimize crashing input, bundle reproducer with 3x replay, and generate regression test."""
        # Read raw input bytes
        raw_bytes = b""
        if test.input_file:
            cand = self.base_dir / test.input_file
            if cand.is_file():
                raw_bytes = cand.read_bytes()
            elif Path(test.input_file).is_file():
                raw_bytes = Path(test.input_file).read_bytes()
        elif test.input_data:
            raw_bytes = test.input_data.encode("utf-8")

        if not raw_bytes:
            return

        def runner_fn(cand_bytes: bytes) -> ExecutionResult:
            return self._execute_test(
                binary_path=binary_path,
                test=test,
                is_sanitized=True,
                input_override_bytes=cand_bytes
            )

        def oracle(cand_bytes: bytes) -> bool:
            res = runner_fn(cand_bytes)
            return res.is_crash and (
                res.detection_mechanism == crash_report.detection_mechanism or
                (crash_report.error_type in (res.error_summary or ""))
            )

        # Delta Debugging Minimization (Section 3.3)
        min_res = DeltaDebugger.minimize(raw_bytes, oracle)

        # Reproducer Bundle & 3x Replay Checks (Section 3.3)
        metadata = ReproducerBundleManager.create_bundle(
            output_dir=self.artifacts_dir / "reproducers",
            target_name=target_name,
            test_name=test.name,
            binary_path=binary_path,
            build_type="sanitized",
            build_cmd=self.config.build.sanitized_cmd,
            execution_cmd=[str(binary_path)],
            original_input_bytes=raw_bytes,
            minimized_result=min_res,
            crash_report=crash_report,
            runner_fn=runner_fn,
            repo_dir=self.base_dir
        )
        self.reproducer_bundles.append(metadata)

        # Automated Regression Test Generation (Section 3.3)
        _, test_def = RegressionGenerator.generate_regression_test(
            output_dir=self.artifacts_dir,
            target_name=target_name,
            original_test_name=test.name,
            minimized_bytes=min_res.minimized_data,
            error_type=crash_report.error_type
        )
        self.regression_tests.append(test_def)

    def _finalize(self, code: ExitCode, reason: str) -> ValidationSummary:
        return ValidationSummary(
            target_name=self.config.name,
            exit_code=code,
            verdict=reason,
            candidate_codes=self.candidate_codes or [code],
            base_reproduced=False,
            findings=self.findings,
            errors=self.errors
        )

    def _get_verdict_summary(self, code: ExitCode) -> str:
        if code == ExitCode.PASS:
            return "PASS: Patch safely eliminates security vulnerability, no functional regression detected, all checks successful."
        if code == ExitCode.VULN_OR_NEW_ISSUE:
            return "FAIL (REMAINS_VULN / NEW_ISSUE): Vulnerability still reproducible or new memory error introduced by patch."
        if code == ExitCode.FUNC_REGRESSION:
            return "FAIL (FUNC_REGRESSION): Functional regression detected; valid inputs broken by the patch."
        if code == ExitCode.ERROR_CONFIG_OR_BUILD:
            return "ERROR (BUILD/CONFIG): Compilation error or configuration failure."
        if code == ExitCode.INCONCLUSIVE:
            return "INCONCLUSIVE: Insufficient evidence, flaky crash, or base vulnerability failed to reproduce."
        return f"Verdict code: {code}"
