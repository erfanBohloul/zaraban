"""Console reporting module with ANSI color styling and tabular layouts."""

from __future__ import annotations
import sys
from zaraban.constants import ExitCode
from zaraban.core.validator import ValidationSummary
from zaraban.correlator.engine import FindingCategory


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[1;31m"
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    MAGENTA = "\033[1;35m"
    CYAN = "\033[1;36m"
    GRAY = "\033[0;37m"


class ConsoleReporter:
    """Renders human-readable summary reports for developers in CI/CD terminal."""

    @classmethod
    def print_summary(cls, summary: ValidationSummary):
        c = Colors
        print("")
        print(f"{c.CYAN}{c.BOLD}{'='*72}{c.RESET}")
        print(f"{c.CYAN}{c.BOLD}   ZARABAN - Automated Security Patch Validation & Regression Report{c.RESET}")
        print(f"{c.CYAN}{c.BOLD}{'='*72}{c.RESET}")
        print(f" Target: {c.BOLD}{summary.target_name}{c.RESET}")
        print(f" Base Bug Reproduced: {'Yes' if summary.base_reproduced else 'No'}")
        print(f"{'-'*72}")

        # 1. Hardening section
        if summary.hardening_comparison:
            comp = summary.hardening_comparison
            print(f"{c.BOLD}[1] Binary Hardening Assessment (Release ELF):{c.RESET}")
            base_st = comp.base_report.status
            patch_st = comp.patch_report.status
            print(f"   NX:       Base={'ON' if base_st.nx else 'OFF'} -> Patch={'ON' if patch_st.nx else 'OFF'}")
            print(f"   PIE:      Base={'ON' if base_st.pie else 'OFF'} -> Patch={'ON' if patch_st.pie else 'OFF'}")
            print(f"   RELRO:    Base={base_st.relro.value} -> Patch={patch_st.relro.value}")
            print(f"   Canary:   Base={'ON' if base_st.canary else 'OFF'} -> Patch={'ON' if patch_st.canary else 'OFF'}")

            if comp.has_regression:
                print(f"   {c.RED}{c.BOLD}[!] HARDENING REGRESSION DETECTED:{c.RESET}")
                for reg in comp.regressions:
                    print(f"       - {c.RED}{reg}{c.RESET}")
            else:
                print(f"   {c.GREEN}[+] Binary hardening protections preserved safely.{c.RESET}")
            print(f"{'-'*72}")

        # 2. Findings section
        print(f"{c.BOLD}[2] Test Suite & Correlation Findings:{c.RESET}")
        for f in summary.findings:
            cat = f.category
            if cat == FindingCategory.FIXED:
                badge = f"{c.GREEN}[ FIXED ]{c.RESET}"
            elif cat == FindingCategory.INCOMPLETE_FIX:
                badge = f"{c.RED}[ INCOMPLETE FIX ]{c.RESET}"
            elif cat == FindingCategory.NEW_ISSUE:
                badge = f"{c.RED}[ NEW ISSUE ]{c.RESET}"
            elif cat == FindingCategory.FUNCTIONAL_REGRESSION:
                badge = f"{c.YELLOW}[ REGRESSION ]{c.RESET}"
            else:
                badge = f"{c.GRAY}[ INCONCLUSIVE ]{c.RESET}"

            print(f"   {badge} {c.BOLD}{f.test_name}{c.RESET}")
            print(f"       Category: {cat.value}")
            print(f"       Evidence: {f.evidence.details}")
            if f.patch_crash and f.patch_crash.error_type:
                print(f"       Error Type: {f.patch_crash.error_type} via {f.patch_crash.detection_mechanism}")
            print("")

        # 3. Reproducer Bundles
        if summary.reproducer_bundles:
            print(f"{c.BOLD}[3] Reproducer Bundles & Testcase Minimization:{c.RESET}")
            for b in summary.reproducer_bundles:
                flaky_str = f"{c.RED}FLAKY{c.RESET}" if b.is_flaky else f"{c.GREEN}100% STABLE (3/3 runs){c.RESET}"
                print(f"   * Test: {b.test_name}")
                print(f"     Original Size:  {b.original_size_bytes} bytes")
                print(f"     Minimized Size: {b.minimized_size_bytes} bytes ({b.reduction_percent}% reduction)")
                print(f"     Binary SHA-256: {b.binary_sha256[:16]}...")
                print(f"     Replay Status:  {flaky_str}")
            print(f"{'-'*72}")

        # 4. Final Verdict Banner
        print(f"{c.BOLD}[4] Final Verdict & CI/CD Exit Code:{c.RESET}")
        code = summary.exit_code
        if code == ExitCode.PASS:
            banner = f"{c.GREEN}{c.BOLD} >>> [PASS] EXIT CODE 0 <<< {c.RESET}"
        elif code == ExitCode.VULN_OR_NEW_ISSUE:
            banner = f"{c.RED}{c.BOLD} >>> [FAIL - VULNERABILITY DETECTED] EXIT CODE 10 <<< {c.RESET}"
        elif code == ExitCode.FUNC_REGRESSION:
            banner = f"{c.YELLOW}{c.BOLD} >>> [FAIL - FUNCTIONAL REGRESSION] EXIT CODE 20 <<< {c.RESET}"
        elif code == ExitCode.ERROR_CONFIG_OR_BUILD:
            banner = f"{c.RED}{c.BOLD} >>> [ERROR - BUILD/CONFIG] EXIT CODE 30 <<< {c.RESET}"
        else:
            banner = f"{c.GRAY}{c.BOLD} >>> [INCONCLUSIVE] EXIT CODE 40 <<< {c.RESET}"

        print(f"   {banner}")
        print(f"   Reason: {summary.verdict}")
        if len(summary.candidate_codes) > 1:
            print(f"   Candidates: {[c.name for c in summary.candidate_codes]} -> Priority resolved to {code.name}")
        print(f"{c.CYAN}{'='*72}{c.RESET}\n")
