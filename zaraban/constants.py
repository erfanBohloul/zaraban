"""Constants and Exit Codes required by the project specification (Section 3.5)."""

from enum import IntEnum


class ExitCode(IntEnum):
    """Exit codes for Zaraban CI/CD integration.
    
    Priority order: 30 > 10 > 20 > 40 > 0
    """
    PASS = 0
    VULN_OR_NEW_ISSUE = 10
    FUNC_REGRESSION = 20
    ERROR_CONFIG_OR_BUILD = 30
    INCONCLUSIVE = 40


# Strict priority resolution order as stated in page 3:
# "در صورت هم‌زمانی چند وضعیت، اولویت کد خروج به ترتیب ۳۰، ۱۰، ۲۰، ۴۰ و ۰ است."
EXIT_CODE_PRIORITY = [
    ExitCode.ERROR_CONFIG_OR_BUILD,  # 30
    ExitCode.VULN_OR_NEW_ISSUE,      # 10
    ExitCode.FUNC_REGRESSION,        # 20
    ExitCode.INCONCLUSIVE,           # 40
    ExitCode.PASS,                   # 0
]


def resolve_exit_code(candidates: list[ExitCode]) -> ExitCode:
    """Resolve the final exit code based on the mandated priority order."""
    if not candidates:
        return ExitCode.INCONCLUSIVE
    for code in EXIT_CODE_PRIORITY:
        if code in candidates:
            return code
    return ExitCode.INCONCLUSIVE
