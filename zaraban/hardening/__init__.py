"""Binary hardening inspection module for Zaraban (Section 3.4).

Verifies the state of binary protections on ELF binaries:
- NX (No-Execute stack)
- PIE (Position-Independent Executable)
- RELRO (No RELRO, Partial RELRO, Full RELRO)
- Stack Canary (__stack_chk_fail)

Detects and warns on any unintended security downgrades between versions.
"""

from zaraban.hardening.inspector import (
    RelroLevel,
    HardeningStatus,
    HardeningReport,
    HardeningComparison,
    inspect_binary_hardening,
    compare_hardening
)

__all__ = [
    "RelroLevel",
    "HardeningStatus",
    "HardeningReport",
    "HardeningComparison",
    "inspect_binary_hardening",
    "compare_hardening"
]
