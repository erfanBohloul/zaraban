"""ELF Binary Hardening

Meets Section 3.4 of the specification.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Any
from elftools.elf.elffile import ELFFile


@dataclass
class ProtectionStatus:
    """Status of an individual binary protection."""
    name: str
    enabled: bool
    evidence: str
    raw_details: dict[str, Any] = field(default_factory=dict)


@dataclass
class HardeningReport:
    """Complete hardening profile of an ELF binary."""
    binary_path: str
    nx: ProtectionStatus
    # Placeholders for upcoming protections (PIE, RELRO, Canary)
    pie: Optional[ProtectionStatus] = None
    relro: Optional[ProtectionStatus] = None
    canary: Optional[ProtectionStatus] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary_path": self.binary_path,
            "protections": {
                "nx": {
                    "enabled": self.nx.enabled,
                    "evidence": self.nx.evidence,
                    "details": self.nx.raw_details
                }
            }
        }


class HardeningChecker:
    """Inspects ELF binaries for security hardening protections."""

    @staticmethod
    def check_nx(elf: ELFFile) -> ProtectionStatus:
        """Inspect the PT_GNU_STACK program header to determine NX status.

        - If PT_GNU_STACK has flags without PF_X (e.g. RW / 0x6): NX is Enabled.
        - If PT_GNU_STACK has PF_X (e.g. RWE / 0x7): NX is Disabled (Executable Stack).
        - If PT_GNU_STACK is missing: Stack is executable by default on Linux.
        """
        gnu_stack_seg = None
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_GNU_STACK":
                gnu_stack_seg = seg
                break

        if gnu_stack_seg is None:
            return ProtectionStatus(
                name="NX",
                enabled=False,
                evidence="PT_GNU_STACK segment missing (stack is executable by default)",
                raw_details={"gnu_stack_present": False}
            )

        flags = gnu_stack_seg["p_flags"]
        # Bit 0 (0x1) is PF_X (Executable flag)
        is_executable = bool(flags & 0x1)
        is_readable = bool(flags & 0x4)
        is_writable = bool(flags & 0x2)

        flag_str = ""
        if is_readable:
            flag_str += "R"
        if is_writable:
            flag_str += "W"
        if is_executable:
            flag_str += "E"

        if is_executable:
            evidence = f"PT_GNU_STACK has executable flag '{flag_str}' (flags: {hex(flags)}). Stack is EXECUTABLE."
            return ProtectionStatus(
                name="NX",
                enabled=False,
                evidence=evidence,
                raw_details={
                    "gnu_stack_present": True,
                    "flags_hex": hex(flags),
                    "flags_str": flag_str,
                    "executable": True
                }
            )
        else:
            evidence = f"PT_GNU_STACK flags are '{flag_str}' (flags: {hex(flags)}). Non-Executable Stack (NX Enabled)."
            return ProtectionStatus(
                name="NX",
                enabled=True,
                evidence=evidence,
                raw_details={
                    "gnu_stack_present": True,
                    "flags_hex": hex(flags),
                    "flags_str": flag_str,
                    "executable": False
                }
            )

    @classmethod
    def inspect(cls, binary_path: str | Path) -> HardeningReport:
        """Inspect all enabled protections for an ELF binary."""
        path = Path(binary_path)
        if not path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        with path.open("rb") as f:
            elf = ELFFile(f)
            nx_status = cls.check_nx(elf)

        return HardeningReport(
            binary_path=str(path),
            nx=nx_status
        )

    @staticmethod
    def compare_hardening(base_report: HardeningReport, patch_report: HardeningReport) -> list[str]:
        """Compare hardening profiles and detect security regressions.

        Raises warnings if a protection was active in base but disabled in patch.
        """
        warnings = []
        if base_report.nx.enabled and not patch_report.nx.enabled:
            warnings.append(
                f"[SECURITY REGRESSION] NX was ENABLED in base binary but is DISABLED in patch binary! "
                f"Evidence: {patch_report.nx.evidence}"
            )
        return warnings
