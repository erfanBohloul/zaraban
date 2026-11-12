"""Binary hardening checker (SPEC §11).

Checks NX, PIE, RELRO and the stack canary on the two **release** binaries,
records the evidence for each, and warns when a protection is weaker on patch
than on base (for example because the patch changed the build script). The
sanitized builds are never checked: they are instrumented and do not represent
the delivered program (§11.1).

Hardening never changes the exit code (§11.3): a downgrade is the warning
``HARDENING_DOWNGRADE`` only.
"""

from __future__ import annotations

from pathlib import Path

from . import models
from .elf import DF_1_NOW, DF_BIND_NOW, PF_X, ElfView
from .models import (
    HardeningChange,
    HardeningChangeKind,
    HardeningReport,
    HardeningResult,
    Issue,
    ProtectionResult,
    Relro,
    WarningCode,
)

# Strength order for the comparison (§11.3). Higher index = stronger.
_RELRO_ORDER = {Relro.NONE: 0, Relro.PARTIAL: 1, Relro.FULL: 2}


def check(binary: str | Path) -> HardeningResult:
    """Read the four protections of one release binary, with evidence (§11.2)."""
    elf = ElfView.load(binary)
    return HardeningResult(
        nx=_nx(elf),
        pie=_pie(elf),
        relro=_relro(elf),
        canary=_canary(elf),
    )


def report(base_binary: str | Path, patch_binary: str | Path) -> tuple[HardeningReport, list[Issue]]:
    """Check both release binaries and compare them (§11.2, §11.3).

    Returns the report and any ``HARDENING_DOWNGRADE`` warnings. Improvements
    and unchanged protections produce no warning.
    """
    base = check(base_binary)
    patch = check(patch_binary)
    changes, warnings = _compare(base, patch)
    return HardeningReport(base=base, patch=patch, changes=changes), warnings


# ---------------------------------------------------------------------------
# One protection each (§11.2)
# ---------------------------------------------------------------------------


def _nx(elf: ElfView) -> ProtectionResult:
    # Enabled when PT_GNU_STACK exists without the execute flag. Missing header
    # means the stack is executable by default, so NX is disabled.
    if elf.gnu_stack_flags is None:
        return ProtectionResult(False, "PT_GNU_STACK missing (stack executable by default)")
    executable = bool(elf.gnu_stack_flags & PF_X)
    return ProtectionResult(
        not executable,
        f"PT_GNU_STACK present, flags=0x{elf.gnu_stack_flags:x} "
        f"({'has' if executable else 'no'} PF_X)",
    )


def _pie(elf: ElfView) -> ProtectionResult:
    # A PIE is ET_DYN with a PT_INTERP header; a shared library is ET_DYN
    # without one, and a non-PIE executable is ET_EXEC.
    enabled = elf.e_type == "ET_DYN" and elf.has_interp
    return ProtectionResult(
        enabled, f"e_type={elf.e_type}, PT_INTERP={'present' if elf.has_interp else 'absent'}"
    )


def _relro(elf: ElfView) -> ProtectionResult:
    if not elf.has_relro:
        return ProtectionResult(Relro.NONE, "no PT_GNU_RELRO header")
    bind = None
    if "DT_BIND_NOW" in elf.dyn_tags:
        bind = "DT_BIND_NOW"
    elif elf.dt_flags & DF_BIND_NOW:
        bind = "DT_FLAGS&DF_BIND_NOW"
    elif elf.dt_flags_1 & DF_1_NOW:
        bind = "DT_FLAGS_1&DF_1_NOW"
    if bind:
        return ProtectionResult(Relro.FULL, f"PT_GNU_RELRO present, immediate binding ({bind})")
    return ProtectionResult(Relro.PARTIAL, "PT_GNU_RELRO present, lazy binding (no BIND_NOW)")


def _canary(elf: ElfView) -> ProtectionResult:
    present = "__stack_chk_fail" in elf.symbols
    return ProtectionResult(
        present,
        "__stack_chk_fail in symbol table" if present else "__stack_chk_fail not referenced",
    )


# ---------------------------------------------------------------------------
# Comparison (§11.3)
# ---------------------------------------------------------------------------


def _strength(protection: str, value: object) -> int:
    if protection == "relro":
        return _RELRO_ORDER[Relro(value)]
    return 1 if value else 0


def _compare(base: HardeningResult, patch: HardeningResult) -> tuple[list[HardeningChange], list[Issue]]:
    changes: list[HardeningChange] = []
    warnings: list[Issue] = []
    for name in ("nx", "pie", "relro", "canary"):
        b: ProtectionResult = getattr(base, name)
        p: ProtectionResult = getattr(patch, name)
        bs, ps = _strength(name, b.value), _strength(name, p.value)
        if ps == bs:
            continue
        kind = HardeningChangeKind.DOWNGRADE if ps < bs else HardeningChangeKind.IMPROVEMENT
        changes.append(HardeningChange(protection=name, from_value=b.value, to_value=p.value, kind=kind))
        if kind is HardeningChangeKind.DOWNGRADE:
            warnings.append(Issue(
                WarningCode.HARDENING_DOWNGRADE.value,
                f"{name} is weaker on patch: {_show(b.value)} -> {_show(p.value)}",
                {
                    "protection": name,
                    "from": _show(b.value), "to": _show(p.value),
                    "base_evidence": b.evidence, "patch_evidence": p.evidence,
                },
            ))
    return changes, warnings


def _show(value: object) -> str:
    if isinstance(value, Relro):
        return value.value
    return "enabled" if value else "disabled"
