"""Binary hardening checker.

Checks NX, PIE, RELRO and the stack canary on the two **release** binaries,
records the evidence for each, and warns when a protection is weaker on patch
than on base (for example because the patch changed the build script). The
sanitized builds are never checked: they are instrumented and do not represent
the delivered program.

Hardening never changes the exit code: a downgrade is the warning
``HARDENING_DOWNGRADE`` only.
"""

from __future__ import annotations

from pathlib import Path

from .elf import DF_1_NOW, DF_1_PIE, DF_BIND_NOW, PF_X, ElfView
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

# Strength order for the comparison. Higher index = stronger.
_RELRO_ORDER = {Relro.NONE: 0, Relro.PARTIAL: 1, Relro.FULL: 2}


def check(binary: str | Path) -> HardeningResult:
    """Read the four protections of one release binary, with evidence."""
    elf = ElfView.load(binary)
    return HardeningResult(
        nx=_nx(elf),
        pie=_pie(elf),
        relro=_relro(elf),
        canary=_canary(elf),
    )


def report(base_binary: str | Path, patch_binary: str | Path) -> tuple[HardeningReport, list[Issue]]:
    """Check both release binaries and compare them.

    Returns the report and any ``HARDENING_DOWNGRADE`` warnings. Improvements
    and unchanged protections produce no warning.
    """
    base = check(base_binary)
    patch = check(patch_binary)
    changes, warnings = _compare(base, patch)
    return HardeningReport(base=base, patch=patch, changes=changes), warnings


# ---------------------------------------------------------------------------
# One protection each
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
    # A PIE is ET_DYN with a PT_INTERP header (or DF_1_PIE when linked
    # statically); a shared library is ET_DYN with neither, and a non-PIE
    # executable is ET_EXEC. The rule lives in ElfView.is_pie.
    evidence = f"e_type={elf.e_type}, PT_INTERP={'present' if elf.has_interp else 'absent'}"
    if elf.dt_flags_1 & DF_1_PIE:
        evidence += ", DT_FLAGS_1 has DF_1_PIE"
    return ProtectionResult(elf.is_pie, evidence)


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
    # The compiler makes protected functions call __stack_chk_fail. In a
    # dynamically linked binary that call is an import from libc, so an
    # imported __stack_chk_fail shows the program's code uses canaries. In a
    # statically linked one libc defines the function itself, whether the
    # program uses it or not, so its presence proves nothing: reported absent.
    name = "__stack_chk_fail"
    table = ".dynsym" if name in elf.dynamic_symbols else ".symtab"
    if name in elf.imported:
        return ProtectionResult(True, f"{name} imported from libc (undefined in {table})")
    if name in elf.symbols:
        return ProtectionResult(
            False,
            f"{name} defined in {table} by statically linked libc; "
            "this does not show that the program's code uses canaries",
        )
    return ProtectionResult(False, f"{name} not referenced")


# ---------------------------------------------------------------------------
# Comparison
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
                f"the patch weakens {_LABEL[name]} in the release binary: "
                f"{_show(b.value)} on base, {_show(p.value)} on patch",
                {
                    "protection": name,
                    "from": _show(b.value), "to": _show(p.value),
                    "base_evidence": b.evidence, "patch_evidence": p.evidence,
                },
            ))
    return changes, warnings


_LABEL = {"nx": "NX (non-executable stack)", "pie": "PIE", "relro": "RELRO",
          "canary": "the stack canary"}


def _show(value: object) -> str:
    if isinstance(value, Relro):
        return value.value
    return "enabled" if value else "disabled"
