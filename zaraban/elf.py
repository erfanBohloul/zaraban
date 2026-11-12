"""Read-only ELF inspection shared by the build profile check (§6.3) and the
hardening checker (§11).

Both read the same file: its header, program headers, dynamic section and
symbol tables. :class:`ElfView` parses the file once with ``pyelftools`` and
exposes exactly the facts those two modules need, so there is one ELF parser
in the tool, not two (SPEC §11.4 change from current code).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile

# Dynamic-section flag bits (not always exposed by name in pyelftools).
DF_BIND_NOW = 0x8  # DT_FLAGS
DF_1_NOW = 0x1  # DT_FLAGS_1
PF_X = 0x1  # executable segment flag


@dataclass
class ElfView:
    """The facts the tool needs about one ELF file, read once.

    Build it with :meth:`load`. Everything here comes straight from the file;
    no judgement about profiles or hardening is made (that is §6.3 and §11).
    """

    path: Path
    is_elf: bool
    machine: Optional[str]  # e.g. "EM_X86_64"
    e_type: Optional[str]  # "ET_EXEC" | "ET_DYN" | ...
    seg_types: set[str] = field(default_factory=set)  # PT_* present
    gnu_stack_flags: Optional[int] = None  # p_flags of PT_GNU_STACK, if present
    has_interp: bool = False
    has_relro: bool = False
    dyn_tags: set[str] = field(default_factory=set)  # DT_* tag names present
    dt_flags: int = 0  # value of DT_FLAGS, if any
    dt_flags_1: int = 0  # value of DT_FLAGS_1, if any
    symbols: set[str] = field(default_factory=set)  # .dynsym + .symtab names
    has_debug_info: bool = False  # a .debug_info section is present

    # -- derived facts used by callers -------------------------------------

    @property
    def is_x86_64_exec(self) -> bool:
        """True for an x86-64 ELF executable or PIE (§6.2 step 4)."""
        return self.is_elf and self.machine == "EM_X86_64" and self.e_type in ("ET_EXEC", "ET_DYN")

    @property
    def has_asan(self) -> bool:
        return "__asan_init" in self.symbols

    @property
    def has_ubsan(self) -> bool:
        return any(n.startswith("__ubsan_handle_") for n in self.symbols)

    @property
    def uses_fortify(self) -> bool:
        """True when the binary calls a _FORTIFY_SOURCE checked function (``__*_chk``)."""
        return any(n.startswith("__") and n.endswith("_chk") for n in self.symbols)

    @classmethod
    def load(cls, path: str | Path) -> "ElfView":
        p = Path(path)
        try:
            with open(p, "rb") as fh:
                elf = ELFFile(fh)
                return cls._read(p, elf)
        except Exception:
            # Not an ELF file, or unreadable. Callers treat this as "not x86-64
            # ELF" (a build failure) or as absent protections.
            return cls(path=p, is_elf=False, machine=None, e_type=None)

    @classmethod
    def _read(cls, p: Path, elf: ELFFile) -> "ElfView":
        seg_types: set[str] = set()
        gnu_stack_flags: Optional[int] = None
        has_interp = False
        has_relro = False
        for seg in elf.iter_segments():
            t = seg["p_type"]
            seg_types.add(t)
            if t == "PT_GNU_STACK":
                gnu_stack_flags = int(seg["p_flags"])
            elif t == "PT_INTERP":
                has_interp = True
            elif t == "PT_GNU_RELRO":
                has_relro = True

        dyn_tags: set[str] = set()
        dt_flags = 0
        dt_flags_1 = 0
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    name = tag.entry.d_tag
                    dyn_tags.add(name)
                    if name == "DT_FLAGS":
                        dt_flags = int(tag.entry.d_val)
                    elif name == "DT_FLAGS_1":
                        dt_flags_1 = int(tag.entry.d_val)

        symbols: set[str] = set()
        for sec_name in (".dynsym", ".symtab"):
            sec = elf.get_section_by_name(sec_name)
            if sec is not None:
                for sym in sec.iter_symbols():
                    if sym.name:
                        symbols.add(sym.name)

        has_debug_info = elf.get_section_by_name(".debug_info") is not None

        return cls(
            path=p,
            is_elf=True,
            machine=elf["e_machine"],
            e_type=elf["e_type"],
            seg_types=seg_types,
            gnu_stack_flags=gnu_stack_flags,
            has_interp=has_interp,
            has_relro=has_relro,
            dyn_tags=dyn_tags,
            dt_flags=dt_flags,
            dt_flags_1=dt_flags_1,
            symbols=symbols,
            has_debug_info=has_debug_info,
        )
