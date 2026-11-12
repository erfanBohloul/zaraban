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
DF_1_PIE = 0x08000000  # DT_FLAGS_1: position-independent executable
PF_X = 0x1  # executable segment flag

# Prefixes of the interceptor symbols a sanitizer runtime defines for libc
# functions (``__interceptor___sprintf_chk``; newer LLVM also uses the others).
_INTERCEPTOR_PREFIXES = ("__interceptor_trampoline_", "___interceptor_", "__interceptor_")

# Source paths of sanitizer runtimes. gcc links libasan's preinit object, built
# with -g, into every ASan binary, so its debug info says nothing about whether
# the program itself was compiled with -g.
_RUNTIME_SOURCE_MARKERS = ("libsanitizer/", "compiler-rt/", "sanitizer_common/")


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
    needed: list[str] = field(default_factory=list)  # DT_NEEDED shared libraries
    symbols: set[str] = field(default_factory=set)  # .dynsym + .symtab names
    has_debug_info: bool = False  # the program's own code has DWARF debug info

    # -- derived facts used by callers -------------------------------------

    @property
    def is_pie(self) -> bool:
        """A position-independent executable: ET_DYN with a program
        interpreter, or a static PIE (no interpreter, DF_1_PIE set). A shared
        library is ET_DYN with neither."""
        return self.e_type == "ET_DYN" and (self.has_interp or bool(self.dt_flags_1 & DF_1_PIE))

    @property
    def is_x86_64_exec(self) -> bool:
        """True for an x86-64 ELF executable, PIE or not; false for a shared
        library or an object file (§6.2 step 4)."""
        return (self.is_elf and self.machine == "EM_X86_64"
                and (self.e_type == "ET_EXEC" or self.is_pie))

    @property
    def has_asan(self) -> bool:
        """AddressSanitizer is linked: its runtime entry point is referenced
        (static runtime, as clang links it) or libasan is a needed library (gcc)."""
        return "__asan_init" in self.symbols or self._needs("libasan")

    @property
    def has_ubsan(self) -> bool:
        """UndefinedBehaviorSanitizer is linked. Handler symbols appear only
        when the code has checks to make, so a needed libubsan (gcc's runtime)
        counts as well."""
        return (any(n.startswith("__ubsan_handle_") for n in self.symbols)
                or self._needs("libubsan", "libclang_rt.ubsan"))

    @property
    def uses_fortify(self) -> bool:
        """True when the binary calls a _FORTIFY_SOURCE checked function (``__*_chk``).

        This is judged only when no sanitizer runtime is linked into the
        binary itself. A static runtime (clang's default) brings its own
        ``__*_chk`` symbols: interceptors such as ``__sprintf_chk``, and calls
        of its own such as ``__syslog_chk``. They cannot be told apart from
        the program's calls, so the answer is then False. This can only miss
        a warning (FORTIFY_IN_SANITIZED), never cause an error.
        """
        if self.has_static_sanitizer_runtime:
            return False
        return any(n.startswith("__") and n.endswith("_chk") for n in self.symbols)

    @property
    def has_static_sanitizer_runtime(self) -> bool:
        """A sanitizer runtime is linked into the binary (its interceptors are
        defined here), rather than loaded from a shared library."""
        return any(n.startswith(_INTERCEPTOR_PREFIXES) for n in self.symbols)

    def _needs(self, *prefixes: str) -> bool:
        return any(lib.startswith(prefixes) for lib in self.needed)

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
        needed: list[str] = []
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    name = tag.entry.d_tag
                    dyn_tags.add(name)
                    if name == "DT_FLAGS":
                        dt_flags = int(tag.entry.d_val)
                    elif name == "DT_FLAGS_1":
                        dt_flags_1 = int(tag.entry.d_val)
                    elif name == "DT_NEEDED":
                        needed.append(tag.needed)

        symbols: set[str] = set()
        for sec_name in (".dynsym", ".symtab"):
            sec = elf.get_section_by_name(sec_name)
            if sec is not None:
                for sym in sec.iter_symbols():
                    if sym.name:
                        symbols.add(sym.name)

        has_debug_info = _program_has_debug_info(elf)

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
            needed=needed,
            symbols=symbols,
            has_debug_info=has_debug_info,
        )


def _program_has_debug_info(elf: ELFFile) -> bool:
    """True when a DWARF compile unit comes from the program, not only from a
    linked-in sanitizer runtime (see _RUNTIME_SOURCE_MARKERS)."""
    if elf.get_section_by_name(".debug_info") is None:
        return False
    try:
        for cu in elf.get_dwarf_info().iter_CUs():
            name = cu.get_top_DIE().attributes.get("DW_AT_name")
            path = name.value.decode("utf-8", "replace") if name else ""
            if not any(m in path for m in _RUNTIME_SOURCE_MARKERS):
                return True
        return False
    except Exception:
        return True  # unreadable DWARF: fall back to "the section is there"
