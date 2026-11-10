"""ELF and Mach-O binary hardening inspector.

Fulfills Section 3.4 of the project specification:
"بررسی پایۀ سخت‌سازی باینری (Binary Hardening):
ابزار باید وضعیت محافظت‌های فایل ELF شامل NX، PIE، RELRO و Stack Canary را همراه با
شواهد آن‌ها در نسخۀ عادی بررسی کند و در صورت تغییر ناخواسته در نسخۀ جدید، مثلاً غیرفعال شدن
یک محافظ در اثر تغییر اسکریپت ساخت، هشدار دهد."
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Optional
import os
import struct
import subprocess


class RelroLevel(str, Enum):
    NONE = "None"
    PARTIAL = "Partial"
    FULL = "Full"


@dataclass
class HardeningStatus:
    nx: bool = False
    nx_evidence: str = ""
    pie: bool = False
    pie_evidence: str = ""
    relro: RelroLevel = RelroLevel.NONE
    relro_evidence: str = ""
    canary: bool = False
    canary_evidence: str = ""
    format: str = "ELF"  # ELF or Mach-O
    notes: list[str] = field(default_factory=lambda: [
        "Presence of PIE in binary does not guarantee that kernel ASLR is active at runtime.",
        "Stack canary evidence indicates canary symbols are present, but does not guarantee protection for 100% of functions."
    ])

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "nx": self.nx,
            "nx_evidence": self.nx_evidence,
            "pie": self.pie,
            "pie_evidence": self.pie_evidence,
            "relro": self.relro.value,
            "relro_evidence": self.relro_evidence,
            "canary": self.canary,
            "canary_evidence": self.canary_evidence,
            "notes": self.notes
        }


@dataclass
class HardeningReport:
    binary_path: str
    sha256: str
    status: HardeningStatus

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary_path": self.binary_path,
            "sha256": self.sha256,
            "status": self.status.to_dict()
        }


@dataclass
class HardeningComparison:
    base_report: HardeningReport
    patch_report: HardeningReport
    regressions: list[str] = field(default_factory=list)
    improvements: list[str] = field(default_factory=list)
    has_regression: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "base": self.base_report.to_dict(),
            "patch": self.patch_report.to_dict(),
            "regressions": self.regressions,
            "improvements": self.improvements,
            "has_regression": self.has_regression
        }


def _calc_sha256(file_path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class PurePythonELFParser:
    """Pure Python parser for ELF32/ELF64 hardening attributes.
    Zero external dependencies required.
    """

    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_GNU_STACK = 0x6474E551
    PT_GNU_RELRO = 0x6474E552

    PF_X = 1
    PF_W = 2
    PF_R = 4

    DT_BIND_NOW = 24
    DT_FLAGS = 30
    DT_FLAGS_1 = 0x6FFFFFFB

    DF_BIND_NOW = 0x8
    DF_1_NOW = 0x1
    DF_1_PIE = 0x08000000

    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 16 or data[:4] != b"\x7fELF":
            raise ValueError("Not a valid ELF binary")

        self.ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
        self.ei_data = data[5]   # 1 = little-endian, 2 = big-endian
        self.is_64 = self.ei_class == 2
        self.endian = "<" if self.ei_data == 1 else ">"

        self._parse_header()

    def _parse_header(self):
        if self.is_64:
            fmt = f"{self.endian}HHIQQQIHHHHHH"
            header_size = 64
            hdr = struct.unpack_from(fmt, self.data, 16)
            self.e_type = hdr[0]
            self.e_machine = hdr[1]
            self.e_version = hdr[2]
            self.e_entry = hdr[3]
            self.e_phoff = hdr[4]
            self.e_shoff = hdr[5]
            self.e_flags = hdr[6]
            self.e_ehsize = hdr[7]
            self.e_phentsize = hdr[8]
            self.e_phnum = hdr[9]
            self.e_shentsize = hdr[10]
            self.e_shnum = hdr[11]
            self.e_shstrndx = hdr[12]
        else:
            fmt = f"{self.endian}HHIIIIIHHHHHH"
            header_size = 52
            hdr = struct.unpack_from(fmt, self.data, 16)
            self.e_type = hdr[0]
            self.e_machine = hdr[1]
            self.e_version = hdr[2]
            self.e_entry = hdr[3]
            self.e_phoff = hdr[4]
            self.e_shoff = hdr[5]
            self.e_flags = hdr[6]
            self.e_ehsize = hdr[7]
            self.e_phentsize = hdr[8]
            self.e_phnum = hdr[9]
            self.e_shentsize = hdr[10]
            self.e_shnum = hdr[11]
            self.e_shstrndx = hdr[12]

    def get_program_headers(self) -> list[dict[str, Any]]:
        headers = []
        offset = self.e_phoff
        for _ in range(self.e_phnum):
            if offset + self.e_phentsize > len(self.data):
                break
            if self.is_64:
                # Elf64_Phdr: p_type(4), p_flags(4), p_offset(8), p_vaddr(8), p_paddr(8), p_filesz(8), p_memsz(8), p_align(8)
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
                    f"{self.endian}IIQQQQQQ", self.data, offset
                )
            else:
                # Elf32_Phdr: p_type(4), p_offset(4), p_vaddr(4), p_paddr(4), p_filesz(4), p_memsz(4), p_flags(4), p_align(4)
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(
                    f"{self.endian}IIIIIIII", self.data, offset
                )
            headers.append({
                "type": p_type,
                "flags": p_flags,
                "offset": p_offset,
                "vaddr": p_vaddr,
                "filesz": p_filesz,
                "memsz": p_memsz,
            })
            offset += self.e_phentsize
        return headers

    def parse_hardening(self) -> HardeningStatus:
        status = HardeningStatus(format="ELF")
        program_headers = self.get_program_headers()

        # 1. Check NX (No-Execute stack via PT_GNU_STACK)
        has_gnu_stack = False
        for ph in program_headers:
            if ph["type"] == self.PT_GNU_STACK:
                has_gnu_stack = True
                if ph["flags"] & self.PF_X:
                    status.nx = False
                    status.nx_evidence = f"PT_GNU_STACK header present with executable permission (flags=0x{ph['flags']:x}, PF_X set)"
                else:
                    status.nx = True
                    status.nx_evidence = f"PT_GNU_STACK header present with non-executable permission (flags=0x{ph['flags']:x}, PF_X not set)"
                break

        if not has_gnu_stack:
            status.nx = False
            status.nx_evidence = "PT_GNU_STACK header missing (stack assumed executable by default)"

        # 2. Check PIE (e_type == ET_DYN, e_type=3)
        if self.e_type == 3:
            status.pie = True
            status.pie_evidence = "ELF type ET_DYN (Position-Independent Executable / Shared Object)"
        elif self.e_type == 2:
            status.pie = False
            status.pie_evidence = "ELF type ET_EXEC (Standard non-relocatable executable)"
        else:
            status.pie = False
            status.pie_evidence = f"ELF type {self.e_type}"

        # 3. Check RELRO & BIND_NOW
        has_gnu_relro = any(ph["type"] == self.PT_GNU_RELRO for ph in program_headers)
        has_bind_now = False
        bind_now_evidence = ""

        # Find PT_DYNAMIC to inspect dynamic tags
        dynamic_ph = next((ph for ph in program_headers if ph["type"] == self.PT_DYNAMIC), None)
        if dynamic_ph:
            dyn_offset = dynamic_ph["offset"]
            dyn_size = dynamic_ph["filesz"]
            tag_size = 16 if self.is_64 else 8
            tag_fmt = f"{self.endian}qq" if self.is_64 else f"{self.endian}ii"

            curr = dyn_offset
            while curr + tag_size <= dyn_offset + dyn_size and curr + tag_size <= len(self.data):
                d_tag, d_val = struct.unpack_from(tag_fmt, self.data, curr)
                if d_tag == 0:  # DT_NULL
                    break
                if d_tag == self.DT_BIND_NOW:
                    has_bind_now = True
                    bind_now_evidence = "DT_BIND_NOW tag present"
                elif d_tag == self.DT_FLAGS and (d_val & self.DF_BIND_NOW):
                    has_bind_now = True
                    bind_now_evidence = f"DT_FLAGS tag contains DF_BIND_NOW (val=0x{d_val:x})"
                elif d_tag == self.DT_FLAGS_1 and (d_val & self.DF_1_NOW):
                    has_bind_now = True
                    bind_now_evidence = f"DT_FLAGS_1 tag contains DF_1_NOW (val=0x{d_val:x})"
                curr += tag_size

        if not has_gnu_relro:
            status.relro = RelroLevel.NONE
            status.relro_evidence = "PT_GNU_RELRO header not found"
        elif has_bind_now:
            status.relro = RelroLevel.FULL
            status.relro_evidence = f"PT_GNU_RELRO header present and {bind_now_evidence}"
        else:
            status.relro = RelroLevel.PARTIAL
            status.relro_evidence = "PT_GNU_RELRO header present without BIND_NOW"

        # 4. Check Stack Canary via symbols
        # Search raw bytes for stack canary symbols
        canary_symbols = [b"__stack_chk_fail", b"__stack_chk_guard", b"__intel_security_cookie"]
        found_syms = [s.decode() for s in canary_symbols if s in self.data]
        if found_syms:
            status.canary = True
            status.canary_evidence = f"Stack canary symbols found in binary: {', '.join(found_syms)}"
        else:
            status.canary = False
            status.canary_evidence = "Stack canary symbols (__stack_chk_fail) not found in binary"

        return status


def _inspect_macho_fallback(data: bytes) -> HardeningStatus:
    """Fallback inspector for macOS Mach-O binaries during local host development."""
    status = HardeningStatus(format="Mach-O")
    # Check PIE (MH_PIE is 0x200000 in mach header flags)
    if len(data) >= 32:
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic in (0xFEEDFACF, 0xFEEDFACE):  # MH_MAGIC_64 / MH_MAGIC
            flags = struct.unpack_from("<I", data, 24)[0]
            if flags & 0x200000:
                status.pie = True
                status.pie_evidence = "Mach-O MH_PIE flag present"
            else:
                status.pie = False
                status.pie_evidence = "Mach-O MH_PIE flag not set"

    # In modern macOS, W^X is strictly enforced by kernel
    status.nx = True
    status.nx_evidence = "macOS kernel enforces non-executable stack (W^X / NX)"

    # Mach-O canary check
    canary_symbols = [b"___stack_chk_fail", b"___stack_chk_guard"]
    found_syms = [s.decode() for s in canary_symbols if s in data]
    if found_syms:
        status.canary = True
        status.canary_evidence = f"Canary symbols found: {', '.join(found_syms)}"
    else:
        status.canary = False
        status.canary_evidence = "Canary symbol ___stack_chk_fail not found"

    status.relro = RelroLevel.FULL
    status.relro_evidence = "macOS dyld enforces bind-at-load / read-only segments by default"
    return status


def inspect_binary_hardening(binary_path: str | Path) -> HardeningReport:
    """Inspect binary security protections (NX, PIE, RELRO, Stack Canary)."""
    p = Path(binary_path)
    if not p.is_file():
        raise FileNotFoundError(f"Binary file not found: {binary_path}")

    sha256 = _calc_sha256(p)
    raw_data = p.read_bytes()

    if raw_data.startswith(b"\x7fELF"):
        parser = PurePythonELFParser(raw_data)
        status = parser.parse_hardening()
    elif raw_data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"):
        status = _inspect_macho_fallback(raw_data)
    else:
        # Unknown binary format, default to conservative False
        status = HardeningStatus(format="Unknown")
        status.nx_evidence = "Unknown binary signature"
        status.pie_evidence = "Unknown binary signature"
        status.relro_evidence = "Unknown binary signature"
        status.canary_evidence = "Unknown binary signature"

    return HardeningReport(
        binary_path=str(p.resolve()),
        sha256=sha256,
        status=status
    )


def compare_hardening(base_report: HardeningReport, patch_report: HardeningReport) -> HardeningComparison:
    """Compare binary hardening between base and patch binaries.
    
    Identifies any regressions/downgrades in protections (e.g. build script accidentally disabled canary or RELRO).
    """
    b = base_report.status
    p = patch_report.status

    regressions = []
    improvements = []

    # NX check
    if b.nx and not p.nx:
        regressions.append("NX disabled: Base has non-executable stack, but Patched binary stack is executable!")
    elif not b.nx and p.nx:
        improvements.append("NX enabled in Patched binary")

    # PIE check
    if b.pie and not p.pie:
        regressions.append("PIE disabled: Base binary was position-independent, Patched binary is fixed-address (ET_EXEC)!")
    elif not b.pie and p.pie:
        improvements.append("PIE enabled in Patched binary")

    # Stack Canary check
    if b.canary and not p.canary:
        regressions.append("Stack Canary removed: Base binary contained stack protector (__stack_chk_fail), but Patched binary lacks it!")
    elif not b.canary and p.canary:
        improvements.append("Stack Canary added in Patched binary")

    # RELRO check
    relro_order = {RelroLevel.NONE: 0, RelroLevel.PARTIAL: 1, RelroLevel.FULL: 2}
    if relro_order[p.relro] < relro_order[b.relro]:
        regressions.append(f"RELRO downgraded from {b.relro.value} to {p.relro.value} in Patched binary!")
    elif relro_order[p.relro] > relro_order[b.relro]:
        improvements.append(f"RELRO upgraded from {b.relro.value} to {p.relro.value} in Patched binary")

    return HardeningComparison(
        base_report=base_report,
        patch_report=patch_report,
        regressions=regressions,
        improvements=improvements,
        has_regression=len(regressions) > 0
    )
