"""Unit tests for the ELF reader shared by the builder and the hardening
checker (zaraban/elf.py, SPEC §6.2, §6.3, §11).

Most tests build a tiny binary with ``cc`` and specific flags. A build the
local compiler cannot make (for example without a static libasan) is skipped,
not failed.
"""

import shutil
import subprocess

import pytest

from zaraban.elf import ElfView

needs_cc = pytest.mark.skipif(shutil.which("cc") is None, reason="no C compiler")

# No arithmetic or indexing, so UBSan has nothing to check and emits no
# __ubsan_handle_* call: the case that used to look like "UBSan missing".
_PLAIN = """
#include <stdio.h>
int main(int argc, char **argv) {
    char b[16];
    snprintf(b, sizeof b, "%s", argv[0]);
    puts(b);
    return 0;
}
"""


def _cc(tmp_path, name, *flags, src=_PLAIN):
    c = tmp_path / f"{name}.c"
    c.write_text(src)
    out = tmp_path / name
    r = subprocess.run(["cc", *flags, "-o", str(out), str(c)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"cc cannot build with {flags}: {r.stderr.strip()[:200]}")
    return ElfView.load(out)


# -- what counts as an executable (§6.2 step 4) ------------------------------

@needs_cc
def test_6_2_pie_and_non_pie_are_executables(tmp_path):
    pie = _cc(tmp_path, "pie", "-fPIE", "-pie")
    nopie = _cc(tmp_path, "nopie", "-fno-PIE", "-no-pie")
    assert pie.e_type == "ET_DYN" and pie.is_pie and pie.is_x86_64_exec
    assert nopie.e_type == "ET_EXEC" and not nopie.is_pie and nopie.is_x86_64_exec


@needs_cc
def test_6_2_static_pie_is_an_executable(tmp_path):
    # No PT_INTERP; recognised by DF_1_PIE.
    e = _cc(tmp_path, "spie", "-static-pie", "-O2")
    assert not e.has_interp
    assert e.is_pie and e.is_x86_64_exec


@needs_cc
def test_6_2_shared_library_is_not_an_executable(tmp_path):
    e = _cc(tmp_path, "lib.so", "-shared", "-fPIC")
    assert e.e_type == "ET_DYN"
    assert not e.is_pie and not e.is_x86_64_exec


@pytest.mark.parametrize("content", [b"", b"#!/bin/sh\necho hi\n", b"\x7fELF\x02\x01\x01" + b"\0" * 9])
def test_6_2_non_elf_or_broken_file(tmp_path, content):
    # empty file, a shell script, and a truncated ELF header
    p = tmp_path / "x"
    p.write_bytes(content)
    e = ElfView.load(p)
    assert not e.is_elf and not e.is_x86_64_exec
    assert not e.has_asan and not e.has_ubsan


def test_6_2_missing_file():
    assert not ElfView.load("/nonexistent/zaraban/binary").is_elf


# -- sanitizers (§6.3) -------------------------------------------------------

@needs_cc
def test_6_3_ubsan_found_without_handler_symbols(tmp_path):
    # gcc links libubsan even when the code has nothing to check.
    e = _cc(tmp_path, "san", "-O0", "-fsanitize=address,undefined")
    if not any(n.startswith("__ubsan_handle_") for n in e.symbols) and not e.needed:
        pytest.skip("this compiler links the sanitizers statically")
    assert e.has_asan and e.has_ubsan


@needs_cc
def test_6_3_release_build_has_no_sanitizers(tmp_path):
    e = _cc(tmp_path, "rel", "-O2")
    assert not e.has_asan and not e.has_ubsan


# -- FORTIFY in sanitized builds (§6.3) --------------------------------------

@needs_cc
def test_6_3_static_asan_runtime_is_not_fortify(tmp_path):
    # The ASan runtime defines __sprintf_chk etc. as interceptors. Linked into
    # the binary (as clang does by default), that is not the program using
    # _FORTIFY_SOURCE.
    e = _cc(tmp_path, "static", "-O0", "-U_FORTIFY_SOURCE",
            "-fsanitize=address,undefined", "-static-libasan")
    assert e.has_static_sanitizer_runtime  # the runtime is inside the binary
    assert "__sprintf_chk" in e.symbols     # ... with its own __*_chk symbols
    assert e.has_asan
    assert not e.uses_fortify


@needs_cc
def test_6_3_fortify_call_is_detected(tmp_path):
    # Dynamic libasan (gcc's default): the program's own checked call is visible.
    src = _PLAIN.replace('snprintf(b, sizeof b, "%s", argv[0]);',
                         'char d[4]; memcpy(d, argv[0], argc); b[0] = d[0];')
    src = "#include <string.h>\n" + src
    e = _cc(tmp_path, "fort", "-O2", "-D_FORTIFY_SOURCE=2", "-fsanitize=address,undefined", src=src)
    if e.has_static_sanitizer_runtime:
        pytest.skip("this compiler links the sanitizer runtime statically")
    if not any(n.endswith("_chk") and n != "__stack_chk_fail" for n in e.symbols):
        pytest.skip("this compiler did not emit a checked call")
    assert e.uses_fortify


@needs_cc
def test_6_3_no_fortify_without_the_flag(tmp_path):
    assert not _cc(tmp_path, "plain", "-O0", "-U_FORTIFY_SOURCE").uses_fortify


# -- debug info --------------------------------------------------------------

@needs_cc
def test_6_3_debug_info(tmp_path):
    assert _cc(tmp_path, "g", "-g").has_debug_info
    assert not _cc(tmp_path, "nog", "-g0").has_debug_info


@needs_cc
def test_6_3_sanitizer_runtime_debug_info_does_not_count(tmp_path):
    # gcc links libasan's asan_preinit.o, which has DWARF, into every ASan
    # binary. The program itself built with -g0 still has no debug info.
    e = _cc(tmp_path, "san_g0", "-g0", "-O1", "-fsanitize=address,undefined")
    assert not e.has_debug_info
    assert _cc(tmp_path, "san_g", "-g", "-O1", "-fsanitize=address,undefined").has_debug_info

