"""Unit tests for the hardening checker (SPEC §11).

Each test builds a tiny binary with specific compiler flags and asserts that
the matching protection flips. The program has a stack buffer and some
arithmetic, so the stack canary and sanitizer handlers are actually emitted.
"""

import shutil
import subprocess
import sys

import pytest

from zaraban import hardening
from zaraban.models import HardeningChangeKind, Relro, WarningCode

pytestmark = pytest.mark.skipif(shutil.which("cc") is None, reason="no C compiler")

_PROG = """
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char buf[32];
    int n = argc * 3 + 7;
    if (argc > 1) strcpy(buf, argv[1]);
    else memset(buf, 0, sizeof buf);
    printf("%d %s\\n", n / argc, buf);
    return 0;
}
"""


def _compile(tmp_path, name, *flags):
    src = tmp_path / "p.c"
    src.write_text(_PROG)
    out = tmp_path / name
    r = subprocess.run(["cc", *flags, "-o", str(out), str(src)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"cc cannot build with {flags}: {r.stderr.strip()[:200]}")
    return out


def test_11_2_hardened_all_on(tmp_path):
    b = _compile(tmp_path, "hardened",
                 "-O2", "-fstack-protector-strong",
                 "-Wl,-z,relro,-z,now", "-pie", "-fPIE")
    r = hardening.check(b)
    assert r.nx.value is True
    assert r.pie.value is True
    assert r.relro.value is Relro.FULL
    assert r.canary.value is True
    # Every result carries its evidence (§11.2).
    assert all(p.evidence for p in (r.nx, r.pie, r.relro, r.canary))


def test_11_2_weak_all_off(tmp_path):
    b = _compile(tmp_path, "weak",
                 "-O0", "-fno-stack-protector", "-no-pie",
                 "-Wl,-z,norelro", "-Wl,-z,execstack")
    r = hardening.check(b)
    assert r.nx.value is False
    assert r.pie.value is False
    assert r.relro.value is Relro.NONE
    assert r.canary.value is False


def test_11_2_partial_relro(tmp_path):
    # relro without BIND_NOW is partial, not full.
    b = _compile(tmp_path, "partial", "-O2", "-Wl,-z,relro,-z,lazy", "-pie", "-fPIE")
    assert hardening.check(b).relro.value is Relro.PARTIAL


def test_11_3_downgrade_warns(tmp_path):
    base = _compile(tmp_path, "base",
                    "-O2", "-fstack-protector-strong", "-Wl,-z,relro,-z,now", "-pie", "-fPIE")
    patch = _compile(tmp_path, "patch",
                     "-O0", "-fno-stack-protector", "-no-pie", "-Wl,-z,norelro")
    report, warnings = hardening.report(base, patch)
    downgraded = {c.protection for c in report.changes if c.kind is HardeningChangeKind.DOWNGRADE}
    assert {"pie", "relro", "canary"} <= downgraded
    assert warnings and all(w.code == WarningCode.HARDENING_DOWNGRADE.value for w in warnings)
    # Each warning records both values and both pieces of evidence (§11.3).
    assert all({"from", "to", "base_evidence", "patch_evidence"} <= set(w.details) for w in warnings)


def test_11_3_improvement_no_warning(tmp_path):
    weak = _compile(tmp_path, "weak", "-O0", "-fno-stack-protector", "-no-pie", "-Wl,-z,norelro")
    strong = _compile(tmp_path, "strong",
                      "-O2", "-fstack-protector-strong", "-Wl,-z,relro,-z,now", "-pie", "-fPIE")
    report, warnings = hardening.report(weak, strong)
    assert warnings == []  # improvements never warn (§11.3)
    assert all(c.kind is HardeningChangeKind.IMPROVEMENT for c in report.changes)


def test_11_1_notes_always_present(tmp_path):
    b = _compile(tmp_path, "b", "-O2", "-pie", "-fPIE")
    report, _ = hardening.report(b, b)
    # The two §11.3 caveats are always in the report.
    assert len(report.notes) == 2
    assert any("ASLR" in n for n in report.notes)
    assert any("canary" in n for n in report.notes)
