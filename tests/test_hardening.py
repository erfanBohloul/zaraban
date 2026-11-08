"""Unit tests for ELF binary hardening (NX protection)."""

import subprocess
import pytest
from pathlib import Path
from zaraban.hardening.elf_checker import HardeningChecker


@pytest.fixture(scope="module")
def sample_binaries(tmp_path_factory):
    temp_dir = tmp_path_factory.mktemp("hardening_test")
    src = temp_dir / "test.c"
    src.write_text("int main() { return 0; }\n")

    bin_nx_on = temp_dir / "bin_nx_on"
    bin_nx_off = temp_dir / "bin_nx_off"

    # Default build (NX enabled on modern GCC)
    subprocess.run(["gcc", "-O2", "-o", str(bin_nx_on), str(src)], check=True)

    # Executable stack build (NX disabled)
    subprocess.run(["gcc", "-O2", "-z", "execstack", "-o", str(bin_nx_off), str(src)], check=True)

    return bin_nx_on, bin_nx_off


def test_nx_enabled(sample_binaries):
    bin_nx_on, _ = sample_binaries
    report = HardeningChecker.inspect(bin_nx_on)
    assert report.nx.enabled is True
    assert "Non-Executable Stack" in report.nx.evidence
    assert report.nx.raw_details["executable"] is False


def test_nx_disabled(sample_binaries):
    _, bin_nx_off = sample_binaries
    report = HardeningChecker.inspect(bin_nx_off)
    assert report.nx.enabled is False
    assert "Stack is EXECUTABLE" in report.nx.evidence
    assert report.nx.raw_details["executable"] is True


def test_hardening_regression_warning(sample_binaries):
    bin_nx_on, bin_nx_off = sample_binaries

    rep_base = HardeningChecker.inspect(bin_nx_on)
    rep_regressed_patch = HardeningChecker.inspect(bin_nx_off)

    warnings = HardeningChecker.compare_hardening(rep_base, rep_regressed_patch)
    assert len(warnings) == 1
    assert "SECURITY REGRESSION" in warnings[0]
    assert "NX was ENABLED in base binary but is DISABLED in patch" in warnings[0]


def test_no_regression_when_both_protected(sample_binaries):
    bin_nx_on, _ = sample_binaries

    rep_base = HardeningChecker.inspect(bin_nx_on)
    rep_patch = HardeningChecker.inspect(bin_nx_on)

    warnings = HardeningChecker.compare_hardening(rep_base, rep_patch)
    assert len(warnings) == 0
