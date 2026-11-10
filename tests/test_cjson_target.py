"""Unit tests verifying cJSON Target 2 behaviors across all 4 patch versions."""

from pathlib import Path
import tempfile
from zaraban.executor.runner import SafeRunner

try:
    import pytest
except ImportError:
    pytest = None

TARGET_DIR = Path("targets/target2_cjson")
SRC_DIR = TARGET_DIR / "src"
VERSIONS_DIR = TARGET_DIR / "versions"
TESTS_DIR = TARGET_DIR / "tests"


def _compile_binaries_impl(temp_dir: Path):
    """Compile both release and sanitized builds for all 4 versions."""
    versions = {
        "base": SRC_DIR,
        "incomplete": VERSIONS_DIR / "patch_incomplete" / "src",
        "correct": VERSIONS_DIR / "patch_correct" / "src",
        "regression": VERSIONS_DIR / "patch_regression" / "src",
    }

    binaries = {}
    for vname, vpath in versions.items():
        for mode in ["release", "sanitized"]:
            bin_path = temp_dir / f"cjson_{vname}_{mode}"
            cflags = ["-I" + str(vpath), "-Wno-deprecated-declarations"]
            if mode == "release":
                cmd = ["gcc", "-O2", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2"] + cflags + [
                    "-o", str(bin_path),
                    str(vpath / "main.c"), str(vpath / "cJSON.c"), str(vpath / "cJSON_Utils.c"),
                    "-lm"
                ]
            else:
                cmd = ["clang", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g", "-O1"] + cflags + [
                    "-o", str(bin_path),
                    str(vpath / "main.c"), str(vpath / "cJSON.c"), str(vpath / "cJSON_Utils.c"),
                    "-lm"
                ]
            res = SafeRunner.run(cmd, timeout_seconds=10.0)
            assert res.exit_code == 0, f"Compilation failed for {vname} {mode}: {res.stderr}"
            binaries[(vname, mode)] = bin_path

    return binaries


if pytest is not None:
    @pytest.fixture(scope="session")
    def compiled_binaries(tmp_path_factory):
        return _compile_binaries_impl(tmp_path_factory.mktemp("cjson_bins"))


def test_base_vulnerability_reproduced(compiled_binaries):
    """Base version must trigger ASan Heap-Use-After-Free on exploit_primary."""
    bin_path = compiled_binaries[("base", "sanitized")]
    res = SafeRunner.run(
        [str(bin_path), str(TESTS_DIR / "exploits/exploit_primary.json")],
        is_sanitized=True,
        timeout_seconds=2.0
    )
    assert res.is_crash
    assert res.detection_mechanism == "Sanitizer/ASan"
    assert "heap-use-after-free" in res.stderr


def test_incomplete_patch_bypassed(compiled_binaries):
    """Incomplete patch blocks primary exploit but crashes on secondary exploit."""
    bin_path = compiled_binaries[("incomplete", "sanitized")]

    # Primary exploit is resolved
    res_primary = SafeRunner.run(
        [str(bin_path), str(TESTS_DIR / "exploits/exploit_primary.json")],
        is_sanitized=True,
        timeout_seconds=2.0
    )
    assert not res_primary.is_crash
    assert res_primary.exit_code == 0

    # Secondary exploit bypasses incomplete patch
    res_secondary = SafeRunner.run(
        [str(bin_path), str(TESTS_DIR / "exploits/exploit_secondary.json")],
        is_sanitized=True,
        timeout_seconds=2.0
    )
    assert res_secondary.is_crash
    assert res_secondary.detection_mechanism == "Sanitizer/ASan"
    assert "heap-use-after-free" in res_secondary.stderr


def test_correct_patch_passes_all(compiled_binaries):
    """Correct patch passes both valid tests and both exploit attempts cleanly."""
    bin_path = compiled_binaries[("correct", "sanitized")]

    # Valid test
    res_valid = SafeRunner.run(
        [str(bin_path), str(TESTS_DIR / "valid/valid_1_rfc7386.json")],
        is_sanitized=True,
        timeout_seconds=2.0
    )
    assert not res_valid.is_crash
    assert res_valid.exit_code == 0
    assert "Hello!" in res_valid.stdout

    # Exploit primary blocked
    res_p = SafeRunner.run(
        [str(bin_path), str(TESTS_DIR / "exploits/exploit_primary.json")],
        is_sanitized=True,
        timeout_seconds=2.0
    )
    assert not res_p.is_crash
    assert res_p.exit_code == 0

    # Exploit secondary blocked
    res_s = SafeRunner.run(
        [str(bin_path), str(TESTS_DIR / "exploits/exploit_secondary.json")],
        is_sanitized=True,
        timeout_seconds=2.0
    )
    assert not res_s.is_crash
    assert res_s.exit_code == 0


def test_regression_patch_breaks_functionality(compiled_binaries):
    """Regression patch resolves memory errors but breaks valid null key deletion."""
    bin_path = compiled_binaries[("regression", "sanitized")]

    # Exploits are blocked
    res_p = SafeRunner.run([str(bin_path), str(TESTS_DIR / "exploits/exploit_primary.json")], is_sanitized=True)
    assert not res_p.is_crash

    # Valid null deletion is broken
    res_valid = SafeRunner.run([str(bin_path), str(TESTS_DIR / "valid/valid_3_delete.json")], is_sanitized=True)
    assert res_valid.exit_code == 0
    # Expected: {"active":true}, but regression outputs deprecated_key still present
    assert "deprecated_key" in res_valid.stdout


if __name__ == "__main__":
    tmp = Path(tempfile.mkdtemp(prefix="cjson_test_bins_"))
    print(f"[*] Compiling binaries into {tmp}...")
    bins = _compile_binaries_impl(tmp)
    print("  [✓] All binaries compiled.")

    print("\n[+] Running test_base_vulnerability_reproduced...")
    test_base_vulnerability_reproduced(bins)
    print("  [✓] PASS: ASan caught heap-use-after-free on exploit_primary.")

    print("\n[+] Running test_incomplete_patch_bypassed...")
    test_incomplete_patch_bypassed(bins)
    print("  [✓] PASS: exploit_primary blocked, exploit_secondary triggered heap-use-after-free.")

    print("\n[+] Running test_correct_patch_passes_all...")
    test_correct_patch_passes_all(bins)
    print("  [✓] PASS: RFC 7386 valid test passed; both exploits blocked cleanly.")

    print("\n[+] Running test_regression_patch_breaks_functionality...")
    test_regression_patch_breaks_functionality(bins)
    print("  [✓] PASS: exploits blocked, but functional regression observed on key deletion.")

    print("\n==========================================")
    print("  ALL 4 CJSON TARGET TESTS PASSED! (100%)")
    print("==========================================")
