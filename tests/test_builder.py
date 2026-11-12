"""Unit tests for the four isolated builds and profile checks (SPEC §6).

Builds are driven by plain ``cc`` commands in the config, so the tests need a C
compiler but not a Makefile or clang. ``cc``'s sanitizer build carries both
AddressSanitizer and UndefinedBehaviorSanitizer, as the SPEC's clang build
does, which is what the profile check looks for.
"""

import shutil

import pytest

from zaraban import builder
from zaraban.config import Target
from zaraban.elf import ElfView
from zaraban.models import BUILD_ORDER, BuildName, ErrorCode

pytestmark = pytest.mark.skipif(shutil.which("cc") is None, reason="no C compiler")

_PROG = """
#include <stdio.h>
/* Arithmetic and an array index so clang/gcc emit UBSan handlers in the
   sanitized build, as the real targets do. */
int main(int argc, char **argv) {
    int a[4] = {1, 2, 3, 4};
    int n = argc * 3 + 7;
    return a[n % 4] + printf("ok %d\\n", n / argc) - a[0] - 2;
}
"""

_CONFIG = """\
name: "buildtest"
input_method: "stdin"
build:
  binary_path: "prog"
  release_cmd: "{release}"
  sanitized_cmd: "{sanitized}"
valid_tests:
  - name: "v1"
    input_data: "x"
security_tests:
  - name: "s1"
    input_data: "y"
"""

# cc builds that stand in for the SPEC's release / sanitized profiles.
REL_OK = "cc -O2 -o prog p.c"
SAN_OK = "cc -fsanitize=address,undefined -g -O1 -o prog p.c"


def _make_target(tmp_path, release=REL_OK, sanitized=SAN_OK):
    src = tmp_path / "src"
    src.mkdir()
    (src / "p.c").write_text(_PROG)
    cfg = tmp_path / "zaraban.yaml"
    cfg.write_text(_CONFIG.format(release=release, sanitized=sanitized))
    target, _ = Target.load(cfg)
    return target, src


def _run(tmp_path, target, src):
    return builder.build_all(src, src, target, tmp_path / "work", tmp_path / "out")


def test_6_1_all_four_builds_ok(tmp_path):
    target, src = _make_target(tmp_path)
    result = _run(tmp_path, target, src)
    assert result.ok
    assert result.error is None
    assert list(result.records) == list(BUILD_ORDER)  # built in SPEC order
    for name, rec in result.records.items():
        assert rec.status == "ok"
        assert rec.binary is not None
        kept = tmp_path / "out" / rec.binary.path
        assert kept.exists()
        assert rec.binary.sha256 == __import__("hashlib").sha256(kept.read_bytes()).hexdigest()
        # build.json is written for every build (§6.2 step 5, §12.3).
        assert (tmp_path / "out" / "builds" / name.value / "build.json").exists()


def test_6_3_profiles_verified(tmp_path):
    target, src = _make_target(tmp_path)
    result = _run(tmp_path, target, src)
    for name, rec in result.records.items():
        elf = ElfView.load(tmp_path / "out" / rec.binary.path)
        if name.profile.value == "sanitized":
            assert rec.sanitizers_verified is True
            assert elf.has_asan and elf.has_ubsan
        else:
            assert rec.sanitizers_verified is None  # release builds are not sanitized
            assert not elf.has_asan  # release must not contain ASan (§6.3)


def test_6_2_build_failure_stops(tmp_path):
    # base-sanitized fails, so patch builds are skipped (§6.2).
    target, src = _make_target(tmp_path, sanitized="false")
    result = _run(tmp_path, target, src)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == ErrorCode.BUILD_FAILED.value
    assert BuildName.BASE_RELEASE in result.records
    assert result.records[BuildName.BASE_SANITIZED].status == "failed"
    assert BuildName.PATCH_RELEASE not in result.records  # skipped


def test_6_2_missing_binary_is_failure(tmp_path):
    # The command succeeds but produces no binary at binary_path.
    target, src = _make_target(tmp_path, release="true")
    result = _run(tmp_path, target, src)
    assert result.error is not None
    assert result.error.code == ErrorCode.BUILD_FAILED.value


def test_6_3_sanitizer_missing(tmp_path):
    # "sanitized" build without the sanitizers -> SANITIZER_MISSING (§6.3).
    target, src = _make_target(tmp_path, sanitized="cc -O1 -o prog p.c")
    result = _run(tmp_path, target, src)
    assert result.error is not None
    assert result.error.code == ErrorCode.SANITIZER_MISSING.value


def test_6_3_profile_mixed(tmp_path):
    # "release" build that contains AddressSanitizer -> PROFILE_MIXED (§6.3).
    target, src = _make_target(tmp_path, release="cc -fsanitize=address,undefined -o prog p.c")
    result = _run(tmp_path, target, src)
    assert result.error is not None
    assert result.error.code == ErrorCode.PROFILE_MIXED.value


def test_6_2_minimal_identical_env(tmp_path):
    target, src = _make_target(tmp_path)
    result = _run(tmp_path, target, src)
    envs = [rec.env for rec in result.records.values()]
    assert all(e == builder.MIN_ENV for e in envs)  # identical for all four (§6.2)
