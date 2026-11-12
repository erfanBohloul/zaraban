"""Unit tests for the four isolated builds and profile checks (SPEC §6).

Builds are driven by plain ``cc`` commands in the config, so the tests need a C
compiler but not a Makefile or clang. ``cc``'s sanitizer build carries both
AddressSanitizer and UndefinedBehaviorSanitizer, as the SPEC's clang build
does, which is what the profile check looks for.
"""

import shutil
import time

import pytest

from zaraban import builder
from zaraban.config import Target
from zaraban.elf import ElfView
from zaraban.models import BUILD_ORDER, BuildName, ErrorCode, WarningCode

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
{extra}valid_tests:
  - name: "v1"
    input_data: "x"
security_tests:
  - name: "s1"
    input_data: "y"
"""

# cc builds that stand in for the SPEC's release / sanitized profiles.
REL_OK = "cc -O2 -o prog p.c"
SAN_OK = "cc -fsanitize=address,undefined -g -O1 -o prog p.c"


def _make_target(tmp_path, release=REL_OK, sanitized=SAN_OK, clean=None):
    src = tmp_path / "src"
    src.mkdir()
    (src / "p.c").write_text(_PROG)
    cfg = tmp_path / "zaraban.yaml"
    extra = f'  clean_cmd: "{clean}"\n' if clean else ""
    cfg.write_text(_CONFIG.format(release=release, sanitized=sanitized, extra=extra))
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


# -- timeouts and process cleanup (§6.2) -------------------------------------

def _alive(pid):
    """True while the process exists and is not a zombie. Inside Docker an
    orphan may stay a zombie (PID 1 does not reap it), which is not running."""
    try:
        stat = open(f"/proc/{pid}/stat").read()
    except FileNotFoundError:
        return False
    return stat.rsplit(")", 1)[1].split()[0] != "Z"


def _gone(pid, within=3.0):
    end = time.monotonic() + within
    while time.monotonic() < end:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return False


def test_6_2_timeout_kills_the_whole_build(tmp_path, monkeypatch):
    # The build command starts a child (like make starting cc) and waits.
    # On timeout the child must be killed too, not only sh.
    monkeypatch.setattr(builder, "BUILD_TIMEOUT_S", 1)
    target, src = _make_target(tmp_path, release="sleep 30 & echo $! > child.pid; wait")
    t0 = time.monotonic()
    result = _run(tmp_path, target, src)
    assert time.monotonic() - t0 < 10
    assert result.error.code == ErrorCode.BUILD_FAILED.value
    assert "build command timed out after 1s" in result.error.message
    assert result.records[BuildName.BASE_RELEASE].exit_code is None
    pid = int((tmp_path / "work" / "base-release" / "child.pid").read_text())
    assert _gone(pid), "the build's child process is still running"
    log = (tmp_path / "out" / "builds" / "base-release" / "build.log").read_text()
    assert "[zaraban] stopped after 1s" in log


def test_6_2_background_process_does_not_outlive_its_build(tmp_path):
    # A build that leaves something running in the background and exits.
    target, src = _make_target(tmp_path, release=f"sleep 30 & echo $! > child.pid; {REL_OK}")
    result = _run(tmp_path, target, src)
    assert result.ok
    pid = int((tmp_path / "work" / "base-release" / "child.pid").read_text())
    assert _gone(pid)


# -- clean_cmd (§6.2 step 2) -------------------------------------------------

def test_6_2_clean_cmd_runs_before_the_build(tmp_path):
    target, src = _make_target(tmp_path, clean="touch cleaned")
    result = _run(tmp_path, target, src)
    assert result.ok
    assert (tmp_path / "work" / "base-release" / "cleaned").exists()
    log = (tmp_path / "out" / "builds" / "base-release" / "build.log").read_text()
    assert log.index("$ touch cleaned") < log.index(f"$ {REL_OK}")


def test_6_2_failing_clean_cmd_fails_the_build(tmp_path):
    target, src = _make_target(tmp_path, clean="exit 3")
    result = _run(tmp_path, target, src)
    assert result.error.code == ErrorCode.BUILD_FAILED.value
    assert "clean command exited with code 3" in result.error.message
    rec = result.records[BuildName.BASE_RELEASE]
    assert rec.status == "failed" and rec.exit_code is None  # the build never ran
    assert list(result.records) == [BuildName.BASE_RELEASE]


def test_6_2_clean_cmd_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(builder, "BUILD_TIMEOUT_S", 1)
    target, src = _make_target(tmp_path, clean="sleep 30")
    result = _run(tmp_path, target, src)
    assert "clean command timed out" in result.error.message


# -- build result checks (§6.2 step 4, §6.3) ---------------------------------

def test_6_2_output_that_is_not_elf_is_failure(tmp_path):
    target, src = _make_target(tmp_path, release="echo hello > prog")
    result = _run(tmp_path, target, src)
    assert result.error.code == ErrorCode.BUILD_FAILED.value
    assert "not an x86-64 ELF executable" in result.error.message


def test_6_2_build_log_has_command_and_output(tmp_path):
    target, src = _make_target(tmp_path, release=f"{REL_OK} && echo compiled-fine")
    _run(tmp_path, target, src)
    log = (tmp_path / "out" / "builds" / "base-release" / "build.log").read_text()
    assert f"$ {REL_OK} && echo compiled-fine" in log
    assert "compiled-fine" in log.splitlines()[-1]


def test_6_3_no_debug_info_warning(tmp_path):
    target, src = _make_target(tmp_path, sanitized="cc -fsanitize=address,undefined -g0 -O1 -o prog p.c")
    result = _run(tmp_path, target, src)
    assert result.ok  # a warning, not an error
    codes = [w.code for w in result.warnings]
    assert codes.count(WarningCode.NO_DEBUG_INFO.value) == 2  # base and patch sanitized
