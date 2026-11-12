"""Unit tests for zaraban/config.py (SPEC §4)."""

import textwrap

import pytest

from zaraban.config import Target
from zaraban.models import ErrorCode, InputMethod, OutputMatch, TestKind, ZarabanError

GOOD = """\
name: token_parser
input_method: file
build:
  binary_path: token_parser
  release_cmd: make release
  sanitized_cmd: make sanitized
limits:
  timeout_seconds: 2.0
  memory_limit_mb: 128
valid_tests:
  - name: valid_ping
    input_data: "PING"
    expected_exit_code: 0
    expected_output: "PONG"
  - name: valid_set
    input_data: "SET name=alice"
    expected_output: |
      OK: name=alice
    output_match: exact
boundary_tests:
  - name: boundary_empty
    input_data: ""
    expected_exit_code: 0
invalid_tests:
  - name: invalid_unknown
    input_data: "NOPE"
    expected_exit_code: 1
security_tests:
  - name: exploit_primary
    input_data: "SET x=AAAAAAAA"
    description: overflow
"""


def write(tmp_path, text, name="zaraban.yaml"):
    p = tmp_path / name
    p.write_text(textwrap.dedent(text), encoding="utf-8")
    return p


def test_4_valid_config_loads(tmp_path):
    target, warnings = Target.load(write(tmp_path, GOOD))
    assert target.name == "token_parser"
    assert target.input_method is InputMethod.FILE
    tests = target.all_tests()
    # Order is valid, boundary, invalid, security (§5.1)
    assert [t.kind for t in tests] == [
        TestKind.VALID, TestKind.VALID, TestKind.BOUNDARY, TestKind.INVALID, TestKind.SECURITY,
    ]
    ping = tests[0]
    assert ping.input_bytes == b"PING"
    assert tests[1].output_match is OutputMatch.EXACT
    assert warnings == []  # has invalid_tests and repeats defaults to 3


def test_4_5_unknown_key_is_an_error(tmp_path):
    bad = GOOD.replace("expected_exit_code: 0\n    expected_output: \"PONG\"",
                       "expected_exitcode: 0")  # typo
    with pytest.raises(ZarabanError) as e:
        Target.load(write(tmp_path, bad))
    assert e.value.code is ErrorCode.CONFIG_INVALID
    assert any("expected_exitcode" in p for p in e.value.details["problems"])


def test_4_5_removed_keys_are_rejected_with_hint(tmp_path):
    bad = GOOD + "patch_dir: patch\n"
    with pytest.raises(ZarabanError) as e:
        Target.load(write(tmp_path, bad))
    assert any("--patch" in p and "patch_dir" in p for p in e.value.details["problems"])


def test_4_5_missing_required_lists(tmp_path):
    no_sec = GOOD[: GOOD.index("security_tests:")]
    with pytest.raises(ZarabanError) as e:
        Target.load(write(tmp_path, no_sec))
    assert any("security_tests" in p for p in e.value.details["problems"])


def test_4_5_duplicate_names(tmp_path):
    dup = GOOD.replace("name: exploit_primary", "name: valid_ping")
    with pytest.raises(ZarabanError) as e:
        Target.load(write(tmp_path, dup))
    assert any("valid_ping" in p and "2 times" in p for p in e.value.details["problems"])


def test_4_5_all_problems_reported_together(tmp_path):
    bad = GOOD.replace("memory_limit_mb: 128", "memory_limit_mb: -5") + "nonsense: 1\n"
    with pytest.raises(ZarabanError) as e:
        Target.load(write(tmp_path, bad))
    assert len(e.value.details["problems"]) >= 2


def test_5_2_input_file_read_to_bytes(tmp_path):
    (tmp_path / "poc.bin").write_bytes(b"\x00\x01\x02BOOM")
    cfg = GOOD.replace('    input_data: "SET x=AAAAAAAA"\n    description: overflow',
                       "    input_file: poc.bin")
    target, _ = Target.load(write(tmp_path, cfg))
    sec = [t for t in target.all_tests() if t.kind is TestKind.SECURITY][0]
    assert sec.input_bytes == b"\x00\x01\x02BOOM"
    assert sec.input_ext == ".bin"


def test_5_missing_input_file_is_an_error(tmp_path):
    cfg = GOOD.replace('    input_data: "SET x=AAAAAAAA"\n    description: overflow',
                       "    input_file: nope.bin")
    with pytest.raises(ZarabanError) as e:
        Target.load(write(tmp_path, cfg))
    assert any("nope.bin" in p for p in e.value.details["problems"])


def test_4_5_both_inputs_is_an_error(tmp_path):
    cfg = GOOD.replace('    input_data: "NOPE"',
                       '    input_data: "NOPE"\n    input_file: x.bin')
    (tmp_path / "x.bin").write_bytes(b"x")
    with pytest.raises(ZarabanError) as e:
        Target.load(write(tmp_path, cfg))
    assert any("both input_file and input_data" in p for p in e.value.details["problems"])


def test_4_5_warn_when_no_invalid_tests(tmp_path):
    cfg = GOOD[: GOOD.index("invalid_tests:")] + GOOD[GOOD.index("security_tests:"):]
    _, warnings = Target.load(write(tmp_path, cfg))
    assert any(w.code == "NO_INVALID_TESTS" for w in warnings)


def test_4_missing_file(tmp_path):
    with pytest.raises(ZarabanError) as e:
        Target.load(tmp_path / "does_not_exist.yaml")
    assert e.value.code is ErrorCode.CONFIG_INVALID
