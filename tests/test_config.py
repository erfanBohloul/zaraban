"""Unit tests for zaraban/config.py (SPEC §4)."""

import textwrap
from pathlib import Path

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
    assert any("valid_ping" in p and "used by 2 tests" in p for p in e.value.details["problems"])


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
    assert any("either input_file or input_data, not both" in p for p in e.value.details["problems"])


def test_4_5_warn_when_no_invalid_tests(tmp_path):
    cfg = GOOD[: GOOD.index("invalid_tests:")] + GOOD[GOOD.index("security_tests:"):]
    _, warnings = Target.load(write(tmp_path, cfg))
    assert any(w.code == "NO_INVALID_TESTS" for w in warnings)


def test_4_missing_file(tmp_path):
    with pytest.raises(ZarabanError) as e:
        Target.load(tmp_path / "does_not_exist.yaml")
    assert e.value.code is ErrorCode.CONFIG_INVALID


MINIMAL = """\
name: t
build:
  binary_path: prog
  release_cmd: make release
  sanitized_cmd: make sanitized
valid_tests:
  - name: v1
security_tests:
  - name: s1
"""


def problems_of(tmp_path, text):
    with pytest.raises(ZarabanError) as e:
        Target.load(write(tmp_path, text))
    assert e.value.code is ErrorCode.CONFIG_INVALID
    return e.value.details["problems"]


def test_4_2_defaults(tmp_path):
    target, _ = Target.load(write(tmp_path, MINIMAL))
    spec = target.spec
    assert target.input_method is InputMethod.STDIN
    assert spec.repeats == 3
    assert spec.limits.timeout_seconds == 3.0
    assert spec.limits.memory_limit_mb == 256
    assert spec.file_arg_placeholder == "{input_file}"
    assert spec.regression_dir == "tests/regression"
    assert target.base_dir == tmp_path.resolve()  # relative to the config's directory
    # stdin with no input is allowed (§5.2): the test gets no input at all
    assert target.all_tests()[0].input_bytes is None


def test_4_3_coverage_cmd_is_accepted(tmp_path):
    cfg = MINIMAL.replace("  sanitized_cmd: make sanitized\n",
                          "  sanitized_cmd: make sanitized\n  coverage_cmd: make coverage\n")
    target, _ = Target.load(write(tmp_path, cfg))
    assert target.spec.build.coverage_cmd == "make coverage"


def test_4_5_missing_base_dir(tmp_path):
    problems = problems_of(tmp_path, MINIMAL + "base_dir: nope\n")
    assert any("base_dir" in p and "nope" in p for p in problems)


@pytest.mark.parametrize("bad", ["my test", "a/b", "x²", "تست", "''"])
def test_4_5_bad_test_names(tmp_path, bad):
    problems = problems_of(tmp_path, MINIMAL.replace("name: v1", f"name: {bad}"))
    assert any("ASCII letters" in p for p in problems)


def test_4_5_bad_target_name(tmp_path):
    problems = problems_of(tmp_path, MINIMAL.replace("name: t\n", "name: my target\n"))
    assert any(p.startswith("name:") for p in problems)


def test_4_5_file_method_needs_input(tmp_path):
    problems = problems_of(tmp_path, MINIMAL + "input_method: file\n")
    assert any("test v1:" in p and "needs input_file or input_data" in p for p in problems)


def test_5_3_args_input_with_nul_is_an_error(tmp_path):
    (tmp_path / "nul.bin").write_bytes(b"a\x00b")
    cfg = MINIMAL.replace("  - name: s1\n", "  - name: s1\n    input_file: nul.bin\n")
    problems = problems_of(tmp_path, cfg + "input_method: args\n")
    assert any("s1" in p and "NUL" in p for p in problems)


def test_5_2_input_file_over_1mb_is_an_error(tmp_path):
    (tmp_path / "big.bin").write_bytes(b"A" * ((1 << 20) + 1))
    cfg = MINIMAL.replace("  - name: s1\n", "  - name: s1\n    input_file: big.bin\n")
    assert any("the limit is 1 MB" in p for p in problems_of(tmp_path, cfg))


def test_5_2_input_file_that_is_a_directory_is_an_error(tmp_path):
    (tmp_path / "adir").mkdir()
    cfg = MINIMAL.replace("  - name: s1\n", "  - name: s1\n    input_file: adir\n")
    assert any("not a regular file" in p for p in problems_of(tmp_path, cfg))


def test_4_5_warn_when_repeats_is_1(tmp_path):
    _, warnings = Target.load(write(tmp_path, MINIMAL + "repeats: 1\n"))
    assert any(w.code == "REPEATS_TOO_LOW" for w in warnings)


def test_4_5_repeats_0_is_an_error(tmp_path):
    assert any(p.startswith("repeats:") for p in problems_of(tmp_path, MINIMAL + "repeats: 0\n"))


@pytest.mark.parametrize("content", [b"", b"- just\n- a list\n", b"name: \xff\xfe\n"])
def test_4_unusable_config_file_is_config_invalid(tmp_path, content):
    # empty file, a YAML list instead of a mapping, and bytes that are not UTF-8
    p = tmp_path / "zaraban.yaml"
    p.write_bytes(content)
    with pytest.raises(ZarabanError) as e:
        Target.load(p)
    assert e.value.code is ErrorCode.CONFIG_INVALID


def test_4_config_path_is_a_directory(tmp_path):
    with pytest.raises(ZarabanError) as e:
        Target.load(tmp_path)
    assert e.value.code is ErrorCode.CONFIG_INVALID


def test_4_delivered_sample_config_loads():
    root = Path(__file__).resolve().parent.parent
    target, _ = Target.load(root / "targets" / "target1_sample" / "zaraban.yaml")
    assert target.name == "token_parser"
    assert target.base_dir == (root / "targets" / "target1_sample").resolve()


# --- Messages a first-time user can act on -----------------------------------


def test_4_5_unknown_key_suggests_the_closest_known_key(tmp_path):
    cfg = GOOD.replace("  timeout_seconds: 2.0", "  timeout: 2.0")
    assert "limits: unknown key 'timeout'; did you mean 'timeout_seconds'?" in \
        problems_of(tmp_path, cfg)


def test_4_5_problem_in_a_test_names_the_test_and_the_bad_value(tmp_path):
    cfg = GOOD.replace("    expected_exit_code: 1", "    expected_exit_code: one")
    problems = problems_of(tmp_path, cfg)
    assert any(p.startswith("invalid_tests[0] (invalid_unknown).expected_exit_code: must be")
               and "(got 'one')" in p for p in problems), problems


def test_4_5_missing_key_and_empty_test_list_are_plain_words(tmp_path):
    cfg = MINIMAL.replace("  binary_path: prog\n", "").replace(
        "security_tests:\n  - name: s1\n", "security_tests: []\n")
    problems = problems_of(tmp_path, cfg)
    assert "build.binary_path: required key is missing" in problems
    assert "security_tests: must list at least one test" in problems


def test_4_5_empty_config_is_one_clear_problem(tmp_path):
    problems = problems_of(tmp_path, "")
    assert len(problems) == 1 and "empty or is not a YAML mapping" in problems[0]


def test_4_5_missing_config_file_says_how_to_give_it(tmp_path):
    with pytest.raises(ZarabanError) as e:
        Target.load(tmp_path / "nope.yaml")
    assert e.value.code is ErrorCode.CONFIG_INVALID
    assert "does not exist" in e.value.details["problems"][0]
    assert "-c/--config" in e.value.details["problems"][0]


def test_4_5_messages_do_not_refer_to_the_design_documents(tmp_path):
    cfg = GOOD[: GOOD.index("invalid_tests:")] + GOOD[GOOD.index("security_tests:"):]
    _, warnings = Target.load(write(tmp_path, cfg.replace("name: token_parser",
                                                          "name: token_parser\nrepeats: 1")))
    for w in warnings:
        assert "spec" not in w.message.lower() and "§" not in w.message
