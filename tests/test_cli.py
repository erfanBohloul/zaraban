"""Unit tests for zaraban/cli.py (SPEC §3)."""

import sys
import textwrap

import pytest

import zaraban
from zaraban.cli import main, parse
from zaraban.models import ErrorCode, ZarabanError

GOOD = """\
name: token_parser
input_method: stdin
build:
  binary_path: token_parser
  release_cmd: make release
  sanitized_cmd: make sanitized
valid_tests:
  - name: valid_ping
    input_data: "PING"
    expected_exit_code: 0
security_tests:
  - name: exploit_primary
    input_data: "BOOM"
"""


def cfg(tmp_path, text=GOOD):
    p = tmp_path / "zaraban.yaml"
    p.write_text(textwrap.dedent(text), encoding="utf-8")
    return str(p)


# -- argument parsing (§3.3) -------------------------------------------------

def test_3_3_missing_config_exits_30():
    with pytest.raises(SystemExit) as e:
        parse([])  # -c is required
    assert e.value.code == 30


@pytest.mark.parametrize("argv", [
    ["-c", "x.yaml", "--nope"],         # unknown option
    ["--config"],                       # option without its value
    ["-c", "x.yaml", "--patch"],        # option without its value
])
def test_3_3_bad_argument_exits_30_not_2(argv, capsys):
    with pytest.raises(SystemExit) as e:
        parse(argv)
    assert e.value.code == 30
    assert "ARGUMENT_INVALID" in capsys.readouterr().err


def test_3_1_patch_required_unless_check_config():
    with pytest.raises(SystemExit) as e:
        parse(["-c", "x.yaml"])  # no --patch, no --check-config
    assert e.value.code == 30
    # but --check-config alone is allowed
    args = parse(["-c", "x.yaml", "--check-config"])
    assert args.check_config


def test_patch_accepted():
    args = parse(["-c", "x.yaml", "--patch", "p.diff"])
    assert args.patch == "p.diff"
    assert args.out == "out"


# -- main behaviours ---------------------------------------------------------

def test_version_works_without_config(capsys):
    # --version must not require -c (regression: -c was once required=True)
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"zaraban {zaraban.__version__}"
    assert parse(["--version"]).version is True


def test_3_3_main_returns_30_on_bad_argument(capsys):
    # main() turns the parser's SystemExit into a return value, not an exception.
    assert main(["-c", "x.yaml", "--nope"]) == 30


def test_check_config_ok(tmp_path, capsys):
    assert main(["-c", cfg(tmp_path), "--check-config"]) == 0
    assert "config OK" in capsys.readouterr().out


def test_check_config_invalid_exits_30(tmp_path, capsys):
    bad = GOOD.replace("name: token_parser", "name: token_parser\nbogus: 1")
    assert main(["-c", cfg(tmp_path, bad), "--check-config"]) == 30
    err = capsys.readouterr().err
    assert "CONFIG_INVALID" in err
    assert "  - unknown key 'bogus'" in err  # each problem on its own line


def test_check_config_missing_file_exits_30(tmp_path, capsys):
    assert main(["-c", str(tmp_path / "nope.yaml"), "--check-config"]) == 30
    assert "CONFIG_INVALID" in capsys.readouterr().err


def test_full_run_calls_injected_pipeline(tmp_path):
    seen = {}

    def fake_run(args, target, warnings):
        seen["name"] = target.name
        seen["patch"] = args.patch
        return 10

    rc = main(["-c", cfg(tmp_path), "--patch", "p.diff"], run=fake_run)
    assert rc == 10
    assert seen == {"name": "token_parser", "patch": "p.diff"}


def test_pipeline_import_error_is_tool_internal_30(tmp_path, capsys, monkeypatch):
    # A pipeline that cannot be imported is a bug in the tool, not a crash.
    monkeypatch.setitem(sys.modules, "zaraban.pipeline", None)
    rc = main(["-c", cfg(tmp_path), "--patch", "p.diff"])
    assert rc == 30
    assert "TOOL_INTERNAL" in capsys.readouterr().err


def test_13_pipeline_error_exits_30_with_its_code(tmp_path, capsys):
    def failing_run(args, target, warnings):
        raise ZarabanError(ErrorCode.PATCH_APPLY_FAILED, "no strip level applies")

    assert main(["-c", cfg(tmp_path), "--patch", "p.diff"], run=failing_run) == 30
    assert "PATCH_APPLY_FAILED: no strip level applies" in capsys.readouterr().err


def test_13_unexpected_exception_is_tool_internal_30(tmp_path, capsys):
    # A bug in the tool must give exit 30, not Python's exit 1.
    def buggy_run(args, target, warnings):
        raise KeyError("oops")

    assert main(["-c", cfg(tmp_path), "--patch", "p.diff"], run=buggy_run) == 30
    err = capsys.readouterr().err
    assert "TOOL_INTERNAL" in err
    assert "KeyError" in err  # the traceback is kept for debugging
