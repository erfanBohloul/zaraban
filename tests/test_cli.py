"""Unit tests for zaraban/cli.py (SPEC §3)."""

import textwrap

import pytest

from zaraban import cli
from zaraban.cli import main, parse

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


def test_3_3_bad_argument_exits_30_not_2():
    with pytest.raises(SystemExit) as e:
        parse(["-c", "x.yaml", "--nope"])
    assert e.value.code == 30


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
    assert "zaraban" in capsys.readouterr().out
    assert parse(["--version"]).version is True


def test_check_config_ok(tmp_path, capsys):
    assert main(["-c", cfg(tmp_path), "--check-config"]) == 0
    assert "config OK" in capsys.readouterr().out


def test_check_config_invalid_exits_30(tmp_path, capsys):
    bad = GOOD.replace("name: token_parser", "name: token_parser\nbogus: 1")
    assert main(["-c", cfg(tmp_path, bad), "--check-config"]) == 30
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


def test_full_run_without_pipeline_reports_not_ready(tmp_path, capsys):
    # pipeline.py does not exist yet (Phase 2); main must fail cleanly, not crash.
    rc = main(["-c", cfg(tmp_path), "--patch", "p.diff"])
    assert rc == 30
    assert "Phase 2" in capsys.readouterr().err
