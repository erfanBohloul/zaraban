"""Command-line interface for Zaraban (SPEC §3).

One invocation validates one patch of one target:

    python -m zaraban.cli -c <config> --patch <patch> [options]

The option set is deliberately small: no option can switch off a required
check, because that could produce a PASS the course spec would not accept
(SPEC §3.1). Invalid arguments exit with code 30, not argparse's default 2
(SPEC §3.3).

The process never ends with an exit code outside 0/10/20/30/40: an error the
tool did not expect is reported as ``TOOL_INTERNAL`` with exit 30 (SPEC §13).
"""

from __future__ import annotations

import argparse
import sys
import traceback
from typing import Callable, NoReturn, Optional, Sequence

from . import __version__
from .config import Target
from .models import ErrorCode, ExitCode, ZarabanError

VERSION = __version__  # single source: zaraban/__init__.py
PROG = "zaraban"


class _Parser(argparse.ArgumentParser):
    """ArgumentParser that exits 30 (BUILD_OR_CONFIG_ERROR) on a bad argument."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        print(f"{ErrorCode.ARGUMENT_INVALID.value}: {message}", file=sys.stderr)
        raise SystemExit(int(ExitCode.BUILD_OR_CONFIG_ERROR))


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog=PROG, description="Validate a security patch by building and running the target.")
    # Not required at the argparse level, so --version works on its own.
    # parse() enforces it for every run.
    p.add_argument("-c", "--config", metavar="FILE",
                   help="path to the target's zaraban.yaml")
    p.add_argument("--patch", metavar="PATCH",
                   help="the patched version: a diff file or a source directory (§3.2)")
    p.add_argument("--base", metavar="DIR",
                   help="the base version directory (default: base_dir from the config)")
    p.add_argument("--out", default="out", metavar="DIR",
                   help="directory for all outputs of this run (default: out/)")
    p.add_argument("--no-promote", action="store_true",
                   help="do not copy new regression tests into the target's tests/regression/")
    p.add_argument("--keep-work", action="store_true",
                   help="keep the temporary build directories after the run")
    p.add_argument("--check-config", action="store_true",
                   help="only validate the config and its files, then exit 0 (valid) or 30 (invalid)")
    p.add_argument("-v", "--verbose", action="store_true", help="print progress details")
    p.add_argument("--version", action="store_true", help="print the tool version and exit")
    return p


def parse(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse arguments. Raises ``SystemExit(30)`` on any argument error.

    ``--version`` needs no other argument; every other run needs ``-c``, and
    ``--patch`` unless ``--check-config`` is given (§3.1).
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        return args
    if not args.config:
        parser.error("the following arguments are required: -c/--config")
    if not args.check_config and not args.patch:
        parser.error("--patch is required unless --check-config is given")
    return args


# A pipeline runner is injected so the CLI is testable before Phase 2 wires the
# real pipeline. Signature: run(args, target, warnings) -> exit code.
RunPipeline = Callable[[argparse.Namespace, Target, list], int]


def main(argv: Optional[Sequence[str]] = None, run: Optional[RunPipeline] = None) -> int:
    """Entry point. Returns the process exit code (SPEC §13.1)."""
    try:
        args = parse(argv)
    except SystemExit as exc:  # argument error already reported
        return int(exc.code) if isinstance(exc.code, int) else int(ExitCode.BUILD_OR_CONFIG_ERROR)

    if args.version:
        print(f"{PROG} {VERSION}")
        return int(ExitCode.PASS)

    # The config is loaded and validated for every run (§4.5).
    try:
        target, warnings = Target.load(args.config)
    except ZarabanError as exc:
        _report_error(exc)
        return int(ExitCode.BUILD_OR_CONFIG_ERROR)
    except Exception:
        return _report_internal_error()

    for w in warnings:
        print(f"warning [{w.code}]: {w.message}", file=sys.stderr)

    if args.check_config:
        print(f"config OK: {target.name} "
              f"({len(target.all_tests())} tests, {len(warnings)} warning(s))")
        return int(ExitCode.PASS)

    # Full run: wired in Phase 2. A runner can be injected for testing now.
    if run is None:
        try:
            from .pipeline import run as run  # type: ignore
        except ModuleNotFoundError as exc:
            if exc.name != f"{__package__}.pipeline":
                return _report_internal_error()  # pipeline exists but its imports fail
            print("ERROR: the validation pipeline is implemented in Phase 2; "
                  "only --check-config and --version work so far.", file=sys.stderr)
            return int(ExitCode.BUILD_OR_CONFIG_ERROR)
        except Exception:
            return _report_internal_error()

    # The pipeline writes the report itself, also when it fails (§13). This is
    # the last safety net, so that no error ends the process with Python's
    # exit code 1 and a bare traceback.
    try:
        return int(run(args, target, warnings))
    except ZarabanError as exc:
        _report_error(exc)
        return int(ExitCode.BUILD_OR_CONFIG_ERROR)
    except Exception:
        return _report_internal_error()


def _report_error(exc: ZarabanError) -> None:
    print(f"{exc.code.value}: {exc.message}", file=sys.stderr)
    for problem in exc.details.get("problems", []):
        print(f"  - {problem}", file=sys.stderr)


def _report_internal_error() -> int:
    """Report an unexpected exception as TOOL_INTERNAL; return exit code 30."""
    print(f"{ErrorCode.TOOL_INTERNAL.value}: unexpected error in zaraban "
          "(this is a bug in the tool)", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    return int(ExitCode.BUILD_OR_CONFIG_ERROR)


if __name__ == "__main__":
    raise SystemExit(main())
