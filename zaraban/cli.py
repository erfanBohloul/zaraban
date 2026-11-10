"""Command Line Interface (CLI) entrypoint for Zaraban."""

from __future__ import annotations
import argparse
import sys
from pathlib import Path

from zaraban import __version__
from zaraban.constants import ExitCode
from zaraban.config import TargetConfig
from zaraban.core.validator import PatchValidator
from zaraban.reporter import ConsoleReporter, JsonReporter


def parse_args(args=None):
    parser = argparse.ArgumentParser(
        prog="zaraban",
        description="Automated Security Patch Validation and Regression Testing Tool in CI/CD"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-c", "--config",
        required=True,
        help="Path to the target configuration file (e.g. zaraban.yaml)"
    )
    parser.add_argument(
        "--report",
        default="report.json",
        help="Output path for the structured JSON report (default: report.json)"
    )
    parser.add_argument(
        "--base-dir",
        help="Explicit path to base (unpatched) source directory"
    )
    parser.add_argument(
        "--patch-dir",
        help="Explicit path to patched source directory"
    )
    parser.add_argument(
        "--diff",
        help="Path to git diff file if not derived automatically"
    )
    parser.add_argument(
        "--artifacts",
        default="artifacts",
        help="Directory to store reproducer bundles and regression suites (default: artifacts)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    return parser.parse_args(args)


def main():
    args = parse_args()
    config_path = Path(args.config).resolve()
    if not config_path.is_file():
        print(f"[!] Error: Configuration file not found: {args.config}", file=sys.stderr)
        sys.exit(ExitCode.ERROR_CONFIG_OR_BUILD)

    try:
        config = TargetConfig.from_file(config_path)
    except Exception as e:
        print(f"[!] Error parsing configuration file: {e}", file=sys.stderr)
        sys.exit(ExitCode.ERROR_CONFIG_OR_BUILD)

    # Determine base and patch directories
    target_root = config_path.parent
    base_dir = Path(args.base_dir).resolve() if args.base_dir else target_root
    patch_dir = Path(args.patch_dir).resolve() if args.patch_dir else target_root
    diff_file = Path(args.diff).resolve() if args.diff else (target_root / config.diff_file if config.diff_file else None)

    validator = PatchValidator(
        config=config,
        base_dir=base_dir,
        patch_dir=patch_dir,
        diff_file=diff_file,
        artifacts_dir=args.artifacts
    )

    try:
        summary = validator.validate()
    except Exception as e:
        print(f"[!] Unexpected error during validation: {e}", file=sys.stderr)
        sys.exit(ExitCode.ERROR_CONFIG_OR_BUILD)

    ConsoleReporter.print_summary(summary)
    JsonReporter.save_report(summary, args.report)

    sys.exit(int(summary.exit_code))


if __name__ == "__main__":
    main()
