#!/usr/bin/env python3
"""Run and check every delivered scenario.

For each ``targets/<target>/scenarios.yaml`` and each scenario in it:

1. check that ``patch`` gives exactly ``version_dir`` when applied to the base
   tree, so the diff and the complete tree describe the same version;
2. run the tool with ``--patch`` set to the diff file (and ``--no-promote``,
   so one scenario cannot add regression tests that change the next one);
3. check the exit code against ``expect_exit`` and the findings, in finding id
   order, against ``expect_findings`` (category and tests). Tests of kind
   ``regression`` (from ``tests/regression/``) are left out of the comparison,
   because which ones exist depends on earlier runs, not on the scenario;
4. with ``--save``, copy the run's output to ``results/<target>/<scenario>/``,
   without ``work/`` and without the ``builds/*/bin/`` binaries (the
   reproducer bundles keep their own copy);
5. exit 0 only if every scenario matched.

The tool never reads ``scenarios.yaml``; only this script does.

Usage::

    python3 scripts/run_matrix.py                    # every target
    python3 scripts/run_matrix.py target1_sample     # some targets
    python3 scripts/run_matrix.py --save             # also write results/
"""

from __future__ import annotations

import argparse
import filecmp
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import yaml

ROOT = Path(__file__).resolve().parent.parent
RUN_TIMEOUT_S = 1800


@dataclass
class Scenario:
    target: str
    target_dir: Path
    name: str
    patch: Path
    version_dir: Optional[Path]
    expect_exit: int
    expect_findings: list[dict]


@dataclass
class Outcome:
    scenario: Scenario
    exit_code: Optional[int] = None
    findings_ok: bool = False
    problems: list[str] = field(default_factory=list)
    run_dir: Optional[Path] = None

    @property
    def matched(self) -> bool:
        return not self.problems

    def line(self) -> str:
        s = self.scenario
        code = "-" if self.exit_code is None else str(self.exit_code)
        return (f"{s.target + '/' + s.name:<28}exit {code:<3}(expected {s.expect_exit:<2})  "
                f"findings {'ok ' if self.findings_ok else 'BAD'}  "
                f"{'PASS' if self.matched else 'FAIL'}")


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_scenarios(target_dir: Path) -> list[Scenario]:
    """The scenarios of one target; paths are relative to the target directory."""
    raw = yaml.safe_load((target_dir / "scenarios.yaml").read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        raise ValueError(f"{target_dir}/scenarios.yaml: expected a list of scenarios")
    out = []
    for i, s in enumerate(raw):
        missing = [k for k in ("name", "patch", "expect_exit") if k not in s]
        if missing:
            raise ValueError(f"{target_dir}/scenarios.yaml: scenario {i} lacks {', '.join(missing)}")
        out.append(Scenario(
            target=target_dir.name, target_dir=target_dir, name=s["name"],
            patch=target_dir / s["patch"],
            version_dir=target_dir / s["version_dir"] if s.get("version_dir") else None,
            expect_exit=int(s["expect_exit"]),
            expect_findings=list(s.get("expect_findings") or [])))
    return out


def base_tree(target_dir: Path) -> Path:
    """The target's base tree: ``base_dir`` of its config (default ``.``)."""
    cfg = yaml.safe_load((target_dir / "zaraban.yaml").read_text(encoding="utf-8")) or {}
    return (target_dir / cfg.get("base_dir", ".")).resolve()


# ---------------------------------------------------------------------------
# Step 1: the diff and the complete tree agree
# ---------------------------------------------------------------------------


def check_version_dir(base: Path, patch: Path, version_dir: Path) -> list[str]:
    """Apply ``patch`` to a copy of the parts of ``base`` that ``version_dir``
    holds (``Makefile``, ``src/``, ...), and compare the two trees file by file."""
    if not version_dir.is_dir():
        return [f"version_dir does not exist: {version_dir}"]
    if not patch.is_file():
        return [f"patch does not exist: {patch}"]
    with tempfile.TemporaryDirectory(prefix="zaraban-matrix-") as tmp:
        copy = Path(tmp) / "tree"
        copy.mkdir()
        for entry in version_dir.iterdir():
            src = base / entry.name
            if src.is_dir():
                shutil.copytree(src, copy / entry.name)
            elif src.is_file():
                shutil.copy2(src, copy / entry.name)
        if not _apply(patch, copy):
            return [f"{patch.name} does not apply to the base tree with -p0 to -p4"]
        diffs = _tree_differences(copy, version_dir)
    return [f"{patch.name} and {version_dir.name}/ differ: {d}" for d in diffs]


def _apply(patch: Path, tree: Path) -> bool:
    for p in range(5):
        args = ["git", "apply", f"-p{p}", str(patch.resolve())]
        check = subprocess.run(args[:2] + ["--check"] + args[2:], cwd=tree, capture_output=True)
        if check.returncode == 0:
            return subprocess.run(args, cwd=tree, capture_output=True).returncode == 0
    return False


def _tree_differences(a: Path, b: Path) -> list[str]:
    files_a = {p.relative_to(a) for p in a.rglob("*") if p.is_file()}
    files_b = {p.relative_to(b) for p in b.rglob("*") if p.is_file()}
    out = [f"only in the patched base: {p}" for p in sorted(files_a - files_b)]
    out += [f"only in version_dir: {p}" for p in sorted(files_b - files_a)]
    out += [f"content differs: {p}" for p in sorted(files_a & files_b)
            if not filecmp.cmp(a / p, b / p, shallow=False)]
    return out


# ---------------------------------------------------------------------------
# Steps 2-3: run the tool and compare
# ---------------------------------------------------------------------------

# run_tool(config, patch, out_dir) -> exit code. Injectable for tests.
RunTool = Callable[[Path, Path, Path], int]


def run_tool(config: Path, patch: Path, out_dir: Path) -> int:
    cmd = [sys.executable, "-m", "zaraban.cli", "-c", str(config), "--patch", str(patch),
           "--out", str(out_dir), "--no-promote"]
    # The tool prints its summary on stdout; it is also in summary.txt, so
    # only warnings and errors (stderr) are shown here.
    return subprocess.run(cmd, cwd=ROOT, stdout=subprocess.DEVNULL,
                          timeout=RUN_TIMEOUT_S).returncode


def find_run_dir(out_dir: Path) -> Optional[Path]:
    """The run directory ``<out>/<target name>/<run id>/`` of the run just made."""
    reports = sorted(out_dir.glob("*/*/report.json"), key=lambda p: p.stat().st_mtime)
    return reports[-1].parent if reports else None


def compare_findings(expected: list[dict], report: dict) -> list[str]:
    """Category and tests of each finding, in finding id order.
    Regression-kind tests are ignored (module docstring)."""
    got = [(f["category"], sorted(t["test"] for t in f["tests"] if t.get("kind") != "regression"))
           for f in report.get("findings", [])]
    want = [(e["category"], sorted(e.get("tests", []))) for e in expected]
    if got == want:
        return []
    fmt = lambda items: "; ".join(f"{c} {t}" for c, t in items) or "none"  # noqa: E731
    return [f"findings differ: expected {fmt(want)}, got {fmt(got)}"]


def run_scenario(s: Scenario, out_root: Path, run: RunTool = run_tool) -> Outcome:
    result = Outcome(s)
    if s.version_dir is not None:
        result.problems += check_version_dir(base_tree(s.target_dir), s.patch, s.version_dir)

    out_dir = out_root / s.target / s.name
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True)
    result.exit_code = run(s.target_dir / "zaraban.yaml", s.patch, out_dir)
    if result.exit_code != s.expect_exit:
        result.problems.append(f"exit {result.exit_code}, expected {s.expect_exit}")

    result.run_dir = find_run_dir(out_dir)
    if result.run_dir is None:
        result.problems.append(f"no report.json under {out_dir}")
        return result
    report = json.loads((result.run_dir / "report.json").read_text(encoding="utf-8"))
    finding_problems = compare_findings(s.expect_findings, report)
    result.findings_ok = not finding_problems
    result.problems += finding_problems
    if result.exit_code != s.expect_exit:  # say why the tool stopped, if it did
        result.problems += [f"tool error {e['code']}: {e['message']}" for e in report.get("errors", [])]
    return result


# ---------------------------------------------------------------------------
# Step 4: save
# ---------------------------------------------------------------------------


def save(run_dir: Path, dest: Path) -> None:
    """Copy a run to ``results/<target>/<scenario>/`` without ``work/`` and
    the ``builds/*/bin/`` binaries."""
    def ignore(directory: str, names: list[str]) -> set[str]:
        d = Path(directory)
        skip = set()
        if d == run_dir:
            skip.add("work")
        if d.parent == run_dir / "builds":
            skip.add("bin")
        return skip & set(names)

    shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(run_dir, dest, ignore=ignore)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None, *, root: Path = ROOT, run: RunTool = run_tool) -> int:
    p = argparse.ArgumentParser(description="Run and check the delivered scenarios.")
    p.add_argument("targets", nargs="*", help="target names (default: every target with scenarios.yaml)")
    p.add_argument("--save", action="store_true", help="copy each run to results/<target>/<scenario>/")
    p.add_argument("--out", default="out/run_matrix", help="where the runs are written")
    args = p.parse_args(argv)

    target_dirs = sorted(d.parent for d in (root / "targets").glob("*/scenarios.yaml"))
    if args.targets:
        target_dirs = [d for d in target_dirs if d.name in args.targets]
        unknown = set(args.targets) - {d.name for d in target_dirs}
        if unknown:
            print(f"no scenarios.yaml for: {', '.join(sorted(unknown))}", file=sys.stderr)
            return 1
    scenarios = [s for d in target_dirs for s in load_scenarios(d)]
    if not scenarios:
        print("no scenarios found", file=sys.stderr)
        return 1

    outcomes = []
    for s in scenarios:
        o = run_scenario(s, root / args.out, run)
        outcomes.append(o)
        print(o.line(), flush=True)
        for problem in o.problems:
            print(f"    {problem}")
        if args.save and o.run_dir is not None:
            save(o.run_dir, root / "results" / s.target / s.name)

    matched = sum(o.matched for o in outcomes)
    print(f"{matched}/{len(outcomes)} scenarios matched")
    return 0 if matched == len(outcomes) else 1


if __name__ == "__main__":
    sys.exit(main())
