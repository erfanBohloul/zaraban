"""Assemble and write the run's report (SPEC §12).

``report.json`` is the machine-readable record of everything the run did: the
versions and diff, the environment, the four builds, hardening, every
finding, the regression tests added, and the final status. It is a dump of the
:class:`~zaraban.models.Report` dataclass, so its field order is the order in
that class and its JSON form comes from :func:`~zaraban.models.dump_json`
(§12.2). Alongside it this module writes ``summary.txt``: the short, human
verdict a person reads first.

This module only *collects* already-produced pieces into the report and
writes them. It makes no judgements: the verdict comes from
:mod:`zaraban.status` (§13), the findings from Member C (§8), the runs from
Member B (§7). It does not build or run anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from . import __version__
from .models import (
    BuildName,
    DiffInfo,
    EnvironmentInfo,
    Finding,
    HardeningReport,
    Issue,
    RegressionTest,
    Report,
    Status,
    VersionInfo,
    dump_json,
)

REPORT_FILE = "report.json"
SUMMARY_FILE = "summary.txt"

TOOL = {"name": "zaraban", "version": __version__}


def assemble_report(
    *,
    run_id: str,
    started_at: str,
    duration_s: float,
    target_name: str,
    config_path: str,
    config_sha256: str,
    versions: dict[str, Any],  # {"base": VersionInfo, "patch": VersionInfo, "diff": DiffInfo}
    environment: EnvironmentInfo,
    settings: dict[str, Any],
    builds: dict[BuildName, dict[str, Any]],
    status: Status,
    execution_logs: Optional[dict[BuildName, dict[str, dict[str, Any]]]] = None,
    hardening: Optional[HardeningReport] = None,
    findings: Optional[list[Finding]] = None,
    regression_added: Optional[list[RegressionTest]] = None,
    warnings: Optional[list[Issue]] = None,
    errors: Optional[list[Issue]] = None,
) -> Report:
    """Build the :class:`Report` from the pieces the pipeline has gathered.

    Only ``execution_logs``, ``hardening``, ``findings``, ``regression_added``,
    ``warnings`` and ``errors`` are optional; they default to empty, so a run
    that stopped early (a build failure with no findings) still produces a
    complete report (§12.1).
    """
    return Report(
        tool=dict(TOOL),
        run_id=run_id,
        started_at=started_at,
        duration_s=round(duration_s, 4),
        target={"name": target_name, "config": config_path, "config_sha256": config_sha256},
        versions=versions,
        environment=environment,
        settings=settings,
        builds=builds,
        hardening=hardening,
        execution_logs=execution_logs or {},
        findings=findings or [],
        regression_added=regression_added or [],
        status=status,
        warnings=warnings or [],
        errors=errors or [],
    )


def write(report: Report, out_dir: str | Path) -> tuple[Path, Path]:
    """Write ``report.json`` and ``summary.txt`` into ``out_dir`` (§12.1).

    Returns the two paths. ``report.json`` is the full record; ``summary.txt``
    is the human verdict (also printed to the console by the CLI).
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / REPORT_FILE
    summary_path = out / SUMMARY_FILE
    dump_json(report, report_path)
    summary_path.write_text(human_summary(report), encoding="utf-8")
    return report_path, summary_path


def human_summary(report: Report) -> str:
    """The short, readable verdict (§12.1).

    One block: the result and exit code, the reason, the build tally, each
    finding on a line, and the counts of warnings and errors.
    """
    st: Status = report.status
    lines: list[str] = []
    lines.append(f"{report.tool['name']} {report.tool['version']} — {report.target['name']}")
    lines.append(f"Result: {st.exit_name} (exit {int(st.exit_code)})")
    lines.append(f"Reason: {st.reason}")
    lines.append("")

    ok = sum(1 for b in report.builds.values() if b.get("status") == "ok")
    lines.append(f"Builds: {ok}/{len(report.builds)} ok")

    lines.append(f"Findings: {len(report.findings)}")
    for f in report.findings:
        tests = ", ".join(f.test_names)
        lines.append(f"  {f.id}  {f.category.value}" + (f"  tests: {tests}" if tests else ""))

    if report.hardening and report.hardening.changes:
        downgrades = [c.protection for c in report.hardening.changes
                      if c.kind.value == "downgrade"]
        if downgrades:
            lines.append(f"Hardening downgrades: {', '.join(downgrades)}")

    if report.regression_added:
        lines.append(f"Regression tests added: {len(report.regression_added)}")

    lines.append(f"Warnings: {len(report.warnings)}")
    for w in report.warnings:
        lines.append(f"  [{w.code}] {w.message}")
    if report.errors:
        lines.append(f"Errors: {len(report.errors)}")
        for e in report.errors:
            lines.append(f"  [{e.code}] {e.message}")

    lines.append("")
    lines.append(f"Full report: {REPORT_FILE}")
    return "\n".join(lines) + "\n"
