"""Assemble and write the run's report.

``report.json`` is the machine-readable record of everything the run did: the
versions and diff, the environment, the four builds, hardening, every
finding, the regression tests added, and the final status. It is a dump of the
:class:`~zaraban.models.Report` dataclass, so its field order is the order in
that class and its JSON form comes from :func:`~zaraban.models.dump_json`.
Alongside it this module writes ``summary.txt``, the short human-readable
version; the same text is printed at the end of the run.

This module only *collects* already-produced pieces into the report and
writes them. It makes no judgements: the verdict comes from
:mod:`zaraban.status`, the findings from :mod:`zaraban.findings`, the runs
from :mod:`zaraban.runner`. It does not build or run anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from . import __version__
from .models import (
    BUILD_ORDER,
    BuildName,
    BuildRecord,
    Bundle,
    EnvironmentInfo,
    Finding,
    HardeningReport,
    Issue,
    RegressionTest,
    Report,
    Status,
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
    complete report.
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




def build_entries(records: dict[BuildName, BuildRecord]) -> dict[BuildName, dict[str, Any]]:
    """The ``builds`` field of report.json: for each build its
    ``status``, ``binary_sha256`` and ``details`` (path of ``build.json``)."""
    return {
        name: {
            "status": rec.status,
            "binary_sha256": rec.binary.sha256 if rec.binary else None,
            "details": f"builds/{name.value}/build.json",
        }
        for name, rec in records.items()
    }


def write(report: Report, out_dir: str | Path,
          bundles: Optional[list[Bundle]] = None) -> tuple[Path, Path]:
    """Write ``report.json`` and ``summary.txt`` into the run directory.

    ``bundles`` gives the size and replay line of each finding.
    Returns the two paths.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / REPORT_FILE
    summary_path = out / SUMMARY_FILE
    dump_json(report, report_path)
    summary_path.write_text(human_summary(report, bundles, report_path), encoding="utf-8")
    return report_path, summary_path


# ---------------------------------------------------------------------------
# summary.txt
# ---------------------------------------------------------------------------

_W = 11  # width of the section labels ("BUILDS     ")
_D = 11  # width of the per-finding labels ("sanitized: ")


def human_summary(report: Report, bundles: Optional[list[Bundle]] = None,
                  report_path: str | Path = REPORT_FILE) -> str:
    """The human-readable summary, in the agreed order: target and run id;
    base and patch; the four builds; the hardening comparison; tests, builds,
    repeats and flaky results; one block per finding; warnings and errors
    (each error with its listed problems); the exit code and name; the path
    of ``report.json``. Tests without findings are only counted."""
    by_finding = {b.finding: b for b in bundles or []}
    lines = [
        f"{report.tool['name'].upper()} {report.tool['version']}  "
        f"{report.target['name']}  run {report.run_id}",
        f"base:  {_version_line(report.versions.get('base'))}",
        f"patch: {_version_line(report.versions.get('patch'))}",
        "",
        _label("BUILDS") + _builds_line(report.builds),
        _label("HARDENING") + _hardening_line(report.hardening),
        _label("TESTS") + _tests_line(report),
    ]
    variants_line = _variants_line(report.settings.get("variants"))
    if variants_line:
        lines.append(_label("VARIANTS") + variants_line)
    lines += [
        "",
        "FINDINGS",
    ]
    if not report.findings:
        lines.append("  (none)")
    for f in report.findings:
        lines.extend(_finding_block(f, by_finding.get(f.id)))

    if report.warnings:
        lines.append("")
        lines.extend(_warning_lines(report.warnings))
    if report.errors:
        if not report.warnings:
            lines.append("")
        for e in report.errors:
            lines.append(_label("ERROR") + f"{e.code}: {e.message}")
            lines.extend(f"{'':<{_W}}  - {p}" for p in (e.details or {}).get("problems", []))

    st: Status = report.status
    lines += [
        "",
        _label("RESULT") + f"exit {int(st.exit_code)}  {st.exit_name}",
        f"{'report:':<{_W}}{report_path}",
    ]
    return "\n".join(lines) + "\n"


_MAX_PER_CODE = 3  # warnings of one code shown in full; the rest are counted


def _warning_lines(warnings: list[Issue]) -> list[str]:
    """One line per warning, with its message; a code that repeats (one
    truncated output per repeat, say) shows its first few and a count."""
    by_code: dict[str, list[str]] = {}
    for w in warnings:
        by_code.setdefault(w.code, [])
        if w.message not in by_code[w.code]:
            by_code[w.code].append(w.message)
    lines = []
    for code, messages in by_code.items():
        for m in messages[:_MAX_PER_CODE]:
            lines.append(f"{code}: {m}")
        if len(messages) > _MAX_PER_CODE:
            lines.append(f"{code}: ... and {len(messages) - _MAX_PER_CODE} more "
                         "(see report.json)")
    return [(_label("WARNINGS") if i == 0 else _label("")) + line
            for i, line in enumerate(lines)]


def _label(text: str) -> str:
    return f"{text:<{_W}}"


def _get(obj: Any, key: str) -> Any:
    """A field of a model or of its dict form (versions and builds may be either)."""
    if obj is None:
        return None
    return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)


def _version_line(v: Any) -> str:
    if v is None:
        return "-"
    form = _get(v, "form")
    strip = _get(v, "strip_level")
    extra = f", -p{strip}" if form == "diff" and strip is not None else ""
    return f"{_get(v, 'ref')} ({form}{extra})"


def _builds_line(builds: dict[Any, Any]) -> str:
    def key(name: Any) -> str:
        return name.value if isinstance(name, BuildName) else str(name)
    by_name = {key(k): v for k, v in builds.items()}
    order = [b.value for b in BUILD_ORDER] + [k for k in by_name if k not in
                                              {b.value for b in BUILD_ORDER}]
    return " · ".join(f"{n} {_get(by_name[n], 'status') or '-'}" for n in order if n in by_name) \
        or "not run"


def _on_off(value: Any) -> str:
    if isinstance(value, bool):
        return "on" if value else "off"
    return getattr(value, "value", str(value))


def _hardening_line(h: Optional[HardeningReport]) -> str:
    if h is None:
        return "not checked"
    parts = []
    for prot, label in (("nx", "NX"), ("pie", "PIE"), ("relro", "RELRO"), ("canary", "canary")):
        base = getattr(h.base, prot).value
        patch = getattr(h.patch, prot).value
        parts.append(f"{label} {_on_off(base)}→{_on_off(patch)}")
    downgrades = [c.protection for c in h.changes if c.kind.value == "downgrade"]
    if not h.changes:
        note = "(no changes)"
    elif downgrades:
        note = f"(downgrade: {', '.join(downgrades)})"
    else:
        note = f"(improvement: {', '.join(c.protection for c in h.changes)})"
    return " · ".join(parts) + "   " + note


def _tests_line(report: Report) -> str:
    if not report.execution_logs:
        return "not run"
    tests: set[str] = set()
    flaky = 0
    for per_test in report.execution_logs.values():
        for name, result in per_test.items():
            tests.add(name)
            if _get(result, "flaky"):
                flaky += 1
    repeats = report.settings.get("repeats", "?")
    return (f"{len(tests)} tests × {len(report.builds)} builds × {repeats} repeats"
            f"   flaky: {flaky}")


def _variants_line(v: Optional[dict[str, Any]]) -> str:
    """What the variant step did; empty when it was off (then no line)."""
    if not v or not v.get("enabled"):
        return ""
    if "screening_runs" not in v:  # on, but the run stopped before it
        return f"on (seed {v.get('seed')}), not run"
    kept = [k["test"] for k in v.get("kept", [])]
    text = (f"seed {v.get('seed')}, {v['screening_runs']} screening runs on patch-sanitized"
            f", kept {len(kept)}")
    if kept:
        text += ": " + ", ".join(kept)
    if v.get("skipped_tests"):
        text += f"   (no input to mutate: {', '.join(v['skipped_tests'])})"
    return text


def _finding_block(f: Finding, bundle: Optional[Bundle]) -> list[str]:
    headline = f.signature or (f.error_type.value if f.error_type else "")
    out = [f"  {f.id} {f.category.value}" + (f"  {headline}" if headline else "")]

    def row(label: str, text: str) -> None:
        # At least one space after the label, also for "regression:" (as wide as _D).
        out.append(f"        {label + ':':<{_D - 1}} {text}")

    row("tests", " · ".join(
        f"{t.test} {t.on_patch.value}" if t.on_patch else t.test for t in f.tests) or "-")
    if f.release:
        row("release", _profile_text(f.release))
    if f.sanitized:
        row("sanitized", _profile_text(f.sanitized))
    if f.link is not None:
        row("link", _link_text(f))
    if bundle is not None:
        row("bundle", _bundle_text(bundle))
    elif f.reproducer:
        row("bundle", f.reproducer.rstrip("/"))
    if f.regression_test:
        row("regression", f.regression_test)
    if f.notes:
        row("notes", f.notes)
    return out


def _short(text: str) -> str:
    """``CRASH FORTIFY SIGABRT`` → ``FORTIFY/SIGABRT``; other results unchanged."""
    if text.startswith("CRASH ") and ";" not in text and "(" not in text:
        return "/".join(text.split()[1:])
    return text


def _profile_text(d: dict[str, str]) -> str:
    return f"{_short(d.get('base', '-'))} → {_short(d.get('patch', '-'))}"


def _link_text(f: Finding) -> str:
    link = f.link
    level = link.level.value
    where = []
    if link.file:
        where.append(f"{link.file}:{link.line}" if link.line is not None else link.file)
    if link.function:
        where.append(link.function)
    side = f" ({link.side.value} side)" if link.side is not None else ""
    return f"{level}  {' '.join(where)}{side}".rstrip() if where else f"{level}{side}"


def _bundle_text(b: Bundle) -> str:
    sizes = (f"{b.original_size} → {b.minimized_size} bytes" if b.minimized_size is not None
             else f"{b.original_size} bytes (not minimized)")
    ok = sum(r.reproduced for r in b.replays)
    replay = f"replay {ok}/{len(b.replays)}"
    if b.replayed_input == "orig" and b.minimized_size is not None:
        replay += " (original input)"
    if not b.stable:
        replay += ", UNSTABLE"
    return f"{b.path}  {sizes}, {replay}"
