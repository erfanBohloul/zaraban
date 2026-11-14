"""The shared state that the two pipeline stages pass between them.

The pipeline connects the modules into one run. The run is split in two
halves that are developed and tested independently:

* **build & execute**: the four builds, hardening, and the
  execution matrix — fills the second group of fields here;
* **analyze & report**: diff, findings, links, reproducers,
  regression, status and the report — reads them and fills the third group.

:class:`RunContext` is the *only* thing they exchange. It is a plain data
container: no logic lives here, exactly like :mod:`zaraban.models`. Keeping it
in its own module means both stages import it without touching each other's
files. Because every result is stored here as soon as it exists, a run that
fails half-way still has everything collected so far for its report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from .models import Checks, Issue

if TYPE_CHECKING:  # annotations only; no runtime import, so this stays light
    import argparse

    from .builder import BuildSet
    from .config import Target
    from .models import (Bundle, EnvironmentInfo, Finding, HardeningReport, RegressionTest,
                         Results, TestCase)
    from .runner import RunSettings
    from .sources import Sources

# The copies of the run's inputs, relative to the run directory.
CONFIG_COPY = "inputs/config.yaml"
DIFF_COPY = "inputs/patch.diff"


@dataclass
class RunContext:
    """Everything one run produces and consumes, passed between the two stages.

    ``out_dir`` is the run directory ``out/<target>/<run id>/``; every
    path in the report is relative to it. ``work_dir`` is ``<run dir>/work``,
    the temporary source and build copies, deleted at the end unless
    ``--keep-work`` is given.
    """

    # Set by the pipeline before stage 1.
    args: "argparse.Namespace"
    target: "Target"
    work_dir: Path
    out_dir: Path
    run_id: str
    started_at: str  # ISO 8601 UTC
    sources: Optional["Sources"] = None  # None when the sources could not be prepared
    environment: Optional["EnvironmentInfo"] = None
    run_settings: Optional["RunSettings"] = None
    settings: dict[str, Any] = field(default_factory=dict)  # report.settings

    # Filled by the build & execute stage.
    build_set: Optional["BuildSet"] = None
    hardening: Optional["HardeningReport"] = None
    tests: list["TestCase"] = field(default_factory=list)  # in run order
    results: Optional["Results"] = None  # results[test][build] -> CombinedResult

    # Filled by the analyze & report stage.
    findings: list["Finding"] = field(default_factory=list)
    bundles: list["Bundle"] = field(default_factory=list)
    regression_added: list["RegressionTest"] = field(default_factory=list)
    base_not_reproduced: list[str] = field(default_factory=list)

    # Accumulated across the whole run.
    checks: Checks = field(default_factory=Checks)
    warnings: list[Issue] = field(default_factory=list)
    errors: list[Issue] = field(default_factory=list)

    def add_warnings(self, issues: list[Issue]) -> None:
        self.warnings.extend(issues)

    def add_errors(self, issues: list[Issue]) -> None:
        self.errors.extend(issues)
