"""The shared pipeline state that the two Phase 2 stages pass between them.

Phase 2 wires the Phase 1 modules into one run (SPEC §2). The run is split in
two halves that two people build independently:

* **build & execute** (stages 2–5): sources, the four builds, hardening, and
  the execution matrix — fills the first group of fields here;
* **analyze & report** (stages 6–11): diff, findings, links, reproducers,
  regression, status and the report — reads them.

:class:`RunContext` is the *only* thing they exchange. It is a plain data
container: no logic lives here, exactly like :mod:`zaraban.models`. Keeping it
in its own module means both branches import it without touching each other's
files.
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
    from .models import EnvironmentInfo, HardeningReport, Results
    from .sources import Sources


@dataclass
class RunContext:
    """Everything one run produces and consumes, passed between the two stages.

    The pipeline builds it with the always-present fields; the build & execute
    stage fills ``sources``..``environment``; the analyze & report stage reads
    them and fills ``checks`` as it goes. ``warnings``/``errors`` accumulate
    across the whole run.
    """

    # Always set by the pipeline before stage 1.
    args: "argparse.Namespace"
    target: "Target"
    work_dir: Path
    out_dir: Path
    run_id: str
    started_at: str  # ISO 8601 UTC

    # Filled by the build & execute stage (Person 1).
    sources: Optional["Sources"] = None
    build_set: Optional["BuildSet"] = None
    hardening: Optional["HardeningReport"] = None
    results: Optional["Results"] = None  # results[test][build] -> CombinedResult
    environment: Optional["EnvironmentInfo"] = None

    # Accumulated across both stages.
    settings: dict[str, Any] = field(default_factory=dict)
    checks: Checks = field(default_factory=Checks)
    warnings: list[Issue] = field(default_factory=list)
    errors: list[Issue] = field(default_factory=list)

    def add_warnings(self, issues: list[Issue]) -> None:
        self.warnings.extend(issues)

    def add_errors(self, issues: list[Issue]) -> None:
        self.errors.extend(issues)
