"""Stage 1 of the pipeline: build and execute (SPEC §2 steps 2–5).

Implemented by Person 1 (Phase 2). Given the initial
:class:`~zaraban.pipeline_state.RunContext`, it runs, in order:

1. source preparation (``sources.prepare``) → ``ctx.sources``;
2. the four isolated builds (``builder.build_all``) → ``ctx.build_set``;
   a build or profile failure **short-circuits**: the context carries the
   error and the analyze stage still writes a report (§6.2);
3. the hardening comparison (``hardening.report``) → ``ctx.hardening``;
4. the environment snapshot (``environment.gather``) → ``ctx.environment``;
5. the execution matrix (``execution.run_matrix``) → ``ctx.results``.

It also sets the build-side ``Checks`` (``builds_ok``, ``profiles_verified``,
``hardening_checked``, ``all_runs_completed``, ``results_stable``). The
remaining two checks (``base_reproduced``, ``bundles_replayed``) belong to the
analyze stage (Person 2).

The program is run through an injected ``run_one`` (default: an adapter over
Member B's ``runner.run_once``), so the orchestration is testable without B's
runner merged.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from . import builder, environment, execution, hardening, sources
from .execution import RunOne
from .models import BUILD_ORDER, BuildName, Version
from .pipeline_state import RunContext


def build_and_execute(ctx: RunContext, *, run_one: Optional[RunOne] = None) -> RunContext:
    """Run sources → builds → hardening → environment → execution (stages 2–5)."""
    # 1. Sources: --base defaults to the config's base_dir; --patch is required.
    base = getattr(ctx.args, "base", None) or str(ctx.target.base_dir)
    patch = ctx.args.patch
    ctx.sources = sources.prepare(base, patch, ctx.work_dir)

    # 2. The four builds. A build/profile failure stops here (§6.2): record it,
    #    still snapshot the environment, and let the analyze stage write the report.
    build_set = builder.build_all(
        ctx.sources.base_tree, ctx.sources.patch_tree, ctx.target, ctx.work_dir, ctx.out_dir)
    ctx.build_set = build_set
    ctx.add_warnings(build_set.warnings)
    ctx.checks.builds_ok = build_set.ok
    ctx.checks.profiles_verified = build_set.ok
    if not build_set.ok:
        if build_set.error is not None:
            ctx.add_errors([build_set.error])
        ctx.environment = environment.gather()
        ctx.settings = _settings(ctx.target)
        return ctx

    # 3. Hardening on the two release binaries.
    h_report, h_warnings = hardening.report(
        _binary_path(ctx, BuildName.BASE_RELEASE), _binary_path(ctx, BuildName.PATCH_RELEASE))
    ctx.hardening = h_report
    ctx.add_warnings(h_warnings)
    ctx.checks.hardening_checked = True

    # 4. Environment snapshot.
    ctx.environment = environment.gather()

    # 5. Execution matrix over all four builds.
    runner = run_one or _make_run_one(ctx)
    ex = execution.run_matrix(
        tests=ctx.target.all_tests(), builds=BUILD_ORDER,
        repeats=ctx.target.spec.repeats, run_one=runner, out_dir=ctx.out_dir)
    ctx.results = ex.results
    ctx.checks.all_runs_completed = ex.all_runs_completed
    ctx.checks.results_stable = ex.results_stable

    ctx.settings = _settings(ctx.target)
    return ctx


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _binary_path(ctx: RunContext, build: BuildName) -> Path:
    """The kept binary of one build, as an absolute path under the run dir."""
    return ctx.out_dir / ctx.build_set.records[build].binary.path


def _make_run_one(ctx: RunContext) -> RunOne:
    """Adapt Member B's runner to the ``run_one`` the matrix calls.

    Matches ``runner.run_once`` / ``RunSettings`` as used in B's
    ``test_runner.py``. Imported lazily so this module loads even before B's
    runner is on the branch; if B's signature changes, this one function is the
    only thing to update.
    """
    from .executor.runner import RunSettings, run_once  # Member B (§7)

    settings = RunSettings.from_target(ctx.target)

    def run_one(test, build: BuildName, repeat: int, run_dir: Path):
        binary = _binary_path(ctx, build)
        source_root = ctx.sources.base_tree if build.version is Version.BASE else ctx.sources.patch_tree
        per_run = Path(run_dir) / "runs" / test.name / build.value / str(repeat)
        return run_once(binary, test, settings, build, repeat, per_run,
                        source_root=str(source_root))

    return run_one


def _settings(target: Any) -> dict[str, Any]:
    """The run settings recorded in the report (§12.4)."""
    limits = target.spec.limits
    return {
        "repeats": target.spec.repeats,
        "limits": {
            "timeout_seconds": limits.timeout_seconds,
            "memory_limit_mb": limits.memory_limit_mb,
        },
    }
