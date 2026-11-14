"""Stage 1 of the pipeline: build and execute.

Given the :class:`~zaraban.pipeline_state.RunContext` that the pipeline set
up (sources prepared, run directory created), it first loads the tests: the
config tests, then the regression tests of earlier runs. An invalid
regression test file stops the run with ``CONFIG_INVALID`` before anything is
built, like an invalid config. Then it runs, in order:

1. the four isolated builds (``builder.build_all``) → ``ctx.build_set``;
   a build or profile failure **stops here**: the build's error goes
   into the context and the analyze stage still writes the report;
2. the hardening comparison (``hardening.report``) → ``ctx.hardening``;
3. the execution matrix: every test, on every build, ``repeats`` times
   (``runner.run_test``) → ``ctx.tests`` and ``ctx.results``.

It sets the build-side ``Checks`` (``builds_ok``, ``profiles_verified``,
``hardening_checked``, ``all_runs_completed``, ``results_stable``); the
other two (``base_reproduced``, ``bundles_replayed``) belong to the analyze
stage.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Optional

from . import builder, hardening, regression, runner
from .models import BUILD_ORDER, BuildName, CombinedResult
from .pipeline_state import RunContext

# runner.run_test's signature; injectable so the stage is testable without a compiler.
RunTestFn = Callable[..., CombinedResult]


def build_and_execute(ctx: RunContext, *, run_test: Optional[RunTestFn] = None) -> RunContext:
    """Run builds → hardening → execution and return ``ctx``."""
    run_test = run_test or runner.run_test
    target = ctx.target

    # 0. The tests: config tests, then regression tests from earlier runs.
    #    Loaded first, so a bad regression file is a config error before any
    #    build.
    tests = target.all_tests() + regression.load_tests(target)

    # 1. The four builds; stop at a failure.
    build_set = builder.build_all(ctx.sources.base_tree, ctx.sources.patch_tree, target,
                                  ctx.work_dir, ctx.out_dir)
    ctx.build_set = build_set
    ctx.add_warnings(build_set.warnings)
    ctx.checks.builds_ok = (len(build_set.records) == len(BUILD_ORDER)
                            and all(r.status == "ok" for r in build_set.records.values()))
    ctx.checks.profiles_verified = build_set.ok
    if not build_set.ok:
        ctx.add_errors([build_set.error])
        return ctx

    # 2. Hardening of the two release binaries.
    ctx.hardening, h_warnings = hardening.report(binary(ctx, BuildName.BASE_RELEASE),
                                                 binary(ctx, BuildName.PATCH_RELEASE))
    ctx.add_warnings(h_warnings)
    ctx.checks.hardening_checked = True

    # 3. Every test on every build, `repeats` times; regression tests last.
    ctx.tests = tests
    ctx.results = {
        t.name: {b: run_test(binary(ctx, b), t, ctx.run_settings, b, target.spec.repeats,
                             ctx.out_dir, source_root=source_root(ctx, b))
                 for b in BUILD_ORDER}
        for t in ctx.tests
    }
    ctx.add_warnings(runner.output_warnings(
        [r for per_build in ctx.results.values() for c in per_build.values() for r in c.runs]))
    # A run that cannot complete raises (TOOL_INTERNAL), so reaching here means
    # every planned run produced its record.
    ctx.checks.all_runs_completed = True
    ctx.checks.results_stable = not any(
        c.flaky for per_build in ctx.results.values() for c in per_build.values())
    return ctx


def binary(ctx: RunContext, build: BuildName) -> Path:
    """The kept binary of one build (``builds/<build>/bin/<name>``)."""
    return ctx.out_dir / ctx.build_set.records[build].binary.path


def source_root(ctx: RunContext, build: BuildName) -> str:
    """The build's own source copy ``work/<build>/``. Its binary's debug
    info points there, so frame paths are made relative to it.

    Always absolute: the debug info holds absolute paths
    (``/workspace/out/.../work/patch-sanitized/src/main.c``), and a relative
    ``--out`` would leave the prefix unmatched, so frames would keep
    build-specific paths and the same bug would get a different key on base
    and on patch."""
    return os.path.abspath(ctx.work_dir / build.value)
