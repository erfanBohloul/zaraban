"""Stage 1 of the pipeline: build and execute (SPEC §2 steps 2–5).

Person 1 (Phase 2) implements this. It takes the initial
:class:`~zaraban.pipeline_state.RunContext` and fills ``sources``,
``build_set``, ``hardening``, ``results`` and ``environment`` — running
sources preparation, the four builds, the hardening check and the execution
matrix — then returns the same context for the analyze & report stage.

Step 0 ships only this seam; the body is a stub so the pipeline imports and
the two branches have a fixed entry point to build against.
"""

from __future__ import annotations

from .pipeline_state import RunContext


def build_and_execute(ctx: RunContext) -> RunContext:
    """Run sources, builds, hardening and the execution matrix (stages 2–5).

    Fills ``ctx.sources``, ``ctx.build_set``, ``ctx.hardening``,
    ``ctx.results``, ``ctx.environment`` and the build-side ``ctx.checks``,
    then returns ``ctx``.
    """
    raise NotImplementedError(
        "Phase 2 Person 1: implement build_and_execute "
        "(sources -> builds -> hardening -> execution matrix)")
