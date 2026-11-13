"""Stage 2 of the pipeline: analyze and report (SPEC §2 steps 6–11).

Person 2 (Phase 2) implements this. It reads the filled
:class:`~zaraban.pipeline_state.RunContext` and drives the diff parse,
findings and links (Member C), the reproducers and regression tests
(Member D), the status decision and the report writer — then returns the
process exit code.

Step 0 ships only this seam; the body is a stub so the pipeline imports and
the two branches have a fixed entry point to build against.
"""

from __future__ import annotations

from .pipeline_state import RunContext


def analyze_and_report(ctx: RunContext) -> int:
    """Drive findings -> reproducers -> regression -> status -> report (6–11).

    Completes ``ctx.checks``, writes ``report.json`` and ``summary.txt``, and
    returns the final exit code (``status.exit_code``).
    """
    raise NotImplementedError(
        "Phase 2 Person 2: implement analyze_and_report "
        "(findings -> reproducers -> regression -> status -> report)")
