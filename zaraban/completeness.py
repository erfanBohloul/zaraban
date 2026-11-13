"""Nothing is lost: the end-of-run completeness check (SPEC §8.7).

Every abnormal result (a crash, an oracle mismatch, a timeout, a resource
limit, or a flaky result, on any build) must be referenced by at least one
finding or status condition, and each crash result with a signature must be
in exactly one crash finding. A failure is a bug in the tool: it raises
:class:`~zaraban.models.ZarabanError` with ``TOOL_INTERNAL`` (exit 30).

Phase 2 Task 2.4 (Member B): not written yet. :func:`check` is already called
at its place in the run, after findings and bundles and before the status.
"""

from __future__ import annotations

from .models import Finding, Results


def check(results: Results, findings: list[Finding]) -> None:
    """Raise ``ZarabanError(TOOL_INTERNAL)`` if an abnormal result is in no
    finding (§8.7). Placeholder until Task 2.4: accepts every run."""
    return None
