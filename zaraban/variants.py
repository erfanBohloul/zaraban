"""Variants: bounded, seeded mutations of the security inputs.

Seeing no crash in the tests does not prove that the vulnerability is gone:
an incomplete patch often blocks the known exploit but not a slightly
different input. This optional step looks for such inputs. It is off by
default; ``variants.enabled`` in the config or ``--variants`` on the command
line turns it on.

How it works:

1. For each security test that has an input, a fixed number of mutated
   inputs is made from it. The mutations are seeded with ``variants.seed``
   and the test name, so the same config, test and patch always give the
   same candidates, in the same order.
2. Each candidate runs **once**, on ``patch-sanitized`` only (screening),
   with the same command, environment and limits as the normal runs. The
   total number of these runs is ``variants.budget_runs``; there is no time
   budget, so the result never depends on the speed of the machine.
3. A candidate that crashes on patch with a bug that no normal test showed
   on patch runs once more; if it shows the same bug again it is kept, one
   per bug, at most ``variants.max_tests``. Both runs count in the budget.
4. Each kept candidate becomes a test of kind ``variant`` and runs like any
   other test: on all four builds, ``repeats`` times. From there the normal
   rules apply: findings with the same-bug rule, links to the patch,
   minimization, the reproducer bundle and the regression test.

The mutations do not know the program. They use only the input itself and
the changed lines of the diff: integers there become interesting lengths
(``n - 1``, ``n``, ``n + 1``) and character literals become interesting bytes.
"""

from __future__ import annotations

import hashlib
import random
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from . import findings
from .models import BuildName, InputMethod, Outcome, RunRecord, TestCase, TestKind

# Bytes that often matter to parsers, tried in every target.
SPECIAL_BYTES = b"\x00\xff\x7f\x80\n\r\t \"'\\/*%{}[]<>"
# Interesting lengths are taken from the diff in this range.
MIN_SIZE, MAX_SIZE = 2, 1 << 16
# A candidate never grows past this (the config's input limit is 1 MB).
MAX_CANDIDATE_BYTES = 1 << 20
# How many structured candidates (cut the end, resize a run) come before the
# random ones; the rest of each test's share of the budget is random.
_TAIL_CUTS = 8

_INT_RE = re.compile(r"(?<![\w.])(0[xX][0-9a-fA-F]+|\d+)(?![\w.])")
_CHAR_RE = re.compile(r"'(\\x[0-9a-fA-F]{1,2}|\\[0-7]{1,3}|\\.|[^'\\])'")
_ESCAPES = {"n": 10, "r": 13, "t": 9, "0": 0, "\\": 92, "'": 39, '"': 34, "a": 7,
            "b": 8, "f": 12, "v": 11}


@dataclass
class Settings:
    """The variant settings of one run (config block, then CLI override)."""

    enabled: bool = False
    budget_runs: int = 200
    seed: int = 1
    max_tests: int = 5

    def as_report(self) -> dict:
        return {"enabled": self.enabled, "budget_runs": self.budget_runs,
                "seed": self.seed, "max_tests": self.max_tests}


@dataclass
class Hints:
    """What the diff suggests: lengths and bytes from its changed lines."""

    sizes: list[int] = field(default_factory=list)
    tokens: bytes = b""


@dataclass
class Screened:
    """The outcome of the screening, for the report."""

    runs: int = 0
    per_test: dict[str, int] = field(default_factory=dict)  # candidates run per source test
    skipped: list[str] = field(default_factory=list)  # security tests without an input
    unconfirmed: int = 0  # new crashes that a second run did not show again
    kept: list[TestCase] = field(default_factory=list)


def resolve(spec: Any, flag: Optional[bool]) -> Settings:
    """The settings of a run: the config's ``variants`` block (the defaults
    when there is none, as for a test double), with ``enabled`` replaced by
    ``--variants`` (True) or ``--no-variants`` (False) when one is given."""
    s = Settings() if spec is None else Settings(
        enabled=spec.enabled, budget_runs=spec.budget_runs, seed=spec.seed,
        max_tests=spec.max_tests)
    if flag is not None:
        s.enabled = flag
    return s


# run_candidate(test) -> the record of one run of ``test`` on patch-sanitized.
RunCandidateFn = Callable[[TestCase], RunRecord]


# ---------------------------------------------------------------------------
# Hints from the diff
# ---------------------------------------------------------------------------


def hints_from_diff(diff_text: str) -> Hints:
    """Integers and character literals in the diff's added and removed lines."""
    sizes: set[int] = set()
    tokens: list[int] = []
    for line in diff_text.splitlines():
        if not line or line[0] not in "+-" or line.startswith(("+++", "---")):
            continue
        body = line[1:]
        for m in _INT_RE.finditer(body):
            n = int(m.group(1), 0) if m.group(1)[:2] in ("0x", "0X") else int(m.group(1))
            for k in (n - 1, n, n + 1):
                if MIN_SIZE <= k <= MAX_SIZE:
                    sizes.add(k)
        for m in _CHAR_RE.finditer(body):
            b = _char_value(m.group(1))
            if b is not None and b not in tokens:
                tokens.append(b)
    return Hints(sizes=sorted(sizes), tokens=bytes(tokens))


def _char_value(lit: str) -> Optional[int]:
    """The byte of a C character literal's body: ``a``, ``\\n``, ``\\x2f``, ``\\057``."""
    if not lit.startswith("\\"):
        return ord(lit) if ord(lit) < 256 else None
    rest = lit[1:]
    if rest[:1] in ("x", "X"):
        return int(rest[1:], 16) & 0xFF
    if rest[:1].isdigit() and rest[:1] in "01234567" and len(rest) > 1:
        return int(rest, 8) & 0xFF
    return _ESCAPES.get(rest)


# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------


def candidates(data: bytes, seed: int, test_name: str, hints: Hints) -> Iterator[bytes]:
    """An endless, deterministic stream of mutations of ``data``.

    First the structured ones: the input with its last 1 … 8 bytes cut, and
    the longest run of one byte resized to each interesting length. Then
    random ones: one to three random mutations stacked. The caller stops
    when its budget is used, and drops duplicates.
    """
    rng = random.Random(f"{seed}:{test_name}")  # str seeds are stable across runs
    pool = bytes(dict.fromkeys(hints.tokens + SPECIAL_BYTES))  # ordered, no duplicates

    for k in range(1, min(_TAIL_CUTS, len(data) - 1) + 1):
        yield data[:-k]
    run = _longest_run(data)
    if run is not None:
        start, length = run
        for n in hints.sizes:
            if n != length:
                yield data[:start] + data[start:start + 1] * n + data[start + length:]

    ops = (_flip, _insert, _delete, _duplicate, _cut, _resize)
    while True:
        out = data
        for _ in range(rng.randint(1, 3)):
            out = rng.choice(ops)(out, rng, pool, hints)
        if len(out) > MAX_CANDIDATE_BYTES:
            out = out[:MAX_CANDIDATE_BYTES]
        yield out


def _longest_run(data: bytes) -> Optional[tuple[int, int]]:
    """``(start, length)`` of the longest run of one byte, if it is at least 2."""
    best: Optional[tuple[int, int]] = None
    i = 0
    while i < len(data):
        j = i
        while j < len(data) and data[j] == data[i]:
            j += 1
        if j - i >= 2 and (best is None or j - i > best[1]):
            best = (i, j - i)
        i = j
    return best


def _flip(d: bytes, rng: random.Random, pool: bytes, hints: Hints) -> bytes:
    if not d:
        return bytes([rng.choice(pool)])
    i = rng.randrange(len(d))
    b = rng.choice(pool) if rng.random() < 0.5 else d[i] ^ (1 << rng.randrange(8))
    return d[:i] + bytes([b]) + d[i + 1:]


def _insert(d: bytes, rng: random.Random, pool: bytes, hints: Hints) -> bytes:
    i = rng.randint(0, len(d))
    return d[:i] + bytes([rng.choice(pool)]) + d[i:]


def _delete(d: bytes, rng: random.Random, pool: bytes, hints: Hints) -> bytes:
    if len(d) < 2:
        return d
    i = rng.randrange(len(d))
    n = rng.randint(1, max(1, min(8, len(d) - i)))
    return d[:i] + d[i + n:]


def _duplicate(d: bytes, rng: random.Random, pool: bytes, hints: Hints) -> bytes:
    if not d:
        return d
    i = rng.randrange(len(d))
    j = rng.randint(i + 1, min(len(d), i + 64))
    return d[:j] + d[i:j] + d[j:]


def _cut(d: bytes, rng: random.Random, pool: bytes, hints: Hints) -> bytes:
    return d[:rng.randint(1, len(d) - 1)] if len(d) >= 2 else d


def _resize(d: bytes, rng: random.Random, pool: bytes, hints: Hints) -> bytes:
    run = _longest_run(d)
    if run is None or not hints.sizes:
        return _duplicate(d, rng, pool, hints)
    start, length = run
    n = rng.choice(hints.sizes)
    return d[:start] + d[start:start + 1] * n + d[start + length:]


# ---------------------------------------------------------------------------
# Screening
# ---------------------------------------------------------------------------


def bug_of(rec: RunRecord) -> Optional[str]:
    """What a screening run found: its bug key (the same-bug rule's error
    type, function and file), or its error type when the trace has no
    function names; None when it did not crash."""
    a = rec.analysis
    if a.outcome is not Outcome.CRASH:
        return None
    key = findings.bug_key(a)
    if key is not None:
        return str(key)
    return f"{a.error_type.value if a.error_type else 'UNKNOWN'} (no stack trace)"


def screen(settings: Settings, security_tests: list[TestCase], hints: Hints,
           input_method: InputMethod, known_on_patch: set[str], seen_inputs: set[bytes],
           run_candidate: RunCandidateFn) -> Screened:
    """Run the candidates on patch-sanitized and keep the new crashes.

    ``known_on_patch`` holds what the normal tests already show on
    patch-sanitized (as :func:`bug_of` gives it), so only new bugs are kept.
    ``seen_inputs`` holds the inputs of every test of the run, so no
    candidate repeats an existing test. The budget is shared equally by the
    security tests that have an input, in config order.
    """
    out = Screened()
    sources = [t for t in security_tests if t.input_bytes]
    out.skipped = [t.name for t in security_tests if not t.input_bytes]
    if not sources:
        return out
    share, extra = divmod(settings.budget_runs, len(sources))
    seen = set(seen_inputs)
    found = set(known_on_patch)

    for i, src in enumerate(sources):
        quota = share + (1 if i < extra else 0)
        used = 0
        stream = candidates(src.input_bytes, settings.seed, src.name, hints)
        # Duplicates are skipped without a run; stop if the stream only repeats.
        misses = 0
        while used < quota and misses < 50 * quota + 100:
            data = next(stream)
            if data in seen or (input_method is InputMethod.ARGS and b"\0" in data):
                misses += 1
                continue
            seen.add(data)
            cand = variant_test(src, data)
            bug = bug_of(run_candidate(cand))
            used += 1
            if bug is None or bug in found or len(out.kept) >= settings.max_tests:
                continue
            # Confirm with a second run, so a crash seen only by chance is
            # not kept (it would only become a flaky, INCONCLUSIVE test).
            again = bug_of(run_candidate(cand))
            used += 1
            if again == bug:
                found.add(bug)
                out.kept.append(cand)
            else:
                out.unconfirmed += 1
        out.per_test[src.name] = used
        out.runs += used
    return out


def variant_test(source: TestCase, data: bytes) -> TestCase:
    """The test of one candidate: the source test's arguments with the new
    input, and no oracle (the expected output of a mutated input is not
    known). The name holds the input's hash, so it is stable and unique."""
    digest = hashlib.sha256(data).hexdigest()[:8]
    return TestCase(
        name=f"var-{source.name}-{digest}",
        kind=TestKind.VARIANT,
        input_bytes=data,
        input_ext=source.input_ext,
        args=list(source.args),
        description=f"variant of {source.name} ({len(data)} bytes, sha256 {digest}…)",
    )


def write_inputs(tests: list[TestCase], out_dir: Path) -> None:
    """Save each kept variant's input as ``variants/<name><ext>`` and point
    the test's ``source_path`` at it, so the report shows where it is."""
    folder = out_dir / "variants"
    for t in tests:
        folder.mkdir(exist_ok=True)
        rel = f"variants/{t.name}{t.input_ext}"
        (out_dir / rel).write_bytes(t.input_bytes or b"")
        t.source_path = rel


def patch_sanitized_bugs(results: dict, tests: list[TestCase]) -> set[str]:
    """What the normal tests show on patch-sanitized, as :func:`bug_of` gives
    it, from every repeat."""
    bugs: set[str] = set()
    for t in tests:
        r = results.get(t.name, {}).get(BuildName.PATCH_SANITIZED)
        if r is None:
            continue
        for run in r.runs:
            b = bug_of(run)
            if b is not None:
                bugs.add(b)
    return bugs
