"""Reproducer bundles: minimize a crashing input, replay it, and write a
self-contained bundle.

For each crash finding that gets a bundle, this takes the input of the
finding's **source test**, shrinks it with delta debugging (``ddmin``) while
the *same* crash still happens, replays it three times, and writes
``reproducers/<finding id>/``:

==================  ============================================================
``input.orig.<ext>``  the source test's input, byte for byte
``input.min.<ext>``   the minimized input (only when minimization ran)
``bin/<binary>``      a copy of the binary, so the bundle is self-contained
``metadata.json``     everything needed to reproduce the error
``replays.json``      the replay results
``minimize.log``      each minimization step: candidate size, accepted or not
``reproduce.sh``      replays the error from any location
==================  ============================================================

The program is run through an injected ``run`` callable that returns a
:class:`RunOutcome`. That keeps this module independent of the runner:
the pipeline runs the input with the same command, environment and
limits as the source test and adapts the :class:`RunRecord` with
:meth:`RunOutcome.from_record`; the tests pass a fake ``run``.

"Same crash" means the same signature as the source test's crash (error type
and top three functions). A crash without a signature cannot be
minimized; it is replayed as is, and a replay counts as reproduced when it
crashes with the same error type and detection.
"""

from __future__ import annotations

import hashlib
import json
import shlex
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from .models import (
    SCHEMA_VERSION,
    BuildName,
    BuildRecord,
    Bundle,
    Category,
    Detection,
    EnvironmentInfo,
    ErrorType,
    Finding,
    InputMethod,
    Issue,
    Outcome,
    Replay,
    RunRecord,
    WarningCode,
)

MAX_RUNS = 500       # minimization stops after 500 candidate runs ...
MAX_SECONDS = 120.0  # ... or 120 seconds
REPLAYS = 3          # a bundle is stable when all replays reproduce the crash

# Which build a bundle is made on. Other categories get no bundle.
_BUNDLE_BUILD: dict[Category, BuildName] = {
    Category.FIXED: BuildName.BASE_SANITIZED,
    Category.INCOMPLETE_FIX: BuildName.PATCH_SANITIZED,
    Category.NEW_ISSUE: BuildName.PATCH_SANITIZED,
}

# What reproduce.sh looks for in standard error, per error type.
# Extended regular expressions for ``grep -E``.
ERROR_PATTERNS: dict[ErrorType, str] = {
    ErrorType.STACK_BUFFER_OVERFLOW:
        r"(dynamic-)?stack-buffer-overflow|\*\*\* stack smashing detected \*\*\*",
    ErrorType.HEAP_BUFFER_OVERFLOW: r"heap-buffer-overflow",
    ErrorType.GLOBAL_BUFFER_OVERFLOW: r"global-buffer-overflow",
    ErrorType.BUFFER_OVERFLOW: r"\*\*\* buffer overflow detected \*\*\*",
    ErrorType.USE_AFTER_FREE: r"heap-use-after-free",
    ErrorType.USE_AFTER_SCOPE: r"stack-use-after-(scope|return)",
    ErrorType.DOUBLE_FREE: r"attempting double-free|double free detected",
    ErrorType.INVALID_FREE:
        r"attempting free on address which was not malloc|free\(\): invalid pointer",
    ErrorType.NULL_DEREF: r"AddressSanitizer: SEGV|null pointer",
    ErrorType.SEGV: r"AddressSanitizer: SEGV",
    ErrorType.STACK_EXHAUSTION: r"AddressSanitizer: stack-overflow",
    ErrorType.DIV_BY_ZERO: r"division by zero",
    ErrorType.INTEGER_OVERFLOW: r"signed integer overflow",
    ErrorType.OUT_OF_BOUNDS_INDEX: r"index .* out of bounds",
    ErrorType.UB_OTHER: r"runtime error:",
    ErrorType.HEAP_CORRUPTION: r"malloc\(\)|free\(\)|corrupted",
}

_SIGNALS = {"SIGHUP": 1, "SIGINT": 2, "SIGQUIT": 3, "SIGILL": 4, "SIGTRAP": 5,
            "SIGABRT": 6, "SIGBUS": 7, "SIGFPE": 8, "SIGKILL": 9, "SIGSEGV": 11,
            "SIGPIPE": 13, "SIGALRM": 14, "SIGTERM": 15, "SIGXCPU": 24}


@dataclass
class RunOutcome:
    """One execution's result, as the reproducer needs it (a slim view of
    the runner's :class:`RunRecord`)."""

    crashed: bool
    signature: Optional[str]
    signal: Optional[str] = None
    exit_code: Optional[int] = None
    error_type: Optional[ErrorType] = None
    detection: Optional[Detection] = None
    top_functions: list[str] = field(default_factory=list)
    duration_s: float = 0.0

    @classmethod
    def from_record(cls, rec: RunRecord) -> "RunOutcome":
        a = rec.analysis
        return cls(
            crashed=a.is_crash,
            signature=a.signature,
            signal=rec.signal,
            exit_code=rec.exit_code,
            error_type=a.error_type,
            detection=a.detection,
            top_functions=[f.function for f in a.app_frames if f.function][:3],
            duration_s=rec.duration_s,
        )


RunFn = Callable[[bytes], RunOutcome]


# ---------------------------------------------------------------------------
# Which findings get a bundle, from which test
# ---------------------------------------------------------------------------


def bundle_build(category: Category) -> Optional[BuildName]:
    """The build a finding's bundle is made on, or ``None`` for no bundle."""
    return _BUNDLE_BUILD.get(category)


def source_test(finding: Finding) -> Optional[str]:
    """The first test of the finding, in config order, that crashes on the
    bundle's build. ``finding.tests`` is in config order."""
    build = bundle_build(finding.category)
    if build is None:
        return None
    for t in finding.tests:
        summary = t.results.get(build)
        if summary is not None and summary.outcome is Outcome.CRASH:
            return t.test
    return None


# ---------------------------------------------------------------------------
# The bundle
# ---------------------------------------------------------------------------


def reproduce(
    *,
    finding: Finding,
    source: RunRecord,
    input_bytes: bytes,
    input_ext: str,
    build: BuildRecord,
    run_dir: str | Path,
    run: RunFn,
    versions: dict[str, Any],
    environment: Optional[EnvironmentInfo] = None,
    max_runs: int = MAX_RUNS,
    max_seconds: float = MAX_SECONDS,
    replays: int = REPLAYS,
) -> tuple[Bundle, list[Issue]]:
    """Minimize, replay and write the bundle of one finding.

    ``source`` is the first repeat of the source test on the bundle's build;
    it gives the expected crash, the command, the environment and the input
    method. ``build`` is that build's record; its binary (a path relative to
    ``run_dir``) is copied into the bundle. ``versions`` is the report's
    ``versions`` dict (``base``/``patch`` :class:`VersionInfo`, ``diff``
    :class:`DiffInfo`).

    Returns the :class:`Bundle` and its warnings (``MINIMIZE_LIMIT``). An
    unstable bundle is kept; :func:`apply_bundle` then makes the finding
    ``INCONCLUSIVE``.
    """
    run_dir = Path(run_dir)
    rel_path = f"reproducers/{finding.id}"
    bundle_dir = run_dir / rel_path
    bundle_dir.mkdir(parents=True, exist_ok=True)
    warnings: list[Issue] = []

    a = source.analysis
    expected = _Expected(signature=a.signature, error_type=a.error_type, detection=a.detection)

    # The binary, so the bundle is self-contained.
    if build.binary is None:
        raise ValueError(f"{build.build.value} has no binary to put in the bundle")
    src_bin = Path(build.binary.path)
    if not src_bin.is_absolute():
        src_bin = run_dir / src_bin
    bin_name = src_bin.name
    (bundle_dir / "bin").mkdir(exist_ok=True)
    shutil.copy2(src_bin, bundle_dir / "bin" / bin_name)

    (bundle_dir / f"input.orig{input_ext}").write_bytes(input_bytes)

    # Minimization: only when the crash has a signature.
    steps: list[tuple[int, Optional[bool]]] = [(len(input_bytes), None)]
    minimized: Optional[bytes] = None
    minimize_runs = 0
    limit_hit = False
    if expected.signature is not None:
        minimized, minimize_runs, limit_hit = ddmin(
            input_bytes, lambda c: expected.matches(run(c)),
            max_runs=max_runs, max_seconds=max_seconds, log=steps)
        (bundle_dir / f"input.min{input_ext}").write_bytes(minimized)
        if limit_hit:
            warnings.append(Issue(
                WarningCode.MINIMIZE_LIMIT.value,
                f"{finding.id}: minimization stopped at its budget "
                f"({max_runs} runs or {max_seconds:g} s); the smallest input found is used",
                {"finding": finding.id, "runs": minimize_runs, "path": rel_path}))
    _write_minimize_log(bundle_dir / "minimize.log", steps, minimized is not None)

    # Replays: the minimized input first, the original as fallback.
    attempts: list[dict[str, Any]] = []
    min_unstable = False
    if minimized is not None:
        min_replays = _replay(run, minimized, expected, replays)
        attempts.append(_attempt("min", min_replays))
        chosen, chosen_replays = "min", min_replays
        if not _stable(min_replays):
            min_unstable = True
            chosen = "orig"
            chosen_replays = _replay(run, input_bytes, expected, replays)
            attempts.append(_attempt("orig", chosen_replays))
    else:
        chosen = "orig"
        chosen_replays = _replay(run, input_bytes, expected, replays)
        attempts.append(_attempt("orig", chosen_replays))
    stable = _stable(chosen_replays)

    bundle = Bundle(
        finding=finding.id, source_test=source.test, build=source.build, path=rel_path,
        original_size=len(input_bytes),
        minimized_size=len(minimized) if minimized is not None else None,
        minimize_runs=minimize_runs, minimize_limit_hit=limit_hit,
        replayed_input=chosen, replays=chosen_replays, stable=stable,
    )

    _write_json(bundle_dir / "replays.json", {
        "schema_version": SCHEMA_VERSION,
        "input": chosen,
        "stable": stable,
        "minimized_input_unstable": min_unstable,
        "replays": [_replay_json(r) for r in chosen_replays],
        "attempts": attempts,
    })

    binary_sha = _sha256_file(bundle_dir / "bin" / bin_name)
    metadata = _metadata(finding, source, build, versions, environment, expected,
                         bundle, bin_name, binary_sha, input_ext, min_unstable)
    _write_json(bundle_dir / "metadata.json", metadata)
    _write_reproduce_sh(bundle_dir / "reproduce.sh", source, bin_name, input_ext,
                        expected, chosen)
    return bundle, warnings


def apply_bundle(finding: Finding, bundle: Bundle) -> None:
    """Record the bundle on its finding. An unstable bundle makes the finding
    ``INCONCLUSIVE`` and is kept, marked unstable."""
    finding.reproducer = bundle.path + "/"
    if not bundle.stable:
        ok = sum(r.reproduced for r in bundle.replays)
        note = (f"The reproducer did not replay stably ({ok}/{len(bundle.replays)} replays "
                f"reproduced the error); the bundle is kept, marked unstable.")
        finding.notes = f"{finding.notes} {note}".strip() if finding.notes else note
        finding.category = Category.INCONCLUSIVE


# ---------------------------------------------------------------------------
# Delta debugging
# ---------------------------------------------------------------------------


def ddmin(
    data: bytes,
    interesting: Callable[[bytes], bool],
    max_runs: int = MAX_RUNS,
    max_seconds: float = MAX_SECONDS,
    log: Optional[list[tuple[int, Optional[bool]]]] = None,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[bytes, int, bool]:
    """Shrink ``data`` while ``interesting`` holds (complement-based ddmin).

    Returns the smallest accepted input, the number of ``interesting`` calls,
    and whether the budget (``max_runs`` calls or ``max_seconds``) ran out
    first. Without hitting the budget the result is 1-minimal: removing any
    single byte makes it rejected. ``log`` receives ``(size, accepted)`` for
    every candidate tried.
    """
    start = clock()
    best = data
    n = 2
    calls = 0
    while len(best) >= 2:
        n = min(n, len(best))
        chunk = len(best) // n
        reduced = False
        for i in range(n):
            lo = i * chunk
            hi = lo + chunk if i < n - 1 else len(best)
            comp = best[:lo] + best[hi:]
            if not comp:
                continue
            if calls >= max_runs or clock() - start > max_seconds:
                return best, calls, True
            calls += 1
            ok = interesting(comp)
            if log is not None:
                log.append((len(comp), ok))
            if ok:
                best = comp
                n = max(n - 1, 2)
                reduced = True
                break
        if not reduced:
            if n >= len(best):
                break
            n = min(len(best), n * 2)
    return best, calls, False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class _Expected:
    signature: Optional[str]
    error_type: Optional[ErrorType]
    detection: Optional[Detection]

    def matches(self, o: RunOutcome) -> bool:
        """Same error: a crash with the same signature. A non-zero exit code or
        a different error is not enough. Without a signature, the same
        error type and detection."""
        if not o.crashed:
            return False
        if self.signature is not None:
            return o.signature == self.signature
        return o.error_type == self.error_type and o.detection == self.detection


def _replay(run: RunFn, data: bytes, expected: _Expected, n: int) -> list[Replay]:
    out = []
    for i in range(1, n + 1):
        o = run(data)
        out.append(Replay(i, reproduced=expected.matches(o), signal=o.signal,
                          exit_code=o.exit_code, error_type=o.error_type,
                          top_functions=list(o.top_functions), duration_s=o.duration_s))
    return out


def _stable(replays: list[Replay]) -> bool:
    return bool(replays) and all(r.reproduced for r in replays)


def _replay_json(r: Replay) -> dict[str, Any]:
    return {"n": r.n, "reproduced": r.reproduced, "signal": r.signal, "exit_code": r.exit_code,
            "error_type": r.error_type.value if r.error_type else None,
            "top_functions": r.top_functions, "duration_s": round(r.duration_s, 4)}


def _attempt(which: str, replays: list[Replay]) -> dict[str, Any]:
    return {"input": which, "stable": _stable(replays),
            "replays": [_replay_json(r) for r in replays]}


def _write_minimize_log(path: Path, steps: list[tuple[int, Optional[bool]]], ran: bool) -> None:
    lines = ["step  size  accepted"]
    lines.append(f"1     {steps[0][0]:<5} -        (original)")
    for i, (size, ok) in enumerate(steps[1:], start=2):
        lines.append(f"{i:<5} {size:<5} {'yes' if ok else 'no'}")
    if not ran:
        lines.append("minimization skipped: the crash has no signature")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _metadata(finding: Finding, source: RunRecord, build: BuildRecord, versions: dict[str, Any],
              environment: Optional[EnvironmentInfo], expected: _Expected, bundle: Bundle,
              bin_name: str, binary_sha: str, input_ext: str,
              min_unstable: bool) -> dict[str, Any]:
    version = source.build.version.value
    vinfo = versions.get(version)
    diff = versions.get("diff")
    compilers = {}
    if environment is not None:
        compilers = {"gcc": environment.gcc, "clang": environment.clang}
    return {
        "schema_version": SCHEMA_VERSION,
        "finding": finding.id,
        "category": finding.category.value,
        "source_test": source.test,
        "version": version,
        "build": source.build.value,
        "git_commit": getattr(vinfo, "git_commit", None),
        "tree_sha256": getattr(vinfo, "tree_sha256", None),
        "diff_sha256": getattr(diff, "sha256", None),
        "binary": f"bin/{bin_name}",
        "binary_sha256": binary_sha,
        "build_settings": {"cmd": build.cmd, "env": build.env, "compilers": compilers},
        "run_env": source.env,
        "cmd": source.cmd,
        "bundle_cmd": _bundle_cmd(source, bin_name),
        "input_method": source.input.method.value,
        "input_name": source.input.name,
        "input_files": {"orig": f"input.orig{input_ext}",
                        "min": f"input.min{input_ext}" if bundle.minimized_size is not None
                        else None},
        "expected": {
            "signature": expected.signature,
            "error_type": expected.error_type.value if expected.error_type else None,
            "detection": expected.detection.value if expected.detection else None,
        },
        "sizes": {"original": bundle.original_size, "minimized": bundle.minimized_size,
                  "minimize_runs": bundle.minimize_runs},
        "minimize_limit_hit": bundle.minimize_limit_hit,
        "replayed_input": bundle.replayed_input,
        "minimized_input_unstable": min_unstable,
        "stable": bundle.stable,
    }


def _bundle_cmd(source: RunRecord, bin_name: str) -> list[str]:
    """The run's command with the binary replaced by the bundle's copy and the
    run directory removed from the input path (the input is always
    ``input<ext>`` in the working directory)."""
    args = list(source.cmd[1:])
    if source.input.method is InputMethod.ARGS and args:
        args[-1] = "{input}"  # the input itself; filled in by reproduce.sh
    elif source.input.method is InputMethod.FILE and source.input.name:
        prefix = source.cwd.rstrip("/") + "/" if source.cwd else None
        args = [a.replace(prefix, "") if prefix else a for a in args]
    return [f"bin/{bin_name}", *args]


def _write_reproduce_sh(path: Path, source: RunRecord, bin_name: str, input_ext: str,
                        expected: _Expected, default_input: str) -> None:
    """Generate ``reproduce.sh``. It needs only bash, sha256sum, grep
    and the sanitizer runtime, and works from any location."""
    q = shlex.quote
    method = source.input.method
    name = source.input.name or f"input{input_ext}"

    argv = []
    for a in _bundle_cmd(source, bin_name)[1:]:
        argv.append('"$INPUT_ARG"' if (method is InputMethod.ARGS and a == "{input}") else q(a))
    run_line = " ".join([
        "env -i", *(q(f"{k}={v}") for k, v in source.env.items()),
        f'"$HERE/bin/{bin_name}"', *argv])
    if method is InputMethod.STDIN:
        run_line += ' < "$TMP/input"'
    else:
        run_line += " < /dev/null"

    pattern = ""
    want_signal = ""
    if expected.detection is Detection.SIGNAL or expected.error_type is None:
        want_signal = str(_SIGNALS.get(source.signal or "", "")) if source.signal else ""
    else:
        pattern = ERROR_PATTERNS.get(expected.error_type, "")
    functions = []
    if expected.signature and " @ " in expected.signature:
        functions = [f.strip() for f in expected.signature.split(" @ ", 1)[1].split(" < ")]

    script = f"""#!/usr/bin/env bash
# Replays {source.test} of this finding on {source.build.value}.
#   ./reproduce.sh        replays the {default_input} input
#   ./reproduce.sh orig   replays the original input
#   ./reproduce.sh min    replays the minimized input
# Exit codes: 0 reproduced, 1 not reproduced, 2 binary hash mismatch or bad usage.
set -u
HERE="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"

WANT_SHA="$(grep -o '"binary_sha256": *"[0-9a-f]*"' "$HERE/metadata.json" | grep -o '[0-9a-f]\\{{64\\}}')"
GOT_SHA="$(sha256sum "$HERE/bin/{bin_name}" | cut -d' ' -f1)"
if [ -z "$WANT_SHA" ] || [ "$WANT_SHA" != "$GOT_SHA" ]; then
  echo "binary hash mismatch: bin/{bin_name} is not the binary in metadata.json" >&2
  exit 2
fi

WHICH="${{1:-{default_input}}}"
case "$WHICH" in orig|min) ;; *) echo "usage: $0 [orig|min]" >&2; exit 2 ;; esac
SRC="$HERE/input.$WHICH{input_ext}"
[ -f "$SRC" ] || {{ echo "no input.$WHICH{input_ext} in this bundle" >&2; exit 2; }}

# An empty working directory that holds only the input file, under the same
# name as during the run (input method "file"); otherwise it stays empty.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/run"
cp "$SRC" "$TMP/input"
{f'cp "$SRC" "$TMP/run/"{q(name)}' if method is InputMethod.FILE else ': # input method ' + method.value + ': nothing in the working directory'}
IFS= read -r -d '' INPUT_ARG < "$TMP/input" || true
cd "$TMP/run"
ulimit -c 0
{run_line} > "$TMP/stdout" 2> "$TMP/stderr"
STATUS=$?
cat "$TMP/stdout"
cat "$TMP/stderr" >&2

OK=1
PATTERN={q(pattern)}
WANT_SIGNAL={q(want_signal)}
FUNCS=({" ".join(q(f) for f in functions)})
if [ -n "$PATTERN" ] && ! grep -Eq -- "$PATTERN" "$TMP/stderr"; then OK=0; fi
if [ -n "$WANT_SIGNAL" ] && [ "$STATUS" -ne $((128 + WANT_SIGNAL)) ]; then OK=0; fi
if [ -z "$PATTERN" ] && [ -z "$WANT_SIGNAL" ] && [ "$STATUS" -lt 128 ]; then OK=0; fi
for FN in ${{FUNCS[@]+"${{FUNCS[@]}}"}}; do
  grep -qF -- "$FN" "$TMP/stderr" || OK=0
done

if [ "$OK" = 1 ]; then
  echo "REPRODUCED: {expected.signature or (expected.error_type.value if expected.error_type else 'crash')}"
  exit 0
fi
echo "NOT REPRODUCED (exit status $STATUS)"
exit 1
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
