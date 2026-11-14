"""Unit tests for the optional variant step (SPEC §7.6): hints from the diff,
seeded candidates, screening on patch-sanitized, the config and CLI switches,
the wiring in the build & execute stage, and the findings of a kept variant.

Nothing here compiles or runs a program: runs are fakes from results_fakes.
"""

import itertools
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from results_fakes import crash, normal, results, run_record
from zaraban import completeness, exec_stage, findings, report, runner, variants
from zaraban.cli import parse
from zaraban.config import Target
from zaraban.models import (BUILD_ORDER, BuildName, Category, CombinedResult, InputMethod,
                            OnPatch, TestCase, TestKind, ZarabanError)
from zaraban.pipeline_state import RunContext

PS = BuildName.PATCH_SANITIZED
OTHER = (("other_fn", "src/main.c", 90), ("main", "src/main.c", 99))

DIFF = textwrap.dedent("""\
    diff --git a/src/main.c b/src/main.c
    --- a/src/main.c
    +++ b/src/main.c
    @@ -1,4 +1,5 @@
     char buf[64];
    -    if (len > 100)
    +    if (len > 63 || c == '/' || c == '\\\\')
    +        return 0x10;
    """)


def security(name="exploit_primary", data=b"SET x=AAAAAAAAAAAA"):
    return TestCase(name, TestKind.SECURITY, data, args=["{input_file}"])


def settings(**kw):
    return variants.Settings(**{"enabled": True, "budget_runs": 20, "seed": 1, **kw})


def runner_from(table):
    """A fake run_candidate: ``table(data) -> spec``; records every call."""
    calls = []

    def run(test):
        calls.append(test.input_bytes)
        return run_record(test.name, test.kind, PS, table(test.input_bytes))
    run.calls = calls
    return run


def screen(run, tests=None, **kw):
    args = dict(settings=settings(), security_tests=tests or [security()],
                hints=variants.hints_from_diff(DIFF), input_method=InputMethod.FILE,
                known_on_patch=set(), seen_inputs=set(), run_candidate=run)
    args.update(kw)
    return variants.screen(**args)


# -- hints from the diff ----------------------------------------------------

def test_7_6_hints_take_integers_and_char_literals_from_changed_lines_only():
    h = variants.hints_from_diff(DIFF)
    # 100 (removed), 63 and 0x10 (added), each with n-1 and n+1; 64 is context.
    assert h.sizes == [15, 16, 17, 62, 63, 64, 99, 100, 101]
    assert h.tokens == b"/\\"


def test_7_6_char_literal_escapes():
    h = variants.hints_from_diff("+ x = '\\n' + '\\x2f' + '\\057' + '\\0' + 'a';\n")
    assert h.tokens == b"\n/\x00a"


# -- candidates --------------------------------------------------------------

def test_7_6_candidates_are_deterministic_for_a_seed_and_test():
    hints = variants.hints_from_diff(DIFF)
    take = lambda seed, name: list(itertools.islice(  # noqa: E731
        variants.candidates(b"SET x=AAAAAAAA", seed, name, hints), 60))
    assert take(1, "t") == take(1, "t")
    assert take(1, "t") != take(2, "t")
    assert take(1, "t") != take(1, "u")


def test_7_6_structured_candidates_come_first():
    hints = variants.Hints(sizes=[3, 9])
    data = b"ab" + b"Z" * 5 + b"cd"
    first = list(itertools.islice(variants.candidates(data, 1, "t", hints), 10))
    # the end cut by 1..8 bytes, then the longest run resized to each size
    assert first[:8] == [data[:-k] for k in range(1, 9)]
    assert first[8:10] == [b"abZZZcd", b"ab" + b"Z" * 9 + b"cd"]


# -- screening ---------------------------------------------------------------

def test_7_6_budget_is_the_number_of_screening_runs_shared_by_the_tests():
    run = runner_from(lambda d: normal())
    out = screen(run, tests=[security("exploit_a"), security("exploit_b", b"other input")],
                 settings=settings(budget_runs=11))
    assert out.runs == len(run.calls) == 11
    assert out.per_test == {"exploit_a": 6, "exploit_b": 5}
    assert out.kept == []


def test_7_6_a_new_crash_is_confirmed_once_and_kept_once_per_bug():
    run = runner_from(lambda d: crash(stack=OTHER) if len(d) < 18 else normal())
    out = screen(run, settings=settings(budget_runs=30))
    assert len(out.kept) == 1  # every short input gives the same bug: kept once
    kept = out.kept[0]
    assert kept.kind is TestKind.VARIANT and kept.name.startswith("var-exploit_primary-")
    assert kept.args == ["{input_file}"] and not kept.has_oracle
    assert run.calls[:2] == [kept.input_bytes, kept.input_bytes]  # run, then confirmed
    assert out.runs == 30


def test_7_6_a_crash_that_does_not_repeat_is_not_kept():
    seen = {}

    def flaky(d):
        seen[d] = seen.get(d, 0) + 1
        return crash(stack=OTHER) if seen[d] == 1 else normal()
    out = screen(runner_from(flaky), settings=settings(budget_runs=10))
    assert out.kept == [] and out.unconfirmed == 5


def test_7_6_bugs_the_normal_tests_already_show_on_patch_are_not_kept():
    known = variants.bug_of(run_record("x", TestKind.SECURITY, PS, crash(stack=OTHER)))
    out = screen(runner_from(lambda d: crash(stack=OTHER)), known_on_patch={known})
    assert out.kept == []


def test_7_6_max_tests_caps_the_kept_variants():
    def by_length(d):  # a different bug for every length
        return crash(stack=((f"fn{len(d)}", "src/main.c", 1),))
    out = screen(runner_from(by_length), settings=settings(budget_runs=40, max_tests=2))
    assert len(out.kept) == 2


def test_7_6_no_candidate_repeats_an_existing_test_input():
    data = b"SET x=AAAAAAAAAAAA"
    run = runner_from(lambda d: normal())
    screen(run, seen_inputs={data, data[:-1]})
    assert data not in run.calls and data[:-1] not in run.calls
    assert len(run.calls) == len(set(run.calls))


def test_7_6_args_inputs_never_contain_nul_and_tests_without_input_are_skipped():
    run = runner_from(lambda d: normal())
    out = screen(run, tests=[security(), TestCase("exploit_noinput", TestKind.SECURITY, None)],
                 input_method=InputMethod.ARGS)
    assert all(b"\0" not in d for d in run.calls)
    assert out.skipped == ["exploit_noinput"] and out.per_test == {"exploit_primary": 20}


# -- config and command line -------------------------------------------------

CONFIG = """\
name: t
input_method: file
build: {binary_path: p, release_cmd: make release, sanitized_cmd: make sanitized}
valid_tests: [{name: v, input_data: "x"}]
invalid_tests: [{name: i, input_data: "y"}]
security_tests: [{name: s, input_data: "z"}]
"""


def load(tmp_path, extra=""):
    p = tmp_path / "zaraban.yaml"
    p.write_text(CONFIG + extra)
    return Target.load(p)[0]


def test_7_6_off_by_default_with_documented_defaults(tmp_path):
    s = variants.resolve(load(tmp_path).spec.variants, None)
    assert s == variants.Settings(enabled=False, budget_runs=200, seed=1, max_tests=5)


def test_7_6_config_block_and_cli_flag(tmp_path):
    spec = load(tmp_path, "variants: {enabled: true, budget_runs: 50, seed: 7}\n").spec.variants
    assert variants.resolve(spec, None).enabled
    assert not variants.resolve(spec, False).enabled  # --no-variants wins
    assert variants.resolve(load(tmp_path).spec.variants, True).enabled  # --variants wins
    assert variants.resolve(spec, None).budget_runs == 50


def test_7_6_unknown_variant_key_is_a_config_error(tmp_path):
    with pytest.raises(ZarabanError) as e:
        load(tmp_path, "variants: {enabled: true, budget: 5}\n")
    assert "did you mean 'budget_runs'" in " ".join(e.value.details["problems"])


def test_7_6_cli_flags():
    assert parse(["-c", "x", "--patch", "p"]).variants is None
    assert parse(["-c", "x", "--patch", "p", "--variants"]).variants is True
    assert parse(["-c", "x", "--patch", "p", "--no-variants"]).variants is False
    with pytest.raises(SystemExit) as e:
        parse(["-c", "x", "--patch", "p", "--variants", "--no-variants"])
    assert e.value.code == 30


# -- the build & execute stage -----------------------------------------------

def stage_ctx(tmp_path, enabled):
    out = tmp_path / "run"
    (out / "work").mkdir(parents=True)
    diff = out / "work" / "patch.diff"
    diff.write_text(DIFF)
    base = security()
    target = SimpleNamespace(
        name="t", input_method=InputMethod.FILE,
        spec=SimpleNamespace(repeats=2, variants=variants.Settings(enabled=enabled)))
    builds = SimpleNamespace(records={
        b: SimpleNamespace(binary=SimpleNamespace(path=f"builds/{b.value}/bin/p"))
        for b in BUILD_ORDER})
    ctx = RunContext(args=SimpleNamespace(variants=None), target=target,
                     work_dir=out / "work", out_dir=out, run_id="r", started_at="x",
                     sources=SimpleNamespace(diff_path=diff), run_settings=runner.RunSettings(),
                     build_set=builds, settings={"variants": {"enabled": enabled}})
    ctx.tests = [base]
    ctx.results = results({"exploit_primary": {"base-sanitized": crash()}})
    return ctx


def fake_run_test(test, build, *_args, **_kw):
    spec = crash(stack=OTHER) if build.profile.value == "sanitized" else normal()
    return CombinedResult(test.name, test.kind, build,
                          [run_record(test.name, test.kind, build, spec)], flaky=False)


def test_7_6_off_runs_nothing(tmp_path):
    ctx = stage_ctx(tmp_path, enabled=False)
    calls = []
    exec_stage.run_variants(ctx, lambda *a, **k: calls.append(a),
                            run_candidate=lambda t: calls.append(t))
    assert calls == [] and [t.name for t in ctx.tests] == ["exploit_primary"]
    assert ctx.settings["variants"] == {"enabled": False}


def test_7_6_kept_variants_run_on_all_four_builds_and_are_recorded(tmp_path):
    ctx = stage_ctx(tmp_path, enabled=True)
    run_test = lambda binary, test, s, build, *a, **k: fake_run_test(test, build)  # noqa: E731
    exec_stage.run_variants(ctx, run_test, run_candidate=lambda t: run_record(
        t.name, t.kind, PS, crash(stack=OTHER)))

    assert len(ctx.tests) == 2 and ctx.tests[1].kind is TestKind.VARIANT
    name = ctx.tests[1].name
    assert set(ctx.results[name]) == set(BUILD_ORDER)
    v = ctx.settings["variants"]
    assert v["enabled"] and v["screening_runs"] == 200
    assert v["kept"] == [{"test": name, "input": f"variants/{name}"}]
    assert (ctx.out_dir / "variants" / name).read_bytes() == ctx.tests[1].input_bytes


# -- findings of a kept variant ----------------------------------------------

def test_7_6_variant_that_still_reaches_the_base_bug_makes_an_incomplete_fix():
    r = results({
        "exploit_primary": {"base-sanitized": crash(), "patch-sanitized": normal(0)},
        "var-exploit_primary-1a2b3c4d": {"base-sanitized": crash(), "patch-sanitized": crash()},
    }, kinds={"var-exploit_primary-1a2b3c4d": "variant"})
    (f,) = findings.build_findings(r)
    assert f.category is Category.INCOMPLETE_FIX
    on_patch = {t.test: t.on_patch for t in f.tests}
    assert on_patch == {"exploit_primary": OnPatch.BLOCKED,
                        "var-exploit_primary-1a2b3c4d": OnPatch.REACHES}
    completeness.check(r, [f])  # nothing lost


def test_7_6_variant_base_result_is_not_judged_like_a_security_test():
    r = results({"var-x-00000000": {"base-sanitized": normal(1), "patch-sanitized": normal(0)}},
                kinds={"var-x-00000000": "variant"})
    assert findings.build_findings(r) == []
    completeness.check(r, [])


# -- summary -----------------------------------------------------------------

def test_7_6_summary_line_only_when_on():
    assert report._variants_line({"enabled": False}) == ""
    line = report._variants_line({"enabled": True, "seed": 1, "screening_runs": 200,
                                  "skipped_tests": ["exploit_args"],
                                  "kept": [{"test": "var-a-1", "input": "variants/var-a-1"}]})
    assert "200 screening runs on patch-sanitized, kept 1: var-a-1" in line
    assert "exploit_args" in line
