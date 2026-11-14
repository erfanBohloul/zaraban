# cJSON target: versions, tests and oracle

## The program

[cJSON](https://github.com/DaveGamble/cJSON), a widely used JSON library in C,
at tag `v1.7.10` (commit `c69134d`). The library is unchanged in `src/cJSON.c`
and `src/cJSON.h`; its MIT license is in `src/LICENSE`.

cJSON is a library, so `src/main.c` (`cjson_driver`) is a small front end that
runs it on a file. Its contract is part of the oracle:

| Command | Behavior |
|---|---|
| `cjson_driver minify FILE` | Runs `cJSON_Minify` on the file's bytes in place, prints the result and a newline, exits `0`. |
| `cjson_driver parse FILE` | Parses with `cJSON_Parse` and prints `cJSON_Print` of the tree, with nothing appended, exits `0`. If the file is not valid JSON: `parse error` on stderr, exit `1`. |
| wrong usage, unreadable file | A message on stderr, exit `2`. |

The file is read into a heap buffer of exactly its size plus the terminating
NUL, as any caller passes a C string to `cJSON_Minify`.

## The vulnerability

`v1.7.10` has two out-of-bounds reads in `cJSON_Minify`, both CWE-125, both
fixed by the same upstream rewrite:

| CVE | Upstream issue | Input | What happens on base (sanitized) |
|---|---|---|---|
| CVE-2019-11835 | [#338](https://github.com/DaveGamble/cJSON/issues/338) | an unterminated `/*` comment | The comment loop stops at the NUL, then `json += 2` steps past it, and the main loop reads past the buffer: `heap-buffer-overflow` READ at `cJSON.c:2642`. |
| CVE-2019-11834 | [#337](https://github.com/DaveGamble/cJSON/issues/337) | a string that ends in a backslash | The escape is copied together with the NUL, then the closing-quote copy steps past it: `heap-buffer-overflow` READ at `cJSON.c:2682`. |

How to reproduce both by hand: see [Reproducing by hand](#reproducing-by-hand).

## The four versions

Each patched version is a complete tree in `versions/patch_*/` and the same
change as a diff in `patches/*.patch` (made with
`git diff --no-index --no-prefix a b`, applied with `-p1`). Only
`src/cJSON.c` differs from base.

| Version | What it is | Expected run |
|---|---|---|
| Base (`src/`) | Upstream `v1.7.10`. Both CVEs reproduce under ASan. | |
| Correct | The upstream fix: `a43fa56` ("Rewrite cJSON_Minify, fixing buffer overflows", 1.7.11) for both CVEs, `6b24921` (warning fix in the new code, 1.7.11) and `08d2bc7` ("Fix infinite loop in cJSON_Minify", 1.7.12), which fixes a hang the rewrite introduced on a `/` that starts no comment. `cJSON.c` changes only; the upstream test files are not part of the target. | exit `0` |
| Incomplete | Fixes CVE-2019-11834 fully. For CVE-2019-11835 it only handles the reported input, a `/*` at the very end of the input. An unterminated comment with any text after `/*` (`exploit_comment_bypass`) still reads past the buffer, at the same place as on base. | exit `10` |
| Regression | Fixes both CVEs, but stops a string at a `/*` inside it, as if a comment started there. Both overflows are gone, but every string that contains `/*` is cut, which breaks valid JSON such as `{"pattern":"/*"}`. | exit `20` |

## Sources of expected behavior

Every expected output is taken from one of these, never from running a
patched version (spec §2). `make_tests.py` writes the test inputs and
`zaraban.yaml` straight from an upstream clone, so this can be checked: run
it and `git diff` stays empty.

| Source | Used for |
|---|---|
| **M**: upstream `tests/minify_tests.c` at `v1.7.12`, the unit tests of the fixed `cJSON_Minify` | minify outputs, and the outputs of the fixed version on the exploit inputs |
| **P**: upstream `tests/parse_examples.c`, `tests/inputs/test*` and `test*.expected` at `v1.7.10` | parse outputs, byte for byte |
| **N**: upstream `tests/parse_array.c`, `parse_object.c`, `parse_string.c` at `v1.7.10` | inputs cJSON must not parse |
| **H**: `cJSON.h`: the `CJSON_NESTING_LIMIT` comment (1000) and, in current upstream, the `cJSON_Minify` comment (removes blank characters) | nesting limit; minify rules for boundary inputs |
| **R**: RFC 8259 §7 | `/` and `*` are ordinary characters inside a JSON string |
| **D**: the driver contract above | exit codes, the newline after minify output |

## Tests

Inputs are in `tests/<kind>/<name>.json`; the exact expected output of each
test is in `zaraban.yaml`.

### Valid (17)

| Test | Expected behavior | Source |
|---|---|---|
| `minify_spaces` | prints `{"key":true}` | M `should_remove_spaces`, D |
| `minify_line_comment` | prints `{}` | M `should_remove_single_line_comments`, D |
| `minify_multiline_comment` | prints `{}` | M `should_remove_multiline_comments`, D |
| `minify_keeps_strings` | prints the string unchanged | M `should_not_modify_strings`, D |
| `minify_glossary` | prints the minified glossary | M `should_minify_json`, D |
| `minify_comment_marks_in_string` | prints `{"pattern":"/*"}` unchanged | R, M `should_not_modify_strings`, D |
| `minify_glob_in_string` | prints `{"include":"src/*.c","exclude":"*/tmp"}` unchanged | R, M `should_not_modify_strings`, D |
| `parse_test1` … `parse_test5`, `parse_test7` … `parse_test11` | prints exactly `tests/inputs/testN.expected` | P |

### Boundary (10)

The input ends right after each construct the patches change, plus the
nesting limit.

| Test | Expected behavior | Source |
|---|---|---|
| `minify_empty` | prints an empty line | H, D |
| `minify_only_whitespace` | prints an empty line | H, D |
| `minify_comment_closed_at_end` | `{}/* c */` → `{}` | M, D |
| `minify_empty_comment` | `/**/` → empty line | M, D |
| `minify_line_comment_at_end` | `{}// c` (no newline) → `{}` | M, D |
| `minify_comment_then_string` | `/* x */"a"` → `"a"` | M, D |
| `minify_string_at_end` | `"abc"` unchanged | M, D |
| `minify_escaped_quote_at_end` | `"a\""` unchanged | M, D |
| `minify_escaped_backslash_at_end` | `"a\\"` unchanged | M, D |
| `parse_nesting_at_limit` | 1000 nested arrays are accepted, exit `0` | H |

### Invalid (10)

The program must reject these without crashing.

| Test | Expected behavior | Source |
|---|---|---|
| `parse_empty`, `parse_open_bracket`, `parse_close_bracket`, `parse_open_brace` | exit `1` | N, D |
| `parse_incomplete_object` | `{ "name": ` → exit `1` | P (`test12`), D |
| `parse_unterminated_escape` | `"000000000000000000\` → exit `1` | N (`parse_string.c`), D |
| `parse_html` | an HTML page → exit `1` | P (`test6`), D |
| `parse_nesting_too_deep` | 1001 nested arrays → exit `1` | H, D |
| `minify_lone_slash` | `8 / 5` → no hang, no crash, exit `0`; output not specified | M `should_not_loop_infinitely` |
| `driver_unknown_mode` | unknown mode → exit `2` | D |

### Security (3)

On base each must crash (SPEC §5.5). The expected output is that of the
fixed version.

| Test | Input | On a fixed version | Source |
|---|---|---|---|
| `exploit_comment` | `/*` (CVE-2019-11835) | prints an empty line, exit `0` | M `should_not_overflow_buffer` |
| `exploit_string` | `"\` (CVE-2019-11834) | prints `"\` unchanged, exit `0` | M `should_not_overflow_buffer` |
| `exploit_comment_bypass` | `/* bla` (CVE-2019-11835, different input) | prints an empty line, exit `0` | M `should_not_overflow_buffer` (this exact input) |

## Expected results of the scenarios

What the tool must report for each version, derived from the design above
(`scenarios.yaml` holds the same in machine-readable form):

- **Correct**: all three exploits crash on base and none on patch, with the
  same signature (`HEAP_BUFFER_OVERFLOW @ cJSON_Minify < main`), so one
  `FIXED` finding; every other test matches its oracle on both. Exit `0`.
- **Incomplete**: `exploit_comment_bypass` still crashes on patch with the
  base signature, so one `INCOMPLETE_FIX` finding. Exit `10`.
- **Regression**: the two valid tests with `/*` inside a string match on base
  and fail on patch, so two `FUNCTIONAL_REGRESSION` findings, and the
  exploits give `FIXED`. Exit `20`.

## Reproducing by hand

Inside the container (`docker compose run --rm zaraban bash`), build the
sanitized base in a scratch copy and run an exploit:

```bash
cp -r targets/cjson /tmp/cjson && cd /tmp/cjson
make sanitized
./cjson_driver minify tests/exploits/exploit_comment.json   # CVE-2019-11835
./cjson_driver minify tests/exploits/exploit_string.json    # CVE-2019-11834
```

Each aborts with `AddressSanitizer: heap-buffer-overflow`, a 1-byte `READ` in
`cJSON_Minify`, at `src/cJSON.c:2642` (comment) and `src/cJSON.c:2682`
(string). The upstream fix `a43fa56` makes both inputs exit `0`.

The saved bundle of the incomplete scenario replays the remaining bug on the
patched binary, on its own (exit `0` means reproduced):

```bash
bash results/cjson/incomplete/reproducers/F-001/reproduce.sh       # minimized input
bash results/cjson/incomplete/reproducers/F-001/reproduce.sh orig  # original input
```

## With the variant step

The delivered scenarios run without `--variants`. With `--variants` the
verdicts stay the same (exits `0`, `10` and `20`). The step also works
without the hand-written bypass: with `exploit_comment_bypass` removed from
the config, it finds a 3-byte variant of `exploit_comment` that still
overflows in `cJSON_Minify` on the incomplete patch, so that scenario still
gives `INCOMPLETE_FIX` and exit `10`.
