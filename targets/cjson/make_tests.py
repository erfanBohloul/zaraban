"""Generate targets/cjson test inputs and zaraban.yaml from upstream cJSON sources.

Every expected output comes from an upstream file (tests/inputs/*.expected,
tests/minify_tests.c) or from a documented contract; nothing is produced by
running a patched version. Run from the repository root:
    git clone https://github.com/DaveGamble/cJSON.git /tmp/cjson
    python3 targets/cjson/make_tests.py /tmp/cjson
It rewrites tests/{valid,boundary,invalid,exploits}/ and zaraban.yaml; a
clean `git diff` afterwards shows they match upstream.
"""
import re
import subprocess
import sys
from pathlib import Path

import yaml

UP = Path(sys.argv[1])
T = Path("targets/cjson")


def upstream(rev: str, path: str) -> bytes:
    return subprocess.run(["git", "-C", str(UP), "show", f"{rev}:{path}"],
                          check=True, capture_output=True).stdout


def c_string(func: str, var: str, src: str) -> str:
    """The value of the C string `var` declared in `func` of minify_tests.c."""
    body = src[src.index(f"static void {func}("):]
    body = body[:body.index("\n}\n")]
    m = re.search(rf"{re.escape(var)}\[?\]?\s*=\s*((?:\s*\"(?:[^\"\\]|\\.)*\")+)\s*;", body)
    parts = re.findall(r"\"((?:[^\"\\]|\\.)*)\"", m.group(1))
    raw = "".join(parts)
    return bytes(raw, "latin-1").decode("unicode_escape")


minify_src = upstream("v1.7.12", "tests/minify_tests.c").decode()

valid, boundary, invalid, security = [], [], [], []


def add(lst, name, kind_dir, data: bytes, ext, *, mode="minify", desc, exit_code=0,
        output=None, exact=True):
    path = T / "tests" / kind_dir / f"{name}{ext}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    t = {"name": name, "description": desc, "args": [mode, "{input_file}"],
         "input_file": str(path.relative_to(T))}
    if exit_code is not None:
        t["expected_exit_code"] = exit_code
    if output is not None:
        t["expected_output"] = output
        t["output_match"] = "exact" if exact else "contains"
    lst.append(t)


MINIFY_SRC = "upstream tests/minify_tests.c (v1.7.12)"

# ---- valid: minify, from upstream minify_tests.c ---------------------------
for name, func, out in [
    ("minify_spaces", "cjson_minify_should_remove_spaces", '{"key":true}'),
    ("minify_line_comment", "cjson_minify_should_remove_single_line_comments", "{}"),
    ("minify_multiline_comment", "cjson_minify_should_remove_multiline_comments", "{}"),
]:
    data = c_string(func, "to_minify", minify_src)
    add(valid, name, "valid", data.encode(), ".json",
        desc=f"{func}: prints {out}. Source: {MINIFY_SRC}", output=out + "\n")

data = c_string("cjson_minify_should_not_modify_strings", "to_minify", minify_src)
add(valid, "minify_keeps_strings", "valid", data.encode(), ".json",
    desc=f"cjson_minify_should_not_modify_strings: a string is printed unchanged. Source: {MINIFY_SRC}",
    output=data + "\n")

data = c_string("cjson_minify_should_minify_json", "to_minify", minify_src)
out = c_string("cjson_minify_should_minify_json", "minified", minify_src)
add(valid, "minify_glossary", "valid", data.encode(), ".json",
    desc=f"cjson_minify_should_minify_json: whitespace and both comment kinds removed. Source: {MINIFY_SRC}",
    output=out + "\n")

# ---- valid: comment marks inside strings ------------------------------------
STR_SRC = ("RFC 8259 §7 ('/' and '*' are ordinary string characters) and "
           "cjson_minify_should_not_modify_strings in " + MINIFY_SRC)
for name, text in [("minify_comment_marks_in_string", '{"pattern":"/*"}'),
                   ("minify_glob_in_string", '{"include":"src/*.c","exclude":"*/tmp"}')]:
    add(valid, name, "valid", text.encode(), ".json",
        desc=f"Strings are not modified, so the output equals the input. Source: {STR_SRC}",
        output=text + "\n")

# ---- valid: parse, upstream tests/inputs with their .expected --------------
for n in (1, 2, 3, 4, 5, 7, 8, 9, 10, 11):
    data = upstream("v1.7.10", f"tests/inputs/test{n}")
    exp = upstream("v1.7.10", f"tests/inputs/test{n}.expected").decode()
    add(valid, f"parse_test{n}", "valid", data, ".json", mode="parse",
        desc=f"Parsed and printed with cJSON_Print, byte for byte as tests/inputs/test{n}.expected. "
             "Source: upstream tests/parse_examples.c (v1.7.10)",
        output=exp)

# ---- boundary: end of input inside every construct the patches touch -------
B_SRC = ("cJSON_Minify removes whitespace and comments and keeps strings "
         "(cJSON.h doc comment; " + MINIFY_SRC + ")")
for name, text, out in [
    ("minify_empty", "", ""),
    ("minify_only_whitespace", " \t\r\n", ""),
    ("minify_comment_closed_at_end", "{}/* c */", "{}"),
    ("minify_empty_comment", "/**/", ""),
    ("minify_line_comment_at_end", "{}// c", "{}"),
    ("minify_comment_then_string", '/* x */"a"', '"a"'),
    ("minify_string_at_end", '"abc"', '"abc"'),
    ("minify_escaped_quote_at_end", '"a\\""', '"a\\""'),
    ("minify_escaped_backslash_at_end", '"a\\\\"', '"a\\\\"'),
]:
    add(boundary, name, "boundary", text.encode(), ".json",
        desc=f"Input ends right after the construct; prints {out!r}. Source: {B_SRC}",
        output=out + "\n")
add(boundary, "parse_nesting_at_limit", "boundary", ("[" * 1000 + "]" * 1000).encode(), ".json",
    mode="parse", desc="1000 nested arrays, exactly CJSON_NESTING_LIMIT, are accepted. "
                       "Source: cJSON.h, CJSON_NESTING_LIMIT")

# ---- invalid ----------------------------------------------------------------
P_SRC = "upstream tests/parse_array.c and parse_object.c (v1.7.10), not parsed"
for name, text, src in [
    ("parse_empty", "", P_SRC),
    ("parse_open_bracket", "[", P_SRC),
    ("parse_close_bracket", "]", P_SRC),
    ("parse_open_brace", "{", P_SRC),
    ("parse_incomplete_object", '{ "name": ', "upstream tests/parse_examples.c test12 (v1.7.10)"),
    ("parse_unterminated_escape", '"000000000000000000\\',
     "upstream tests/parse_string.c (v1.7.10), malformed string"),
]:
    add(invalid, name, "invalid", text.encode(), ".json", mode="parse", exit_code=1,
        desc=f"Not valid JSON: 'parse error', exit 1. Source: {src}; driver contract (src/main.c)")
add(invalid, "parse_html", "invalid", upstream("v1.7.10", "tests/inputs/test6"), ".json",
    mode="parse", exit_code=1,
    desc="An HTML page is not JSON: exit 1. Source: upstream tests/parse_examples.c test6 (v1.7.10)")
add(invalid, "parse_nesting_too_deep", "invalid", ("[" * 1001 + "]" * 1001).encode(), ".json",
    mode="parse", exit_code=1,
    desc="1001 nested arrays exceed CJSON_NESTING_LIMIT: exit 1. Source: cJSON.h, CJSON_NESTING_LIMIT")
add(invalid, "minify_lone_slash", "invalid", b"8 / 5\n", ".json", exit_code=0,
    desc="A '/' that starts no comment must not hang or crash; output not specified. "
         "Source: cjson_minify_should_not_loop_infinitely in " + MINIFY_SRC)
add(invalid, "driver_unknown_mode", "invalid", b"{}", ".json", mode="bogus", exit_code=2,
    desc="Unknown mode: usage message, exit 2. Source: driver contract (src/main.c)")

# ---- security ---------------------------------------------------------------
add(security, "exploit_comment", "exploits", b"/*", ".json", exit_code=0, output="\n",
    desc="CVE-2019-11835 (issue #338): unterminated multiline comment; base reads past the "
         "buffer. Fixed: prints an empty line. Source: cjson_minify_should_not_overflow_buffer in "
         + MINIFY_SRC)
add(security, "exploit_string", "exploits", b'"\\', ".json", exit_code=0, output='"\\\n',
    desc="CVE-2019-11834 (issue #337): string ending in a backslash; base reads past the "
         "buffer. Fixed: prints the input unchanged. Source: cjson_minify_should_not_overflow_buffer in "
         + MINIFY_SRC)
add(security, "exploit_comment_bypass", "exploits", b"/* bla", ".json", exit_code=0, output="\n",
    desc="CVE-2019-11835 with a different input: an unterminated comment with text after the "
         "opener. Passes the incomplete patch. Fixed: prints an empty line. Source: "
         "cjson_minify_should_not_overflow_buffer in " + MINIFY_SRC)


# ---- zaraban.yaml -------------------------------------------------------------
class Block(str):
    pass


def block_repr(dumper, s):
    style = "|" if "\n" in s and not s.startswith((" ", "\t")) else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", s, style=style)


yaml.SafeDumper.add_representer(str, block_repr)
config = {
    "name": "cjson",
    "input_method": "file",
    "build": {"binary_path": "cjson_driver", "release_cmd": "make release",
              "sanitized_cmd": "make sanitized", "clean_cmd": "make clean",
              "coverage_cmd": "make coverage"},
    "limits": {"timeout_seconds": 2.0, "memory_limit_mb": 256},
    "valid_tests": valid,
    "boundary_tests": boundary,
    "invalid_tests": invalid,
    "security_tests": security,
}
header = ("# cJSON target (DaveGamble/cJSON v1.7.10), CVE-2019-11834 and CVE-2019-11835.\n"
          "# Where every expected behavior comes from: ORACLE.md.\n\n")
text = header + yaml.safe_dump(config, sort_keys=False, allow_unicode=True, width=100)
(T / "zaraban.yaml").write_text(text, encoding="utf-8")

# Round trip: every expected output survives YAML exactly.
loaded = yaml.safe_load(text)
for lst in ("valid_tests", "boundary_tests", "invalid_tests", "security_tests"):
    for a, b in zip(config[lst], loaded[lst]):
        assert a == b, (a["name"], a.get("expected_output"), b.get("expected_output"))
print(len(valid), "valid,", len(boundary), "boundary,", len(invalid), "invalid,",
      len(security), "security")
