# REPLACE target: versions, tests and oracle

Fill in each section and delete the guidance lines. See `targets/cjson/ORACLE.md`
and `targets/jhead/ORACLE.md` for complete examples.

## The program

Upstream project, link, the exact tag or commit in `src/`, and its license.
How the program takes its input (file, stdin or arguments), and what it
prints and returns on success and on error. That contract is part of the
oracle.

## The vulnerability

| CVE / issue | Input | What happens on base (sanitized) |
|---|---|---|
| REPLACE | REPLACE | REPLACE: error type and `file:line` from the ASan report |

## The four versions

Each patched version is a complete tree in `versions/patch_*/` (its
`Makefile` and `src/`) and the same change as a diff in `patches/*.patch`.
`scripts/run_matrix.py` checks that the two agree. To make a diff from a
tree:

```bash
mkdir -p /tmp/pd/a /tmp/pd/b
cp -r Makefile src /tmp/pd/a/
cp -r versions/patch_correct/. /tmp/pd/b/
(cd /tmp/pd && git diff --no-index --no-prefix a b) > patches/correct.patch
```

| Version | What it is | Expected run |
|---|---|---|
| Base (`src/`) | REPLACE | |
| Correct | REPLACE: the upstream fix commit | exit `0` |
| Incomplete | REPLACE: blocks the public PoC only; which exploit still gets through | exit `10` |
| Regression | REPLACE: removes the crash but breaks which valid inputs | exit `20` |

## Sources of expected behavior

Every expected output comes from one of these, never from running a patched
version or from a language model.

| Source | Used for |
|---|---|
| REPLACE: documentation, man page, upstream tests | REPLACE |

## Tests

For each test: its name, what it checks, and the source of its expectation.

### Valid

### Boundary

### Invalid

### Security

## Expected results of the scenarios

Why each patch gives its exit code and findings (matches `scenarios.yaml`).
