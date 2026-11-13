# jhead target: versions, tests and oracle

## The program

[jhead](https://www.sentex.net/~mwandel/jhead/) (Matthias Wandel), version
3.04, a widely used command-line tool that reads and edits the EXIF metadata
of JPEG files. It is **public domain** (see `src/LICENSE.txt`). The base
sources in `src/` are taken unchanged from upstream commit `56c108f`
(2020-10-22), the last commit before the DateTime over-read fix.

jhead has its **own CLI**, so this target needs no driver: the tool is run as
`jhead <file>`, which prints the file's EXIF fields and exits `0`. A plain run
only reads the file (verified: the input is byte-for-byte unchanged after a
run).

## The vulnerability

A heap out-of-bounds **read** (CWE-125) in `ProcessExifDir` (`src/exif.c`),
in the EXIF DateTime handling. For a `DateTime` tag jhead copies a fixed 19
bytes out of the EXIF buffer:

```c
strncpy(ImageInfo.DateTime, (char *)ValuePtr, 19);
```

The general per-tag check only validates the tag's own `ByteCount` bytes, not
this hardcoded 19. So a `DateTime` tag whose value has a small `ByteCount` and
sits within 19 bytes of the end of the EXIF buffer makes `strncpy` read past
the allocation. Under AddressSanitizer this aborts with:

```
AddressSanitizer: heap-buffer-overflow ... READ
    #1 in ProcessExifDir  src/exif.c:638
    #2 in process_EXIF
    #3 in ReadJpegSections
```

The upstream fix is commit `df124a4` ("Fix fuzz test read up to 19 bytes
beyond allocated"), which adds `if (ValuePtr+19 >= OffsetBase+ExifLength)
{ ErrNonfatal("Incomplete time"); continue; }` before the copy.

## The four versions

Each patched version is a complete tree in `versions/patch_*/` and the same
change as a diff in `patches/*.patch` (made with
`git diff --no-index --no-prefix a b`, applied with `-p1`). Only `src/exif.c`
differs from base.

| Version | What it is | Expected run |
|---|---|---|
| Base (`src/`) | jhead at commit `56c108f`. The DateTime over-read reproduces under ASan. | |
| Correct | The upstream fix `df124a4` verbatim: the bounds check guards both DateTime tags. | exit `0` |
| Incomplete | The bounds check is added **only** for the `DateTime_Original` (0x9003) tag. A plain `DateTime` (0x0132) tag still reaches the unguarded `strncpy`, so it over-reads at the same place. | exit `10` |
| Regression | The bounds check is applied correctly (both overflows gone), but the copy length is reduced from 19 to 10, so only the date is kept and the time is dropped. Every image's `Date/Time` output loses its time. | exit `20` |

## The two exploit inputs

Both are a real camera JPEG (`S100.jpg`) with one extra crafted EXIF APP1
inserted after the SOI, holding a single DateTime tag whose 5-byte value sits
at the very end of a 31-byte TIFF block:

- `exploit_datetime_original.jpg`: tag `0x9003` (DateTime_Original). On base it
  over-reads; the incomplete patch blocks it.
- `exploit_datetime.jpg`: tag `0x0132` (DateTime). On base it over-reads too;
  the incomplete patch does **not** block it, so the vulnerability remains.

Both crash on base with the same signature
(`HEAP_BUFFER_OVERFLOW @ ProcessExifDir < process_EXIF < ReadJpegSections`),
so they are one finding.

## Sources of expected behavior

Every expected output is taken from one of these, never from running a patched
version (spec §2):

| Source | Used for |
|---|---|
| **E**: the EXIF metadata embedded in each image by the camera (the Make, Model and DateTime bytes in the file) | the valid and boundary outputs |
| **X**: jhead's own regression expectations, `tests/expected-txt/` upstream (e.g. S100's `DateTime = "2000:06:27 15:53:09"`) | confirms the values above |
| **C**: jhead's contract (plain `jhead FILE` prints fields and exits 0; it rejects a non-JPEG / truncated / empty file with exit 1, without crashing) | exit codes of the boundary and invalid tests |

## Tests

Inputs are in `tests/<kind>/`. The exact expected output of each test is in
`zaraban.yaml`; the match is `contains` on a stable EXIF value, never on the
varying `File date` line.

### Valid (5)

| Test | Expected (contains) | Source |
|---|---|---|
| `valid_s100_model` | `Canon PowerShot S100` | E, X |
| `valid_s100_datetime` | `2000:06:27 15:53:09` | E, X |
| `valid_kodak_model` | `KODAK DX6340 ZOOM DIGITAL CAMERA` | E |
| `valid_kodak_datetime` | `2004:01:04 18:38:15` | E |
| `valid_pro1_datetime` | `2004:12:28 20:47:05` | E |

The `*_datetime` tests are what the Regression version breaks (the time is
dropped). The `*_model` tests stay stable, confirming the regression is
limited to the DateTime handling.

### Boundary (3)

| Test | Expected | Source |
|---|---|---|
| `boundary_bigendian_model` | `Canon PowerShot A710 IS` | E — the other (Motorola) byte order |
| `boundary_bigendian_datetime` | `2010:01:24 12:31:13` | E |
| `boundary_corrupt_exif` | exit 0, no crash (malformed EXIF subdirectory handled) | C |

### Invalid (3)

The program must reject these without crashing.

| Test | Input | Expected | Source |
|---|---|---|---|
| `invalid_not_jpeg` | a text file | exit 1 | C |
| `invalid_truncated` | a JPEG cut mid-stream | exit 1 | C |
| `invalid_empty` | an empty file | exit 1 | C |

### Security (2)

On base each must crash (SPEC §5.5); on a fixed version each is handled
without crashing.

| Test | Input | Source |
|---|---|---|
| `exploit_datetime_original` | DateTime_Original tag over-read | this file; upstream commit `df124a4` |
| `exploit_datetime` | plain DateTime tag over-read | this file; upstream commit `df124a4` |

## Expected results of the scenarios

What the tool reports for each version (`scenarios.yaml` holds the same in
machine-readable form), confirmed by running it:

- **Correct**: both exploits crash on base and neither on patch, same
  signature, so one `FIXED` finding linked to `src/exif.c:638`; every other
  test matches on both. Exit `0`.
- **Incomplete**: `exploit_datetime` still crashes on patch with the base
  signature, so one `INCOMPLETE_FIX` finding. Exit `10`.
- **Regression**: the four `*_datetime` tests match on base and fail on patch,
  so four `FUNCTIONAL_REGRESSION` findings, and the exploits give `FIXED`.
  Exit `20`.
