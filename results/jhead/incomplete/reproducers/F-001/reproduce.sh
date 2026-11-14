#!/usr/bin/env bash
# Replays exploit_datetime of this finding on patch-sanitized.
#   ./reproduce.sh        replays the min input
#   ./reproduce.sh orig   replays the original input
#   ./reproduce.sh min    replays the minimized input
# Exit codes: 0 reproduced, 1 not reproduced, 2 binary hash mismatch or bad usage.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WANT_SHA="$(grep -o '"binary_sha256": *"[0-9a-f]*"' "$HERE/metadata.json" | grep -o '[0-9a-f]\{64\}')"
GOT_SHA="$(sha256sum "$HERE/bin/jhead" | cut -d' ' -f1)"
if [ -z "$WANT_SHA" ] || [ "$WANT_SHA" != "$GOT_SHA" ]; then
  echo "binary hash mismatch: bin/jhead is not the binary in metadata.json" >&2
  exit 2
fi

WHICH="${1:-min}"
case "$WHICH" in orig|min) ;; *) echo "usage: $0 [orig|min]" >&2; exit 2 ;; esac
SRC="$HERE/input.$WHICH.jpg"
[ -f "$SRC" ] || { echo "no input.$WHICH.jpg in this bundle" >&2; exit 2; }

# An empty working directory that holds only the input file, under the same
# name as during the run (input method "file"); otherwise it stays empty.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/run"
cp "$SRC" "$TMP/input"
cp "$SRC" "$TMP/run/"input.jpg
IFS= read -r -d '' INPUT_ARG < "$TMP/input" || true
cd "$TMP/run"
ulimit -c 0
env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=1:disable_coredump=1:max_allocation_size_mb=256 UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1:symbolize=1 ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer "$HERE/bin/jhead" input.jpg < /dev/null > "$TMP/stdout" 2> "$TMP/stderr"
STATUS=$?
cat "$TMP/stdout"
cat "$TMP/stderr" >&2

OK=1
PATTERN=heap-buffer-overflow
WANT_SIGNAL=''
FUNCS=(ProcessExifDir process_EXIF ReadJpegSections)
if [ -n "$PATTERN" ] && ! grep -Eq -- "$PATTERN" "$TMP/stderr"; then OK=0; fi
if [ -n "$WANT_SIGNAL" ] && [ "$STATUS" -ne $((128 + WANT_SIGNAL)) ]; then OK=0; fi
if [ -z "$PATTERN" ] && [ -z "$WANT_SIGNAL" ] && [ "$STATUS" -lt 128 ]; then OK=0; fi
for FN in ${FUNCS[@]+"${FUNCS[@]}"}; do
  grep -qF -- "$FN" "$TMP/stderr" || OK=0
done

if [ "$OK" = 1 ]; then
  echo "REPRODUCED: HEAP_BUFFER_OVERFLOW @ ProcessExifDir < process_EXIF < ReadJpegSections"
  exit 0
fi
echo "NOT REPRODUCED (exit status $STATUS)"
exit 1
