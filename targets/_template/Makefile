# Template Makefile. Replace SRC and BIN, and add any -I, -D or -l flags the
# program needs. Keep the release flags here, not in zaraban.yaml: the
# hardening check compares the release binaries of base and patch, so a patch
# that weakens these flags is reported.

SRC = $(wildcard src/*.c)
BIN = program

# Release: optimized and hardened (stack canary, FORTIFY, PIE, full RELRO).
RELEASE_CFLAGS  = -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
RELEASE_LDFLAGS = -pie -Wl,-z,relro,-z,now

# Sanitized: ASan and UBSan with debug symbols, so crash frames have file:line.
SANITIZE_FLAGS = -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined

# Coverage: clang source-based coverage, used for the execution trace.
COVERAGE_FLAGS = -O0 -g -fprofile-instr-generate -fcoverage-mapping

.PHONY: release sanitized coverage clean

release:
	gcc $(RELEASE_CFLAGS) -Isrc -o $(BIN) $(SRC) $(RELEASE_LDFLAGS)

sanitized:
	clang $(SANITIZE_FLAGS) -Isrc -o $(BIN) $(SRC)

coverage:
	clang $(COVERAGE_FLAGS) -Isrc -o $(BIN) $(SRC)

clean:
	rm -f $(BIN) *.profraw *.profdata
