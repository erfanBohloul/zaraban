# cJSON target (DaveGamble/cJSON) with the cjson_driver front end.
#
# The release and sanitized flags live here, not in zaraban.yaml, so a patch
# that weakens the release flags is caught by the hardening check.

SRC = src/cJSON.c src/main.c
BIN = cjson_driver

RELEASE_CFLAGS  = -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
RELEASE_LDFLAGS = -pie -Wl,-z,relro,-z,now

SANITIZE_FLAGS = -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined

COVERAGE_FLAGS = -O0 -g -fprofile-instr-generate -fcoverage-mapping

.PHONY: release sanitized coverage clean

release:
	gcc $(RELEASE_CFLAGS) -Isrc -o $(BIN) $(SRC) $(RELEASE_LDFLAGS) -lm

sanitized:
	clang $(SANITIZE_FLAGS) -Isrc -o $(BIN) $(SRC) -lm

coverage:
	clang $(COVERAGE_FLAGS) -Isrc -o $(BIN) $(SRC) -lm

clean:
	rm -f $(BIN) *.profraw *.profdata
