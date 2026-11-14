# jhead target (Matthias Wandel's jhead, public domain), used as a Zaraban target.
# jhead has its own CLI (jhead FILE), so there is no driver.
#
# Release and sanitized flags live here, not in zaraban.yaml, so a patch that
# weakens the release flags is caught by the hardening check.

SRC = exif.c gpsinfo.c iptc.c jhead.c jpgfile.c jpgqguess.c makernote.c paths.c
BIN = jhead

RELEASE_CFLAGS  = -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
RELEASE_LDFLAGS = -pie -Wl,-z,relro,-z,now

SANITIZE_FLAGS = -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined

COVERAGE_FLAGS = -O0 -g -fprofile-instr-generate -fcoverage-mapping

.PHONY: release sanitized coverage clean

release:
	cd src && gcc $(RELEASE_CFLAGS) -o ../$(BIN) $(SRC) $(RELEASE_LDFLAGS) -lm

sanitized:
	cd src && clang $(SANITIZE_FLAGS) -o ../$(BIN) $(SRC) -lm

coverage:
	cd src && clang $(COVERAGE_FLAGS) -o ../$(BIN) $(SRC) -lm

clean:
	rm -f $(BIN) *.profraw *.profdata
