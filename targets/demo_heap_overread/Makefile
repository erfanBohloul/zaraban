CC ?= gcc
CLANG ?= clang
SRC = src/main.c
TARGET = demo_heap_overread

# Release: optimized, hardened binary (what a user would ship).
RELEASE_CFLAGS = -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra
RELEASE_LDFLAGS = -Wl,-z,relro,-z,now -pie -fPIE

# Sanitized: AddressSanitizer + UndefinedBehaviorSanitizer with debug symbols.
SANITIZE_CFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -Wall -Wextra
SANITIZE_LDFLAGS = -fsanitize=address,undefined

# Coverage: source-based coverage, used for the execution trace.
COVERAGE_CFLAGS = -O0 -g -fprofile-instr-generate -fcoverage-mapping -Wall -Wextra

.PHONY: all release sanitized coverage clean
all: release
release: $(SRC)
	$(CC) $(RELEASE_CFLAGS) $(RELEASE_LDFLAGS) -o $(TARGET) $(SRC)
sanitized: $(SRC)
	$(CLANG) $(SANITIZE_CFLAGS) $(SANITIZE_LDFLAGS) -o $(TARGET) $(SRC)
coverage: $(SRC)
	$(CLANG) $(COVERAGE_CFLAGS) -o $(TARGET) $(SRC)
clean:
	rm -f $(TARGET) *.o *.profraw *.profdata
