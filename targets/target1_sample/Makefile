CC ?= gcc
CLANG ?= clang
SRC = src/main.c
TARGET = token_parser

# Release build: Standard optimized, hardened ELF binary
RELEASE_CFLAGS = -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra
RELEASE_LDFLAGS = -Wl,-z,relro,-z,now -pie -fPIE

# Sanitized build: AddressSanitizer and UndefinedBehaviorSanitizer with debug symbols
SANITIZE_CFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -Wall -Wextra
SANITIZE_LDFLAGS = -fsanitize=address,undefined

.PHONY: all release sanitized clean

all: release

release: $(SRC)
	$(CC) $(RELEASE_CFLAGS) $(RELEASE_LDFLAGS) -o $(TARGET) $(SRC)

sanitized: $(SRC)
	$(CLANG) $(SANITIZE_CFLAGS) $(SANITIZE_LDFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET) *.o
