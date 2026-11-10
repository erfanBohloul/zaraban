CC ?= gcc
CLANG ?= clang
SRC = src/main.c src/cJSON.c src/cJSON_Utils.c
TARGET = cjson_patcher

# Release build: Standard optimized, hardened ELF binary
RELEASE_CFLAGS = -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra -Isrc
RELEASE_LDFLAGS = -Wl,-z,relro,-z,now -pie -fPIE -lm

# Sanitized build: AddressSanitizer and UndefinedBehaviorSanitizer with debug symbols
SANITIZE_CFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -Wall -Wextra -Isrc
SANITIZE_LDFLAGS = -fsanitize=address,undefined -lm

.PHONY: all release sanitized clean

all: release

release: $(SRC)
	$(CC) $(RELEASE_CFLAGS) -o $(TARGET) $(SRC) $(RELEASE_LDFLAGS)

sanitized: $(SRC)
	$(CLANG) $(SANITIZE_CFLAGS) -o $(TARGET) $(SRC) $(SANITIZE_LDFLAGS)

clean:
	rm -f $(TARGET) *.o
