CC ?= gcc
CLANG ?= clang
SRC = src/cJSON.c src/main.c
TARGET = cjson_tool

# Compiler detection and flags
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    RELEASE_LDFLAGS = -Wl,-z,relro,-z,now -pie -fPIE -lm
    SANITIZE_CFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -Wall -Wextra -Isrc
    SANITIZE_LDFLAGS = -fsanitize=address,undefined -lm
else
    RELEASE_LDFLAGS = -fPIE -lm
    SANITIZE_CFLAGS = -fsanitize=undefined -fno-omit-frame-pointer -g -O1 -Wall -Wextra -Isrc
    SANITIZE_LDFLAGS = -fsanitize=undefined -lm
endif

RELEASE_CFLAGS = -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Wextra -Isrc

.PHONY: all release sanitized clean

all: release

release: $(SRC)
	$(CC) $(RELEASE_CFLAGS) $(RELEASE_LDFLAGS) -o $(TARGET) $(SRC)

sanitized: $(SRC)
	$(CLANG) $(SANITIZE_CFLAGS) $(SANITIZE_LDFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET) *.o
