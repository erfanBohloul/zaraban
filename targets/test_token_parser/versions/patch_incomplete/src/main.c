#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE 256
#define VALUE_BUF_SIZE 64

/*
 * Process a command line:
 * Supported commands:
 *   PING           -> responds with "PONG\n"
 *   ECHO <msg>     -> responds with "<msg>\n"
 *   SET <key>=<val>-> sets key-value pair and responds with "OK: <key>=<val>\n"
 */
int handle_set_command(const char *arg) {
    char value[VALUE_BUF_SIZE];
    const char *eq = strchr(arg, '=');
    if (!eq) {
        fprintf(stderr, "Error: Invalid SET syntax. Expected KEY=VALUE\n");
        return 1;
    }

    const char *val_start = eq + 1;
    size_t val_len = strlen(val_start);

    /*
     * INCOMPLETE PATCH:
     * Naively blocks inputs larger than 100 bytes (blocking the original 120-byte exploit),
     * but the buffer is only 64 bytes!
     * A secondary exploit input of 80 bytes still triggers the buffer overflow.
     */
    if (val_len >= 100) {
        fprintf(stderr, "Error: Input exceeds 100 bytes limit\n");
        return 1;
    }

    strcpy(value, val_start);

    printf("OK: %s (value length: %zu)\n", arg, strlen(value));
    return 0;
}

int handle_echo_command(const char *arg) {
    printf("%s\n", arg);
    return 0;
}

int process_input(FILE *stream) {
    char line[MAX_LINE];

    while (fgets(line, sizeof(line), stream)) {
        // Strip trailing newline
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[len - 1] = '\0';
            len--;
        }

        if (len == 0) {
            continue;
        }

        if (strcmp(line, "PING") == 0) {
            printf("PONG\n");
        } else if (strncmp(line, "ECHO ", 5) == 0) {
            handle_echo_command(line + 5);
        } else if (strncmp(line, "SET ", 4) == 0) {
            if (handle_set_command(line + 4) != 0) {
                return 1;
            }
        } else {
            fprintf(stderr, "Error: Unknown command: %s\n", line);
            return 1;
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        FILE *f = fopen(argv[1], "r");
        if (!f) {
            perror("fopen");
            return 1;
        }
        int ret = process_input(f);
        fclose(f);
        return ret;
    }
    return process_input(stdin);
}
