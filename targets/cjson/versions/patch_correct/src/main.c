/*
 * cjson_driver: a minimal command-line front end for the cJSON library, so
 * that Zaraban can run it on test inputs. Its contract is part of the oracle
 * (see ../ORACLE.md):
 *
 *   cjson_driver minify FILE
 *       Reads FILE, runs cJSON_Minify on it in place, prints the result and a
 *       newline, exits 0.
 *   cjson_driver parse FILE
 *       Parses FILE with cJSON_Parse and prints it back with cJSON_Print
 *       (formatted, nothing appended), exits 0; if it is not valid JSON,
 *       prints "parse error" to stderr and exits 1.
 *   Wrong usage or an unreadable file: a message on stderr, exit 2.
 *
 * FILE is read into a heap buffer of exactly its size plus the terminating
 * NUL, as a caller of cJSON_Minify would pass a C string.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

static char *read_all(const char *path)
{
    FILE *f = fopen(path, "rb");
    char *buf = NULL;
    long n = 0;

    if (f == NULL) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    buf = malloc((size_t)n + 1);
    if (buf != NULL && fread(buf, 1, (size_t)n, f) == (size_t)n) {
        buf[n] = '\0';
    } else {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    return buf;
}

int main(int argc, char **argv)
{
    char *buf = NULL;
    int rc = 0;

    if (argc != 3 || (strcmp(argv[1], "minify") != 0 && strcmp(argv[1], "parse") != 0)) {
        fprintf(stderr, "usage: %s minify|parse FILE\n", argv[0]);
        return 2;
    }
    buf = read_all(argv[2]);
    if (buf == NULL) {
        fprintf(stderr, "cannot read %s\n", argv[2]);
        return 2;
    }

    if (strcmp(argv[1], "minify") == 0) {
        cJSON_Minify(buf);
        puts(buf);
    } else {
        cJSON *json = cJSON_Parse(buf);
        if (json == NULL) {
            fprintf(stderr, "parse error\n");
            rc = 1;
        } else {
            char *printed = cJSON_Print(json);
            if (printed == NULL) {
                fprintf(stderr, "print error\n");
                rc = 1;
            } else {
                fputs(printed, stdout);
                free(printed);
            }
            cJSON_Delete(json);
        }
    }

    free(buf);
    return rc;
}
