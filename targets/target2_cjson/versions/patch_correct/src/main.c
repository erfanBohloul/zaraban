/*
  cjson_tool: Command-line driver for cJSON library
  Part of Zaraban validation suite
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

int process_json(const char *buffer) {
    cJSON *json = cJSON_Parse(buffer);
    if (!json) {
        fprintf(stderr, "Error: Invalid JSON format\n");
        return 1;
    }

    printf("OK: Successfully parsed JSON object (type: %d)\n", json->type);
    cJSON_Delete(json);
    return 0;
}

int main(int argc, char *argv[]) {
    FILE *f = NULL;
    if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (!f) {
            perror("fopen");
            return 1;
        }
    } else {
        f = stdin;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *data = (char*)malloc(len + 1);
    if (!data) {
        if (f != stdin) fclose(f);
        return 1;
    }

    size_t read_bytes = fread(data, 1, len, f);
    data[read_bytes] = '\0';
    if (f != stdin) fclose(f);

    int ret = process_json(data);
    free(data);
    return ret;
}
