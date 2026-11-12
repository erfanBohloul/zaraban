#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"
int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s FILE\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 2; }
    fseek(f, 0, SEEK_END); long n = ftell(f); rewind(f);
    char *buf = malloc((size_t)n + 1);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); return 2; }
    buf[n] = '\0'; fclose(f);
    cJSON_Minify(buf);
    puts(buf);
    free(buf);
    return 0;
}
