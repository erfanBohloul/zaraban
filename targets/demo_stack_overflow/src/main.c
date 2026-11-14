#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Reads a line from the given file and copies it into a small fixed buffer. */
int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s FILE\n", argv[0]); return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }

    char line[256];
    size_t n = fread(line, 1, sizeof line, f);
    fclose(f);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) n--;

    char name[32];
    /* BUG: no check that the line fits in name[32]. */
    memcpy(name, line, n);
    name[n] = '\0';

    printf("copied: %s\n", name);
    return 0;
}
