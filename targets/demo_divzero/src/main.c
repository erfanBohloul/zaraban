#include <stdio.h>
#include <stdlib.h>

/* Reads two integers "a b" from the file and prints a / b. */
int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s FILE\n", argv[0]); return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }

    long a = 0, b = 0;
    if (fscanf(f, "%ld %ld", &a, &b) != 2) {
        fprintf(stderr, "expected two integers\n");
        fclose(f);
        return 1;
    }
    fclose(f);

    /* BUG: no check that b is non-zero. */
    printf("result=%ld\n", a / b);
    return 0;
}
