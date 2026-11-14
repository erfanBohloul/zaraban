#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* File format: the first line is a count K, the rest is the payload.
   Prints the sum of the first K bytes of the payload. */
int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s FILE\n", argv[0]); return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }

    char raw[512];
    size_t total = fread(raw, 1, sizeof raw, f);
    fclose(f);

    size_t i = 0;
    while (i < total && raw[i] != '\n') i++;
    long k = atol(raw);                       /* count from the first line */
    size_t off = (i < total) ? i + 1 : total;
    size_t plen = total - off;

    char *payload = malloc(plen ? plen : 1);
    memcpy(payload, raw + off, plen);

    long sum = 0;
    /* BUG: trusts k without checking it against plen. */
    for (long j = 0; j < k; j++) sum += (unsigned char)payload[j];

    printf("sum=%ld\n", sum);
    free(payload);
    return 0;
}
