#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Looks up the role of the user named on the first line of the file. */
static const char *role_of(const char *name)
{
    if (strcmp(name, "alice") == 0) return "administrator";
    if (strcmp(name, "root") == 0)  return "superuser";
    return NULL;                      /* unknown user */
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s FILE\n", argv[0]); return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }

    char name[64] = {0};
    if (fgets(name, sizeof name, f)) {
        size_t n = strlen(name);
        while (n > 0 && (name[n-1] == '\n' || name[n-1] == '\r')) name[--n] = '\0';
    }
    fclose(f);

    const char *role = role_of(name);
    /* BUG: role may be NULL for an unknown user. */
    printf("role=%s (%zu chars)\n", role, strlen(role));
    return 0;
}
