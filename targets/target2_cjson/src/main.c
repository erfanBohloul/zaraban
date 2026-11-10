#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"
#include "cJSON_Utils.h"

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <input_json_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f)
    {
        fprintf(stderr, "Error: Cannot open input file %s\n", argv[1]);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *data = (char *)malloc((size_t)len + 1);
    if (!data)
    {
        fclose(f);
        fprintf(stderr, "Error: Memory allocation failed\n");
        return 1;
    }

    size_t read_bytes = fread(data, 1, (size_t)len, f);
    data[read_bytes] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(data);
    free(data);
    if (!root)
    {
        fprintf(stderr, "Error: Failed to parse input JSON\n");
        return 1;
    }

    cJSON *target = cJSON_DetachItemFromObject(root, "target");
    if (!target)
    {
        fprintf(stderr, "Error: Missing 'target' field in input JSON\n");
        cJSON_Delete(root);
        return 1;
    }

    cJSON *patch = NULL;
    cJSON *patch_ptr_item = cJSON_GetObjectItem(root, "patch_pointer");

    if (patch_ptr_item && cJSON_IsString(patch_ptr_item))
    {
        /* Resolve patch as an internal pointer/subtree within target */
        patch = cJSONUtils_GetPointer(target, patch_ptr_item->valuestring);
        if (!patch)
        {
            fprintf(stderr, "Error: Failed to resolve patch_pointer '%s'\n", patch_ptr_item->valuestring);
            cJSON_Delete(target);
            cJSON_Delete(root);
            return 1;
        }
    }
    else
    {
        patch = cJSON_DetachItemFromObject(root, "patch");
        if (!patch)
        {
            fprintf(stderr, "Error: Missing 'patch' or 'patch_pointer' field in input JSON\n");
            cJSON_Delete(target);
            cJSON_Delete(root);
            return 1;
        }
    }

    /* Perform the JSON Merge Patch operation (RFC 7386) */
    cJSON *result = cJSONUtils_MergePatch(target, patch);

    /* If patch was detached from root (external), we free it;
     * If patch was a subtree of target, cJSONUtils_MergePatch handled target lifecycle.
     */
    if (!patch_ptr_item && patch)
    {
        cJSON_Delete(patch);
    }

    cJSON_Delete(root);

    if (result)
    {
        char *out = cJSON_PrintUnformatted(result);
        if (out)
        {
            printf("%s\n", out);
            free(out);
        }
        cJSON_Delete(result);
        return 0;
    }

    return 1;
}
