/*
  cJSON - Ultralightweight JSON parser in ANSI C
  Target 2: Real-World Library implementation for Zaraban
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include "cJSON.h"

#define NUM_BUFFER_SIZE 32

static cJSON *cJSON_New_Item(void) {
    cJSON *node = (cJSON*)malloc(sizeof(cJSON));
    if (node) memset(node, 0, sizeof(cJSON));
    return node;
}

void cJSON_Delete(cJSON *c) {
    cJSON *next;
    while (c) {
        next = c->next;
        if (!(c->type & cJSON_Raw) && c->child) cJSON_Delete(c->child);
        if (!(c->type & cJSON_Raw) && c->valuestring) free(c->valuestring);
        if (!(c->type & cJSON_Raw) && c->string) free(c->string);
        free(c);
        c = next;
    }
}

static const char *skip_whitespace(const char *in) {
    while (in && *in && (unsigned char)*in <= 32) in++;
    return in;
}

/* Forward declarations */
static const char *parse_value(cJSON *item, const char *value);
static const char *parse_string(cJSON *item, const char *str);
static const char *parse_number(cJSON *item, const char *num);
static const char *parse_array(cJSON *item, const char *value);
static const char *parse_object(cJSON *item, const char *value);

/*
 * VULNERABILITY (Base Version):
 * Unbounded copy into a 32-byte stack buffer 'num_buf'!
 * When a numeric literal exceeds 32 digits, strcpy/pointer copy
 * overflows the stack buffer, triggering StackBufferOverflow / __stack_chk_fail.
 */
static const char *parse_number(cJSON *item, const char *num) {
    char num_buf[NUM_BUFFER_SIZE];
    const char *p = num;
    size_t i = 0;

    if (*p == '-') p++;
    while (*p && (isdigit((unsigned char)*p) || *p == '.' || *p == 'e' || *p == 'E' || *p == '+' || *p == '-')) {
        p++;
    }

    size_t len = (size_t)(p - num);

    /* VULNERABLE: Direct unbounded copy into fixed stack buffer */
    for (i = 0; i < len; i++) {
        num_buf[i] = num[i];
    }
    num_buf[i] = '\0';

    item->valuedouble = atof(num_buf);
    if (item->valuedouble >= 2147483647.0) item->valueint = 2147483647;
    else if (item->valuedouble <= -2147483648.0) item->valueint = -2147483648;
    else item->valueint = (int)item->valuedouble;
    item->type = cJSON_Number;

    return p;
}

static const char *parse_string(cJSON *item, const char *str) {
    const char *ptr = str + 1;
    char *ptr2;
    char *out;
    int len = 0;

    if (*str != '\"') return NULL;

    while (*ptr != '\"' && *ptr && ++len) {
        if (*ptr++ == '\\') ptr++;
    }

    out = (char*)malloc(len + 1);
    if (!out) return NULL;

    ptr = str + 1;
    ptr2 = out;
    while (*ptr != '\"' && *ptr) {
        if (*ptr != '\\') {
            *ptr2++ = *ptr++;
        } else {
            ptr++;
            switch (*ptr) {
                case 'b': *ptr2++ = '\b'; break;
                case 'f': *ptr2++ = '\f'; break;
                case 'n': *ptr2++ = '\n'; break;
                case 'r': *ptr2++ = '\r'; break;
                case 't': *ptr2++ = '\t'; break;
                case '\"': *ptr2++ = '\"'; break;
                case '\\': *ptr2++ = '\\'; break;
                default: *ptr2++ = *ptr; break;
            }
            ptr++;
        }
    }
    *ptr2 = 0;
    if (*ptr == '\"') ptr++;

    item->valuestring = out;
    item->type = cJSON_String;
    return ptr;
}

static const char *parse_array(cJSON *item, const char *value) {
    cJSON *child;
    if (*value != '[') return NULL;

    item->type = cJSON_Array;
    value = skip_whitespace(value + 1);
    if (*value == ']') return value + 1;

    item->child = child = cJSON_New_Item();
    if (!item->child) return NULL;
    value = skip_whitespace(parse_value(child, skip_whitespace(value)));
    if (!value) return NULL;

    while (*value == ',') {
        cJSON *new_item = cJSON_New_Item();
        if (!new_item) return NULL;
        child->next = new_item;
        new_item->prev = child;
        child = new_item;
        value = skip_whitespace(parse_value(child, skip_whitespace(value + 1)));
        if (!value) return NULL;
    }

    if (*value == ']') return value + 1;
    return NULL;
}

static const char *parse_object(cJSON *item, const char *value) {
    cJSON *child;
    if (*value != '{') return NULL;

    item->type = cJSON_Object;
    value = skip_whitespace(value + 1);
    if (*value == '}') return value + 1;

    item->child = child = cJSON_New_Item();
    if (!item->child) return NULL;
    value = skip_whitespace(parse_string(child, skip_whitespace(value)));
    if (!value) return NULL;
    child->string = child->valuestring;
    child->valuestring = NULL;

    if (*value != ':') return NULL;
    value = skip_whitespace(parse_value(child, skip_whitespace(value + 1)));
    if (!value) return NULL;

    while (*value == ',') {
        cJSON *new_item = cJSON_New_Item();
        if (!new_item) return NULL;
        child->next = new_item;
        new_item->prev = child;
        child = new_item;
        value = skip_whitespace(parse_string(child, skip_whitespace(value + 1)));
        if (!value) return NULL;
        child->string = child->valuestring;
        child->valuestring = NULL;
        if (*value != ':') return NULL;
        value = skip_whitespace(parse_value(child, skip_whitespace(value + 1)));
        if (!value) return NULL;
    }

    if (*value == '}') return value + 1;
    return NULL;
}

static const char *parse_value(cJSON *item, const char *value) {
    if (!value) return NULL;
    if (!strncmp(value, "null", 4))  { item->type = cJSON_NULL;  return value + 4; }
    if (!strncmp(value, "false", 5)) { item->type = cJSON_False; return value + 5; }
    if (!strncmp(value, "true", 4))  { item->type = cJSON_True;  item->valueint = 1; return value + 4; }
    if (*value == '\"')              { return parse_string(item, value); }
    if (*value == '-' || isdigit((unsigned char)*value)) { return parse_number(item, value); }
    if (*value == '[')              { return parse_array(item, value); }
    if (*value == '{')              { return parse_object(item, value); }
    return NULL;
}

cJSON *cJSON_ParseWithOpts(const char *value, const char **return_parse_end, int require_null_terminated) {
    const char *end = 0;
    cJSON *c = cJSON_New_Item();
    if (!c) return NULL;

    end = parse_value(c, skip_whitespace(value));
    if (!end) { cJSON_Delete(c); return NULL; }

    if (require_null_terminated) {
        end = skip_whitespace(end);
        if (*end) { cJSON_Delete(c); return NULL; }
    }
    if (return_parse_end) *return_parse_end = end;
    return c;
}

cJSON *cJSON_Parse(const char *value) {
    return cJSON_ParseWithOpts(value, 0, 0);
}
