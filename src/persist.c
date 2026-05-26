#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <syslog.h>

#include "persist.h"
#include "utils.h"

/* Ensure the state directory exists with secure permissions (0700, root-only). */
static int ensure_state_dir(const char *dirpath)
{
    struct stat st;

    if (stat(dirpath, &st) == 0)
    {
        if (!S_ISDIR(st.st_mode))
        {
            log_msg(LOG_ERR, "%s exists but is not a directory", dirpath);
            return -1;
        }
        return 0;
    }

    if (mkdir(dirpath, 0700) < 0)
    {
        log_msg(LOG_ERR, "mkdir %s: %s", dirpath, strerror(errno));
        return -1;
    }

    if (chmod(dirpath, 0700) < 0)
    {
        log_msg(LOG_WARNING, "chmod %s: %s", dirpath, strerror(errno));
    }

    return 0;
}

static int json_escape_string(const char *src, char *dst, size_t dst_size)
{
    size_t written = 0;
    unsigned char c;

    if (!src || !dst || dst_size < 1)
        return -1;

    for (; *src; src++)
    {
        c = (unsigned char)*src;

        if (written + 2 >= dst_size)
            return -1;

        if (c == '"')
        {
            dst[written++] = '\\';
            dst[written++] = '"';
        }
        else if (c == '\\')
        {
            dst[written++] = '\\';
            dst[written++] = '\\';
        }
        else if (c == '\b')
        {
            dst[written++] = '\\';
            dst[written++] = 'b';
        }
        else if (c == '\f')
        {
            dst[written++] = '\\';
            dst[written++] = 'f';
        }
        else if (c == '\n')
        {
            dst[written++] = '\\';
            dst[written++] = 'n';
        }
        else if (c == '\r')
        {
            dst[written++] = '\\';
            dst[written++] = 'r';
        }
        else if (c == '\t')
        {
            dst[written++] = '\\';
            dst[written++] = 't';
        }
        else if (c < 0x20)
        {
            if (written + 6 >= dst_size)
                return -1;
            int n = snprintf(&dst[written], dst_size - written, "\\u%04x", c);
            if (n < 0 || n >= (int)(dst_size - written))
                return -1;
            written += (size_t)n;
        }
        else
        {
            dst[written++] = c;
        }
    }

    if (written >= dst_size)
        return -1;

    dst[written] = '\0';
    return (int)written;
}

static int json_unescape_string(char *str)
{
    char *src = str;
    char *dst = str;

    if (!str)
        return -1;

    while (*src)
    {
        if (*src == '\\' && *(src + 1))
        {
            src++;
            switch (*src)
            {
            case '"':
                *dst++ = '"';
                break;
            case '\\':
                *dst++ = '\\';
                break;
            case '/':
                *dst++ = '/';
                break;
            case 'b':
                *dst++ = '\b';
                break;
            case 'f':
                *dst++ = '\f';
                break;
            case 'n':
                *dst++ = '\n';
                break;
            case 'r':
                *dst++ = '\r';
                break;
            case 't':
                *dst++ = '\t';
                break;
            case 'u':
                if (src[1] && src[2] && src[3] && src[4])
                {
                    unsigned int code;
                    if (sscanf(src + 1, "%4x", &code) == 1)
                    {
                        if (code < 0x80)
                            *dst++ = (char)code;
                        else if (code < 0x800)
                        {
                            *dst++ = (char)(0xC0 | (code >> 6));
                            *dst++ = (char)(0x80 | (code & 0x3F));
                        }
                        else
                        {
                            *dst++ = (char)(0xE0 | (code >> 12));
                            *dst++ = (char)(0x80 | ((code >> 6) & 0x3F));
                            *dst++ = (char)(0x80 | (code & 0x3F));
                        }
                        src += 4;
                        break;
                    }
                }
                return -1;
            default:
                return -1;
            }
            src++;
        }
        else
        {
            *dst++ = *src++;
        }
    }

    *dst = '\0';
    return 0;
}

int persist_load(const char *filepath, PersistEntry *out_entries, int max_entries)
{
    FILE *fp;
    char line[4096];
    PersistEntry *current = NULL;
    int count = 0;

    enum
    {
        S_OUTSIDE,
        S_IN_ENTRIES,
        S_IN_ENTRY
    } state = S_OUTSIDE;

    if (!out_entries || max_entries <= 0)
        return 0;

    memset(out_entries, 0, sizeof(*out_entries) * max_entries);

    fp = fopen(filepath, "r");
    if (!fp)
    {
        if (errno == ENOENT)
            return 0;
        log_msg(LOG_ERR, "persist_load: open %s: %s", filepath,
                strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp) && count < max_entries)
    {
        char *p = line;

        while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
            p++;

        if (!*p || *p == '#')
            continue;

        /* Detect the "entries": [ array opener. */
        if (state == S_OUTSIDE && strstr(p, "\"entries\":") != NULL)
        {
            state = S_IN_ENTRIES;
            continue;
        }

        /* Entry start: opening brace inside the entries array. */
        if (state == S_IN_ENTRIES && *p == '{')
        {
            current = &out_entries[count];
            memset(current, 0, sizeof(*current));
            state = S_IN_ENTRY;
            continue;
        }

        /* Entry end: closing brace.  Sanitise and finalise. */
        if (state == S_IN_ENTRY && *p == '}')
        {
            for (int k = current->chain_depth; k < PERSIST_CHAIN_MAX; k++)
            {
                current->chain_comm[k][0] = '\0';
                current->chain_sha512[k][0] = '\0';
            }
            if (current->chain_depth > PERSIST_CHAIN_MAX)
                current->chain_depth = PERSIST_CHAIN_MAX;
            count++;
            current = NULL;
            state = S_IN_ENTRIES;
            continue;
        }

        /* End of entries array or outer closing brace. */
        if ((state == S_IN_ENTRIES && (*p == ']' || *p == '}')) ||
            (state == S_OUTSIDE && *p == '}'))
        {
            if (state == S_IN_ENTRIES)
                state = S_OUTSIDE;
            continue;
        }

        if (state != S_IN_ENTRY || !current)
            continue;

        /* Parse key-value pairs with field-width limits.
         * Patterns intentionally omit the trailing comma so they match
         * both "value",  and  "value"  (last field before closing brace). */
        char key_buf[256], val_buf[1024];
        if (sscanf(p, " \"%255[^\"]\": \"%1023[^\"]\"", key_buf, val_buf) == 2)
        {
            if (json_unescape_string(val_buf) < 0)
            {
                log_msg(LOG_WARNING, "persist_load: unescape failed for \"%s\"", key_buf);
                continue;
            }
            if (strcmp(key_buf, "binary") == 0)
                snprintf(current->binary, PATH_MAX, "%s", val_buf);
            else if (strcmp(key_buf, "binary_sha512") == 0)
            {
                size_t len = strlen(val_buf);
                if (len >= sizeof(current->binary_sha512))
                    len = sizeof(current->binary_sha512) - 1;
                memcpy(current->binary_sha512, val_buf, len);
                current->binary_sha512[len] = '\0';
            }
        }
        else
        {
            int tmp_int;
            long created_tmp;
            if (sscanf(p, " \"%255[^\"]\": %d", key_buf, &tmp_int) == 2 &&
                strcmp(key_buf, "chain_depth") == 0)
            {
                current->chain_depth = tmp_int;
            }
            else if (sscanf(p, " \"%255[^\"]\": %ld", key_buf, &created_tmp) == 2 &&
                     strcmp(key_buf, "created_at") == 0)
            {
                current->created_at = (time_t)created_tmp;
            }
        }

        int idx;
        /* Omit trailing comma in patterns — matches both "value", and "value". */
        if (sscanf(p, " \"chain_comm[%d]\": \"%1023[^\"]\"", &idx, val_buf) == 2)
        {
            if (idx >= 0 && idx < PERSIST_CHAIN_MAX)
            {
                if (json_unescape_string(val_buf) == 0)
                {
                    size_t len = strlen(val_buf);
                    if (len >= sizeof(current->chain_comm[idx]))
                        len = sizeof(current->chain_comm[idx]) - 1;
                    memcpy(current->chain_comm[idx], val_buf, len);
                    current->chain_comm[idx][len] = '\0';
                }
                else
                    log_msg(LOG_WARNING, "persist_load: unescape failed for chain_comm[%d]", idx);
            }
        }
        else if (sscanf(p, " \"chain_sha512[%d]\": \"%1023[^\"]\"", &idx, val_buf) == 2)
        {
            if (idx >= 0 && idx < PERSIST_CHAIN_MAX)
            {
                if (json_unescape_string(val_buf) == 0)
                {
                    size_t len = strlen(val_buf);
                    if (len >= sizeof(current->chain_sha512[idx]))
                        len = sizeof(current->chain_sha512[idx]) - 1;
                    memcpy(current->chain_sha512[idx], val_buf, len);
                    current->chain_sha512[idx][len] = '\0';
                }
                else
                    log_msg(LOG_WARNING, "persist_load: unescape failed for chain_sha512[%d]",
                            idx);
            }
        }
    }

    fclose(fp);
    log_msg(LOG_INFO, "persist_load: loaded %d entries from %s", count, filepath);
    return count;
}

int persist_save(const char *filepath, const PersistEntry *entries, int count)
{
    FILE *fp;
    int i, j;
    char tmp_file[PATH_MAX];
    char escaped[1024];

    if (!entries || count < 0 || count > PERSIST_MAX_ENTRIES)
        return -1;

    /* Derive the parent directory from filepath and ensure it exists. */
    {
        char dirpath[PATH_MAX];
        snprintf(dirpath, sizeof(dirpath), "%s", filepath);
        char *slash = strrchr(dirpath, '/');
        if (slash && slash != dirpath)
        {
            *slash = '\0';
            if (ensure_state_dir(dirpath) < 0)
                return -1;
        }
    }

    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp.%d", filepath, (int)getpid());

    fp = fopen(tmp_file, "w");
    if (!fp)
    {
        log_msg(LOG_ERR, "persist_save: open %s: %s", tmp_file, strerror(errno));
        return -1;
    }

    fprintf(fp, "{\n");
    fprintf(fp, "  \"entries\": [\n");

    for (i = 0; i < count; i++)
    {
        const PersistEntry *e = &entries[i];

        fprintf(fp, "    {\n");

        if (json_escape_string(e->binary, escaped, sizeof(escaped)) > 0)
            fprintf(fp, "      \"binary\": \"%s\",\n", escaped);
        else
            fprintf(fp, "      \"binary\": \"\",\n");

        if (json_escape_string(e->binary_sha512, escaped, sizeof(escaped)) > 0)
            fprintf(fp, "      \"binary_sha512\": \"%s\",\n", escaped);
        else
            fprintf(fp, "      \"binary_sha512\": \"\",\n");

        fprintf(fp, "      \"chain_depth\": %d,\n", e->chain_depth);
        fprintf(fp, "      \"created_at\": %ld,\n", (long)e->created_at);

        /* chain_comm always gets a trailing comma: chain_sha512 fields follow. */
        for (j = 0; j < PERSIST_CHAIN_MAX; j++)
        {
            if (json_escape_string(e->chain_comm[j], escaped, sizeof(escaped)) > 0)
                fprintf(fp, "      \"chain_comm[%d]\": \"%s\",\n", j, escaped);
            else
                fprintf(fp, "      \"chain_comm[%d]\": \"\",\n", j);
        }

        /* Last chain_sha512 field has no trailing comma (closes the object). */
        for (j = 0; j < PERSIST_CHAIN_MAX; j++)
        {
            if (json_escape_string(e->chain_sha512[j], escaped, sizeof(escaped)) > 0)
                fprintf(fp, "      \"chain_sha512[%d]\": \"%s\"%s\n", j, escaped,
                        j < PERSIST_CHAIN_MAX - 1 ? "," : "");
            else
                fprintf(fp, "      \"chain_sha512[%d]\": \"\"%s\n", j,
                        j < PERSIST_CHAIN_MAX - 1 ? "," : "");
        }

        fprintf(fp, "    }%s\n", i < count - 1 ? "," : "");
    }

    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    if (fflush(fp) < 0 || fchmod(fileno(fp), 0600) < 0)
        log_msg(LOG_WARNING, "fchmod %s: %s", tmp_file, strerror(errno));

    if (fclose(fp) < 0)
    {
        log_msg(LOG_ERR, "persist_save: close %s: %s", tmp_file, strerror(errno));
        unlink(tmp_file);
        return -1;
    }

    if (rename(tmp_file, filepath) < 0)
    {
        log_msg(LOG_ERR, "persist_save: rename %s -> %s: %s", tmp_file, filepath,
                strerror(errno));
        unlink(tmp_file);
        return -1;
    }

    log_msg(LOG_INFO, "persist_save: saved %d entries to %s", count, filepath);
    return 0;
}

int persist_delete(const char *filepath)
{
    if (unlink(filepath) < 0 && errno != ENOENT)
    {
        log_msg(LOG_ERR, "persist_delete: unlink %s: %s", filepath,
                strerror(errno));
        return -1;
    }
    return 0;
}
