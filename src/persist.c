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
static int ensure_state_dir(void)
{
    struct stat st;

    if (stat(PERSIST_STATE_DIR, &st) == 0)
    {
        /* Directory exists; verify it's a directory and has secure mode. */
        if (!S_ISDIR(st.st_mode))
        {
            log_msg(LOG_ERR, "%s exists but is not a directory", PERSIST_STATE_DIR);
            return -1;
        }
        /* Allow any permissions here; we mainly care about the file permissions. */
        return 0;
    }

    /* Directory doesn't exist; create it with mode 0700. */
    if (mkdir(PERSIST_STATE_DIR, 0700) < 0)
    {
        log_msg(LOG_ERR, "mkdir %s: %s", PERSIST_STATE_DIR, strerror(errno));
        return -1;
    }

    /* Ensure ownership is root and permissions are tight (in case umask is weird). */
    if (chmod(PERSIST_STATE_DIR, 0700) < 0)
    {
        log_msg(LOG_WARNING, "chmod %s: %s", PERSIST_STATE_DIR, strerror(errno));
    }

    return 0;
}

/*
 * Escape special characters in JSON string value.
 * Handles: ", \, /, \b, \f, \n, \r, \t, and control characters.
 * Returns number of characters written, or -1 on error.
 */
static int json_escape_string(const char *src, char *dst, size_t dst_size)
{
    size_t written = 0;
    unsigned char c;

    if (!src || !dst || dst_size < 3)
        return -1;

    for (; *src; src++)
    {
        c = (unsigned char)*src;

        if (written + 2 >= dst_size) /* need room for escape + char + null */
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
            /* Control character: escape as \uXXXX */
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

/*
 * Unescape a JSON string in-place.
 * Handles: \", \\, \/, \b, \f, \n, \r, \t, \uXXXX.
 * Returns 0 on success, -1 on error.
 */
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
                /* \uXXXX: convert hex to Unicode (BMP only for simplicity). */
                if (src[1] && src[2] && src[3] && src[4])
                {
                    unsigned int code;
                    if (sscanf(src + 1, "%4x", &code) == 1 && code < 256)
                    {
                        *dst++ = (char)code;
                        src += 4;
                        break;
                    }
                }
                return -1; /* malformed escape */
            default:
                return -1; /* unknown escape */
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

int persist_load(PersistEntry *out_entries, int max_entries)
{
    FILE *fp;
    char line[4096];
    PersistEntry *current = NULL;
    int count = 0;
    int in_entry = 0;

    if (!out_entries || max_entries <= 0)
        return 0;

    memset(out_entries, 0, sizeof(*out_entries) * max_entries);

    fp = fopen(PERSIST_STATE_FILE, "r");
    if (!fp)
    {
        if (errno == ENOENT)
            return 0; /* File doesn't exist yet, that's OK. */
        log_msg(LOG_ERR, "persist_load: open %s: %s", PERSIST_STATE_FILE,
                strerror(errno));
        return -1;
    }

    /* Very basic JSON parsing: line-by-line with regex-like checks. */
    while (fgets(line, sizeof(line), fp) && count < max_entries)
    {
        char *p = line;

        /* Skip whitespace. */
        while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
            p++;

        /* Empty line or comment. */
        if (!*p || *p == '#')
            continue;

        /* "entry": { — start of a new entry. */
        if (sscanf(p, " \"entry\": {") > 0 || sscanf(p, " { ") > 0)
        {
            if (current == NULL)
            {
                current = &out_entries[count];
                memset(current, 0, sizeof(*current));
                in_entry = 1;
            }
            continue;
        }

        /* } — end of entry. */
        if (*p == '}')
        {
            if (current != NULL && in_entry)
            {
                count++;
                current = NULL;
                in_entry = 0;
            }
            continue;
        }

        if (!current || !in_entry)
            continue;

        /* Parse key-value pairs like "binary": "/path/to/bin", */
        char key_buf[256], val_buf[1024];
        if (sscanf(p, " \"%[^\"]\": \"%[^\"]\",", key_buf, val_buf) == 2)
        {
            json_unescape_string(val_buf);
            if (strcmp(key_buf, "binary") == 0)
            {
                size_t len = strlen(val_buf);
                memcpy(current->binary, val_buf, len < PATH_MAX ? len : PATH_MAX - 1);
                current->binary[len < PATH_MAX ? len : PATH_MAX - 1] = '\0';
            }
            else if (strcmp(key_buf, "binary_sha512") == 0)
            {
                size_t len = strlen(val_buf);
                memcpy(current->binary_sha512, val_buf, len < 128 ? len : 128 - 1);
                current->binary_sha512[len < 128 ? len : 128 - 1] = '\0';
            }
        }
        else if (sscanf(p, " \"%[^\"]\": %d,", key_buf, &current->chain_depth) == 2)
        {
            /* chain_depth: numeric value */
            continue;
        }
        else if (sscanf(p, " \"%[^\"]\": %ld,", key_buf, (long *)&current->created_at) ==
                 2)
        {
            /* created_at: timestamp */
            continue;
        }

        /* Parse chain_comm and chain_sha512 arrays. */
        int idx;
        if (sscanf(p, " \"chain_comm[%d]\": \"%[^\"]\",", &idx, val_buf) == 2)
        {
            if (idx >= 0 && idx < PERSIST_CHAIN_MAX)
            {
                json_unescape_string(val_buf);
                size_t len = strlen(val_buf);
                memcpy(current->chain_comm[idx], val_buf, len < 255 ? len : 255);
                current->chain_comm[idx][len < 255 ? len : 255] = '\0';
            }
        }
        else if (sscanf(p, " \"chain_sha512[%d]\": \"%[^\"]\",", &idx, val_buf) == 2)
        {
            if (idx >= 0 && idx < PERSIST_CHAIN_MAX)
            {
                json_unescape_string(val_buf);
                size_t len = strlen(val_buf);
                memcpy(current->chain_sha512[idx], val_buf, len < 128 ? len : 128 - 1);
                current->chain_sha512[idx][len < 128 ? len : 128 - 1] = '\0';
            }
        }
    }

    fclose(fp);
    log_msg(LOG_INFO, "persist_load: loaded %d entries from %s", count, PERSIST_STATE_FILE);
    return count;
}

int persist_save(const PersistEntry *entries, int count)
{
    FILE *fp;
    int i, j;
    char tmp_file[PATH_MAX];
    char escaped[1024];

    if (!entries || count < 0 || count > PERSIST_MAX_ENTRIES)
        return -1;

    if (ensure_state_dir() < 0)
        return -1;

    /* Write to a temporary file first, then atomic rename. */
    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp.%d", PERSIST_STATE_FILE, (int)getpid());

    fp = fopen(tmp_file, "w");
    if (!fp)
    {
        log_msg(LOG_ERR, "persist_save: open %s: %s", tmp_file, strerror(errno));
        return -1;
    }

    /* Write minimal JSON array of entries. */
    fprintf(fp, "{\n");
    fprintf(fp, "  \"entries\": [\n");

    for (i = 0; i < count; i++)
    {
        const PersistEntry *e = &entries[i];

        fprintf(fp, "    {\n");

        /* Escape binary path. */
        if (json_escape_string(e->binary, escaped, sizeof(escaped)) > 0)
            fprintf(fp, "      \"binary\": \"%s\",\n", escaped);

        /* Escape SHA-512. */
        if (json_escape_string(e->binary_sha512, escaped, sizeof(escaped)) > 0)
            fprintf(fp, "      \"binary_sha512\": \"%s\",\n", escaped);

        fprintf(fp, "      \"chain_depth\": %d,\n", e->chain_depth);
        fprintf(fp, "      \"created_at\": %ld,\n", (long)e->created_at);

        fprintf(fp, "      \"chain_comm\": [\n");
        for (j = 0; j < PERSIST_CHAIN_MAX; j++)
        {
            if (json_escape_string(e->chain_comm[j], escaped, sizeof(escaped)) > 0)
                fprintf(fp, "        \"%s\"%s\n", escaped,
                        j < PERSIST_CHAIN_MAX - 1 ? "," : "");
            else
                fprintf(fp, "        \"\"%s\n", j < PERSIST_CHAIN_MAX - 1 ? "," : "");
        }
        fprintf(fp, "      ],\n");

        fprintf(fp, "      \"chain_sha512\": [\n");
        for (j = 0; j < PERSIST_CHAIN_MAX; j++)
        {
            if (json_escape_string(e->chain_sha512[j], escaped, sizeof(escaped)) > 0)
                fprintf(fp, "        \"%s\"%s\n", escaped,
                        j < PERSIST_CHAIN_MAX - 1 ? "," : "");
            else
                fprintf(fp, "        \"\"%s\n", j < PERSIST_CHAIN_MAX - 1 ? "," : "");
        }
        fprintf(fp, "      ]\n");

        fprintf(fp, "    }%s\n", i < count - 1 ? "," : "");
    }

    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    if (fclose(fp) < 0)
    {
        log_msg(LOG_ERR, "persist_save: close %s: %s", tmp_file, strerror(errno));
        unlink(tmp_file);
        return -1;
    }

    /* Set strict permissions on the temporary file. */
    if (chmod(tmp_file, 0600) < 0)
    {
        log_msg(LOG_WARNING, "chmod %s: %s", tmp_file, strerror(errno));
    }

    /* Atomic rename. */
    if (rename(tmp_file, PERSIST_STATE_FILE) < 0)
    {
        log_msg(LOG_ERR, "persist_save: rename %s -> %s: %s", tmp_file, PERSIST_STATE_FILE,
                strerror(errno));
        unlink(tmp_file);
        return -1;
    }

    log_msg(LOG_INFO, "persist_save: saved %d entries to %s", count, PERSIST_STATE_FILE);
    return 0;
}

int persist_delete(void)
{
    if (unlink(PERSIST_STATE_FILE) < 0 && errno != ENOENT)
    {
        log_msg(LOG_ERR, "persist_delete: unlink %s: %s", PERSIST_STATE_FILE,
                strerror(errno));
        return -1;
    }
    return 0;
}
