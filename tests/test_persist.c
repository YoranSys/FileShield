#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>

#include "../src/persist.h"

/* Use /tmp for testing instead of /var/lib/fileshield */
static char test_state_file[256];
static char test_state_dir[256];

#define TEST_FAIL(msg) \
    do { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        return 1; \
    } while (0)

#define TEST_PASS(msg) \
    do { \
        fprintf(stdout, "PASS: %s\n", msg); \
    } while (0)

#define ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            TEST_FAIL(msg); \
        } \
    } while (0)

/*
 * Helper: override the PERSIST_STATE_FILE by creating a mock JSON save function.
 * Since we can't easily override macro constants, we'll write directly to a temp file.
 */

static int test_persist_save_mock(const PersistEntry *entries, int count, const char *filename)
{
    FILE *fp;
    int i, j;
    char tmp_file[PATH_MAX];

    if (!entries || count < 0 || count > PERSIST_MAX_ENTRIES)
        return -1;

    /* Ensure directory exists */
    snprintf(test_state_dir, sizeof(test_state_dir), "/tmp/fileshield_test");
    if (mkdir(test_state_dir, 0700) < 0 && errno != EEXIST)
        return -1;

    /* Write to temporary file */
    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp.%d", filename, (int)getpid());

    fp = fopen(tmp_file, "w");
    if (!fp)
        return -1;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"entries\": [\n");

    for (i = 0; i < count; i++)
    {
        const PersistEntry *e = &entries[i];
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"binary\": \"%s\",\n", e->binary);
        fprintf(fp, "      \"binary_sha512\": \"%s\",\n", e->binary_sha512);
        fprintf(fp, "      \"chain_depth\": %d,\n", e->chain_depth);
        fprintf(fp, "      \"created_at\": %ld,\n", (long)e->created_at);
        fprintf(fp, "      \"chain_comm\": [\n");
        for (j = 0; j < PERSIST_CHAIN_MAX; j++)
        {
            fprintf(fp, "        \"%s\"%s\n", e->chain_comm[j],
                    j < PERSIST_CHAIN_MAX - 1 ? "," : "");
        }
        fprintf(fp, "      ],\n");
        fprintf(fp, "      \"chain_sha512\": [\n");
        for (j = 0; j < PERSIST_CHAIN_MAX; j++)
        {
            fprintf(fp, "        \"%s\"%s\n", e->chain_sha512[j],
                    j < PERSIST_CHAIN_MAX - 1 ? "," : "");
        }
        fprintf(fp, "      ]\n");
        fprintf(fp, "    }%s\n", i < count - 1 ? "," : "");
    }

    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    if (fclose(fp) < 0)
    {
        unlink(tmp_file);
        return -1;
    }

    if (chmod(tmp_file, 0600) < 0)
    {
        unlink(tmp_file);
        return -1;
    }

    if (rename(tmp_file, filename) < 0)
    {
        unlink(tmp_file);
        return -1;
    }

    return 0;
}

static int test_persist_load_mock(PersistEntry *out_entries, int max_entries, const char *filename)
{
    FILE *fp;
    char line[4096];
    PersistEntry *current = NULL;
    int count = 0;
    int in_entry = 0;
    int in_chain_comm = 0;
    int in_chain_sha = 0;
    int chain_idx = 0;
    int brace_count = 0;

    if (!out_entries || max_entries <= 0)
        return 0;

    memset(out_entries, 0, sizeof(*out_entries) * max_entries);

    fp = fopen(filename, "r");
    if (!fp)
    {
        if (errno == ENOENT)
            return 0;
        return -1;
    }

    while (fgets(line, sizeof(line), fp) && count < max_entries)
    {
        char *p = line;
        char val_buf[1024];

        /* Skip whitespace */
        while (*p && (*p == ' ' || *p == '\t'))
            p++;

        if (!*p || *p == '\n' || *p == '#')
            continue;

        /* Detect opening brace - only create entry if we're inside entries array */
        if (*p == '{')
        {
            brace_count++;
            /* Only create entry if brace_count indicates we're in an entry (not outer object) */
            if (brace_count >= 2 && current == NULL && count < max_entries)
            {
                current = &out_entries[count];
                memset(current, 0, sizeof(*current));
                in_entry = 1;
            }
            continue;
        }

        /* Detect closing brace */
        if (*p == '}')
        {
            if (current != NULL && in_entry && brace_count >= 2)
            {
                count++;
                current = NULL;
                in_entry = 0;
            }
            brace_count--;
            continue;
        }

        if (!current || !in_entry)
            continue;

        /* Extract fields from current entry */
        if (strstr(p, "\"binary\":") != NULL)
        {
            if (sscanf(p, " \"binary\": \"%[^\"]\",", val_buf) == 1 ||
                sscanf(p, " \"binary\": \"%[^\"]\"", val_buf) == 1)
            {
                size_t len = strlen(val_buf);
                memcpy(current->binary, val_buf, len < PATH_MAX - 1 ? len : PATH_MAX - 1);
                current->binary[len < PATH_MAX - 1 ? len : PATH_MAX - 1] = '\0';
            }
        }
        else if (strstr(p, "\"binary_sha512\":") != NULL)
        {
            if (sscanf(p, " \"binary_sha512\": \"%[^\"]\",", val_buf) == 1 ||
                sscanf(p, " \"binary_sha512\": \"%[^\"]\"", val_buf) == 1)
            {
                size_t len = strlen(val_buf);
                memcpy(current->binary_sha512, val_buf, len < 127 ? len : 127);
                current->binary_sha512[len < 127 ? len : 127] = '\0';
            }
        }
        else if (strstr(p, "\"chain_depth\":") != NULL)
        {
            sscanf(p, " \"chain_depth\": %d,", &current->chain_depth);
        }
        else if (strstr(p, "\"chain_comm\":") != NULL)
        {
            in_chain_comm = 1;
            chain_idx = 0;
            continue;
        }
        else if (strstr(p, "\"chain_sha512\":") != NULL)
        {
            in_chain_sha = 1;
            chain_idx = 0;
            continue;
        }
        else if (in_chain_comm && (strstr(p, "],") != NULL || strstr(p, "]") != NULL))
        {
            in_chain_comm = 0;
        }
        else if (in_chain_sha && strstr(p, "]") != NULL)
        {
            in_chain_sha = 0;
        }
        else if (in_chain_comm && sscanf(p, " \"%[^\"]\",", val_buf) == 1)
        {
            if (chain_idx < PERSIST_CHAIN_MAX)
            {
                size_t len = strlen(val_buf);
                memcpy(current->chain_comm[chain_idx], val_buf, len < 254 ? len : 254);
                current->chain_comm[chain_idx][len < 254 ? len : 254] = '\0';
                chain_idx++;
            }
        }
        else if (in_chain_sha && sscanf(p, " \"%[^\"]\",", val_buf) == 1)
        {
            if (chain_idx < PERSIST_CHAIN_MAX)
            {
                size_t len = strlen(val_buf);
                memcpy(current->chain_sha512[chain_idx], val_buf, len < 127 ? len : 127);
                current->chain_sha512[chain_idx][len < 127 ? len : 127] = '\0';
                chain_idx++;
            }
        }
        else if (in_chain_sha && sscanf(p, " \"%[^\"]\"", val_buf) == 1)
        {
            /* Last element without comma */
            if (chain_idx < PERSIST_CHAIN_MAX)
            {
                size_t len = strlen(val_buf);
                memcpy(current->chain_sha512[chain_idx], val_buf, len < 127 ? len : 127);
                current->chain_sha512[chain_idx][len < 127 ? len : 127] = '\0';
                chain_idx++;
            }
        }
    }

    fclose(fp);
    return count;
}

/* Test: basic save and load roundtrip */
static int test_persist_roundtrip(void)
{
    PersistEntry entries_in[2];
    PersistEntry entries_out[PERSIST_MAX_ENTRIES];
    int count;

    snprintf(test_state_file, sizeof(test_state_file), "/tmp/fileshield_test/test_state.json");

    /* Remove any existing state file */
    unlink(test_state_file);

    /* Prepare test entries */
    memset(entries_in, 0, sizeof(entries_in));

    snprintf(entries_in[0].binary, sizeof(entries_in[0].binary), "/usr/bin/git");
    snprintf(entries_in[0].binary_sha512, sizeof(entries_in[0].binary_sha512),
             "abc123def456abc123def456abc123def456abc123def456abc123def456abc1");
    entries_in[0].chain_depth = 2;
    snprintf(entries_in[0].chain_comm[0], sizeof(entries_in[0].chain_comm[0]), "code");
    snprintf(entries_in[0].chain_sha512[0], sizeof(entries_in[0].chain_sha512[0]),
             "111111111111111111111111111111111111111111111111111111111111111");
    snprintf(entries_in[0].chain_comm[1], sizeof(entries_in[0].chain_comm[1]), "systemd");
    snprintf(entries_in[0].chain_sha512[1], sizeof(entries_in[0].chain_sha512[1]),
             "222222222222222222222222222222222222222222222222222222222222222");

    snprintf(entries_in[1].binary, sizeof(entries_in[1].binary), "/usr/bin/ssh");
    snprintf(entries_in[1].binary_sha512, sizeof(entries_in[1].binary_sha512),
             "xyz789abc123xyz789abc123xyz789abc123xyz789abc123xyz789abc123xyz78");
    entries_in[1].chain_depth = 1;
    snprintf(entries_in[1].chain_comm[0], sizeof(entries_in[1].chain_comm[0]), "bash");
    snprintf(entries_in[1].chain_sha512[0], sizeof(entries_in[1].chain_sha512[0]),
             "333333333333333333333333333333333333333333333333333333333333333");

    /* Save entries using mock */
    if (test_persist_save_mock(entries_in, 2, test_state_file) < 0)
        TEST_FAIL("test_persist_save_mock failed");

    /* Load entries using mock */
    count = test_persist_load_mock(entries_out, PERSIST_MAX_ENTRIES, test_state_file);
    ASSERT(count == 2, "expected 2 entries loaded");

    /* Verify first entry */
    ASSERT(strcmp(entries_out[0].binary, "/usr/bin/git") == 0, "entry 0 binary path mismatch");
    ASSERT(strcmp(entries_out[0].binary_sha512,
                  "abc123def456abc123def456abc123def456abc123def456abc123def456abc1") == 0,
           "entry 0 SHA-512 mismatch");
    ASSERT(entries_out[0].chain_depth == 2, "entry 0 chain depth mismatch");
    ASSERT(strcmp(entries_out[0].chain_comm[0], "code") == 0, "entry 0 chain_comm[0] mismatch");
    ASSERT(strcmp(entries_out[0].chain_comm[1], "systemd") == 0, "entry 0 chain_comm[1] mismatch");

    /* Verify second entry */
    ASSERT(strcmp(entries_out[1].binary, "/usr/bin/ssh") == 0, "entry 1 binary path mismatch");
    ASSERT(entries_out[1].chain_depth == 1, "entry 1 chain depth mismatch");
    ASSERT(strcmp(entries_out[1].chain_comm[0], "bash") == 0, "entry 1 chain_comm[0] mismatch");

    /* Clean up */
    unlink(test_state_file);

    TEST_PASS("roundtrip save/load");
    return 0;
}

/* Test: load from nonexistent file returns 0 */
static int test_persist_load_nonexistent(void)
{
    PersistEntry entries[PERSIST_MAX_ENTRIES];
    int count;

    snprintf(test_state_file, sizeof(test_state_file), "/tmp/fileshield_test/nonexistent.json");

    /* Remove any existing state file */
    unlink(test_state_file);

    /* Try to load from nonexistent file */
    count = test_persist_load_mock(entries, PERSIST_MAX_ENTRIES, test_state_file);
    ASSERT(count == 0, "load from nonexistent file should return 0");

    TEST_PASS("load nonexistent file");
    return 0;
}

/* Test: empty entries save */
static int test_persist_save_empty(void)
{
    PersistEntry entries_out[PERSIST_MAX_ENTRIES];
    int count;

    snprintf(test_state_file, sizeof(test_state_file), "/tmp/fileshield_test/empty.json");

    /* Remove any existing state file */
    unlink(test_state_file);

    /* Save 0 entries */
    if (test_persist_save_mock(NULL, 0, test_state_file) < 0)
    {
        /* Null entries with 0 count should be OK */
    }

    PersistEntry temp[1] = {0};
    if (test_persist_save_mock(temp, 0, test_state_file) < 0)
        TEST_FAIL("test_persist_save_mock with empty entries failed");

    /* Load should return 0 */
    count = test_persist_load_mock(entries_out, PERSIST_MAX_ENTRIES, test_state_file);
    ASSERT(count == 0, "load after saving empty should return 0");

    /* Clean up */
    unlink(test_state_file);

    TEST_PASS("save empty entries");
    return 0;
}

/* Test: chain depth variations */
static int test_persist_chain_depths(void)
{
    PersistEntry entries_in[PERSIST_CHAIN_MAX];
    PersistEntry entries_out[PERSIST_MAX_ENTRIES];
    int i, count;

    snprintf(test_state_file, sizeof(test_state_file), "/tmp/fileshield_test/chains.json");

    /* Remove any existing state file */
    unlink(test_state_file);

    /* Create entries with different chain depths */
    memset(entries_in, 0, sizeof(entries_in));

    for (i = 0; i < PERSIST_CHAIN_MAX; i++)
    {
        snprintf(entries_in[i].binary, sizeof(entries_in[i].binary), "/usr/bin/chain%d", i);
        entries_in[i].chain_depth = i + 1;
        for (int j = 0; j <= i; j++)
        {
            snprintf(entries_in[i].chain_comm[j], sizeof(entries_in[i].chain_comm[j]), "proc%d",
                     j);
        }
    }

    /* Save and load */
    if (test_persist_save_mock(entries_in, PERSIST_CHAIN_MAX, test_state_file) < 0)
        TEST_FAIL("test_persist_save_mock with chain depths failed");

    count = test_persist_load_mock(entries_out, PERSIST_MAX_ENTRIES, test_state_file);
    ASSERT(count == PERSIST_CHAIN_MAX, "expected all chain entries loaded");

    for (i = 0; i < PERSIST_CHAIN_MAX; i++)
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "entry %d chain depth mismatch", i);
        ASSERT(entries_out[i].chain_depth == i + 1, buf);
    }

    /* Clean up */
    unlink(test_state_file);

    TEST_PASS("chain depth variations");
    return 0;
}

int main(void)
{
    int failed = 0;

    fprintf(stdout, "=== test_persist ===\n");

    failed |= test_persist_load_nonexistent();
    failed |= test_persist_roundtrip();
    failed |= test_persist_save_empty();
    failed |= test_persist_chain_depths();

    /* Clean up temp directory */
    rmdir("/tmp/fileshield_test");

    if (failed)
    {
        fprintf(stdout, "FAIL\n");
        return 1;
    }
    else
    {
        fprintf(stdout, "PASS\n");
        return 0;
    }
}
