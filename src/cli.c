#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>

#include "persist.h"

#define CLI_VERSION "1.0.0"

static void print_usage(FILE *f, const char *prog)
{
    fprintf(f,
            "Usage: %s <command> [options]\n"
            "\n"
            "Commands:\n"
            "  list [allow|deny]         List entries (default: both)\n"
            "  remove allow|deny BINARY SHA512\n"
            "                            Remove one entry by key\n"
            "  clear allow|deny           Delete all entries\n"
            "  -h, --help                 Show this help\n"
            "  -v, --version              Show version\n"
            "\n"
            "State files:\n"
            "  " PERSIST_STATE_FILE "\n"
            "  " PERSIST_DENY_STATE_FILE "\n"
            "\n"
            "After changes, reload the daemon:\n"
            "  systemctl reload fileshield\n",
            prog);
}

/*
 * Print a 16-char SHA-512 fingerprint.
 */
static const char *sha_finger(const char *sha512)
{
    static char buf[17];
    if (!sha512 || !sha512[0])
        return "N/A";
    memcpy(buf, sha512, 16);
    buf[16] = '\0';
    return buf;
}

/*
 * Format the call chain as "comm1 -> comm2 -> comm3" (skipping empty).
 */
static void print_chain(const PersistEntry *e)
{
    int printed = 0;
    for (int i = 0; i < e->chain_depth && i < PERSIST_CHAIN_MAX; i++)
    {
        if (e->chain_comm[i][0])
        {
            if (printed) printf(" -> ");
            printf("%s", e->chain_comm[i]);
            printed = 1;
        }
    }
    if (!printed)
        printf("(none)");
}

/*
 * Format a time_t as "YYYY-MM-DD" into a static buffer.
 */
static const char *fmt_date(time_t t)
{
    static char buf[16];
    if (t == 0)
        return "N/A";
    struct tm tm_buf;
    if (!localtime_r(&t, &tm_buf))
        return "N/A";
    strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_buf);
    return buf;
}

/*
 * Print one list with a header.
 */
static void print_list(const char *label, const char *filepath)
{
    PersistEntry entries[PERSIST_MAX_ENTRIES];

    int count = persist_load(filepath, entries, PERSIST_MAX_ENTRIES);
    if (count < 0)
    {
        fprintf(stderr, "Error reading %s\n", filepath);
        return;
    }

    printf("=== %s (%s) ===\n", label, filepath);
    printf("Total entries: %d\n\n", count);

    if (count == 0)
    {
        printf("(empty)\n\n");
        return;
    }

    printf(" %-3s %-20s %-18s %-8s %-10s %-30s %s\n",
           "ID", "Binary", "SHA-512", "Depth", "Created", "Target", "Call chain");
    printf(" %-3s %-20s %-18s %-8s %-10s %-30s %s\n",
           "---", "------------------", "------------------",
           "-----", "--------", "-----------------------------", "--------------------");

    for (int i = 0; i < count; i++)
    {
        const PersistEntry *e = &entries[i];
        /* Truncate binary path to 20 chars for the column. */
        const char *bin = e->binary;
        size_t bin_len = strlen(bin);
        /* Truncate target path to 30 chars for the column. */
        const char *targ = e->target_path;
        char targ_display[31];
        if (targ[0] == '\0')
            snprintf(targ_display, sizeof(targ_display), "(any)");
        else if (strlen(targ) > 29)
        {
            memcpy(targ_display, "~", 1);
            memcpy(targ_display + 1, targ + strlen(targ) - 29, 29);
            targ_display[30] = '\0';
        }
        else
            snprintf(targ_display, sizeof(targ_display), "%s", targ);
        if (bin_len > 19)
        {
            const char *bin_display = bin + bin_len - 19;
            printf(" %-2d ~%-19s %-18s %-8d %-10s %-30s ",
                   i, bin_display, sha_finger(e->binary_sha512),
                   e->chain_depth, fmt_date(e->created_at), targ_display);
        }
        else
        {
            printf(" %-2d %-20s %-18s %-8d %-10s %-30s ",
                   i, bin, sha_finger(e->binary_sha512),
                   e->chain_depth, fmt_date(e->created_at), targ_display);
        }
        print_chain(e);
        printf("\n");
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    static struct option long_opts[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "hv", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'h':
            print_usage(stdout, argv[0]);
            return 0;
        case 'v':
            printf("fileshield-cli %s\n", CLI_VERSION);
            return 0;
        default:
            print_usage(stderr, argv[0]);
            return 1;
        }
    }

    if (optind >= argc)
    {
        print_usage(stderr, argv[0]);
        return 1;
    }

    const char *cmd = argv[optind++];

    /* ── list ── */
    if (strcmp(cmd, "list") == 0)
    {
        int show_allow = 1, show_deny = 1;

        if (optind < argc)
        {
            if (strcmp(argv[optind], "allow") == 0)
                show_deny = 0;
            else if (strcmp(argv[optind], "deny") == 0)
                show_allow = 0;
            else
            {
                fprintf(stderr, "Unknown filter: %s (expected allow|deny)\n",
                        argv[optind]);
                return 1;
            }
        }

        if (show_allow)
            print_list("Allowlist", PERSIST_STATE_FILE);
        if (show_deny)
            print_list("Denylist", PERSIST_DENY_STATE_FILE);
        return 0;
    }

    /* ── remove ── */
    if (strcmp(cmd, "remove") == 0)
    {
        if (optind + 2 >= argc)
        {
            fprintf(stderr,
                    "Usage: %s remove allow|deny <binary> <sha512>\n",
                    argv[0]);
            return 1;
        }

        const char *type = argv[optind++];
        const char *binary = argv[optind++];
        const char *sha512 = argv[optind++];

        const char *filepath;
        const char *label;

        if (strcmp(type, "allow") == 0)
        {
            filepath = PERSIST_STATE_FILE;
            label = "allowlist";
        }
        else if (strcmp(type, "deny") == 0)
        {
            filepath = PERSIST_DENY_STATE_FILE;
            label = "denylist";
        }
        else
        {
            fprintf(stderr, "Unknown type: %s (expected allow|deny)\n", type);
            return 1;
        }

        int r = persist_remove_key(filepath, binary, sha512);
        if (r < 0)
        {
            fprintf(stderr, "Error: failed to update %s\n", label);
            return 1;
        }
        if (r == 1)
        {
            fprintf(stderr,
                    "No matching entry in %s for binary=%s sha512=%s\n",
                    label, binary, sha512);
            return 1;
        }

        printf("Removed entry from %s:\n", label);
        printf("  binary:  %s\n", binary);
        printf("  sha512:  %s\n", sha512);
        printf("\nRun 'systemctl reload fileshield' to apply changes.\n");
        return 0;
    }

    /* ── clear ── */
    if (strcmp(cmd, "clear") == 0)
    {
        if (optind >= argc)
        {
            fprintf(stderr,
                    "Usage: %s clear allow|deny\n", argv[0]);
            return 1;
        }

        const char *type = argv[optind++];
        const char *filepath;
        const char *label;

        if (strcmp(type, "allow") == 0)
        {
            filepath = PERSIST_STATE_FILE;
            label = "allowlist";
        }
        else if (strcmp(type, "deny") == 0)
        {
            filepath = PERSIST_DENY_STATE_FILE;
            label = "denylist";
        }
        else
        {
            fprintf(stderr, "Unknown type: %s (expected allow|deny)\n", type);
            return 1;
        }

        /* Check if file exists before trying to delete. */
        FILE *fp = fopen(filepath, "r");
        if (!fp && errno == ENOENT)
        {
            printf("%s is already empty.\n", label);
            return 0;
        }
        if (fp)
            fclose(fp);

        if (persist_delete(filepath) < 0)
        {
            fprintf(stderr, "Error: failed to clear %s\n", label);
            return 1;
        }

        printf("Cleared entire %s.\n", label);
        printf("Run 'systemctl reload fileshield' to apply changes.\n");
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    print_usage(stderr, argv[0]);
    return 1;
}
