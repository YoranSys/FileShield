#ifndef FILESHIELD_PERSIST_H
#define FILESHIELD_PERSIST_H

#include <sys/types.h>
#include <limits.h>

#define PERSIST_MAX_ENTRIES 256
#define PERSIST_CHAIN_MAX 3
#define PERSIST_STATE_DIR "/var/lib/fileshield"
#define PERSIST_STATE_FILE PERSIST_STATE_DIR "/runtime-allowlist.json"
#define PERSIST_DENY_STATE_FILE PERSIST_STATE_DIR "/runtime-denylist.json"

/*
 * Persistent runtime allowlist entry: mirrors a DynAllowEntry from fanotify.c
 * but is meant to be serialized to JSON and reloaded on daemon restart.
 */
typedef struct
{
    char binary[PATH_MAX];
    char binary_sha512[129];
    char target_path[PATH_MAX];
    char chain_comm[PERSIST_CHAIN_MAX][256];
    char chain_sha512[PERSIST_CHAIN_MAX][129];
    int chain_depth;
    time_t created_at;
} PersistEntry;

/*
 * Public API: load and save persistent entries
 */

/* Load persisted entries from JSON file. Returns count of entries loaded, or -1 on error. */
int persist_load(const char *filepath, PersistEntry *out_entries, int max_entries);

/* Save entries to JSON file. Returns 0 on success, -1 on error. */
int persist_save(const char *filepath, const PersistEntry *entries, int count);

/* Delete a persistent state file. Used on daemon cleanup. */
int persist_delete(const char *filepath);

/*
 * Remove one entry from a persist JSON file, matched by binary path
 * and SHA-512 hash.  Returns 0 on success, 1 if no matching entry
 * was found, -1 on error.
 */
int persist_remove_key(const char *filepath, const char *binary,
                       const char *binary_sha512);

#endif
