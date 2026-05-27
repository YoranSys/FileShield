#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <signal.h>
#include <syslog.h>

#include "fanotify.h"
#include "utils.h"
#include "config.h"
#include "cache.h"
#include "notify.h"
#include "sha512.h"
#include "persist.h"

extern volatile sig_atomic_t g_running;
extern volatile sig_atomic_t g_need_reload;
extern Config *g_config;

#define BUF_SIZE 4096

/* ------------------------------------------------------------------ */
/*  proc helpers                                                       */
/* ------------------------------------------------------------------ */

static pid_t get_ppid(pid_t pid)
{
    char path[64], line[256];
    FILE *f;
    pid_t ppid = 0;

    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    f = fopen(path, "r");
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f))
    {
        if (sscanf(line, "PPid:\t%d", &ppid) == 1)
            break;
    }
    fclose(f);
    return ppid;
}

static int read_comm(pid_t pid, char *out, size_t size)
{
    char path[64];
    FILE *f;
    size_t len;

    snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
    f = fopen(path, "r");
    if (!f)
        return -1;
    if (!fgets(out, (int)size, f))
    {
        fclose(f);
        return -1;
    }
    fclose(f);
    len = strlen(out);
    if (len > 0 && out[len - 1] == '\n')
        out[len - 1] = '\0';
    return 0;
}

/*
 * Resolve the path of a fanotify event fd.
 * ev->fd is an open fd in the DAEMON's fd table (not the target process's).
 * We must read /proc/self/fd/<fd_num>, not /proc/<target_pid>/fd/<fd_num>.
 */
static char *resolve_fd_path(int fd_num)
{
    char link[64];
    char *buf;
    ssize_t len;

    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd_num);
    buf = malloc(PATH_MAX);
    if (!buf)
        return NULL;
    len = readlink(link, buf, PATH_MAX - 1);
    if (len < 0)
    {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}

/*
 * Read /proc/<pid>/cmdline and collapse null separators into spaces.
 * Returns the number of bytes written (excluding the terminating '\0'),
 * or -1 on error.
 */
static int read_cmdline(pid_t pid, char *out, size_t size)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
    int fd_c = open(path, O_RDONLY);
    if (fd_c < 0)
        return -1;

    ssize_t n = read(fd_c, out, size - 1);
    close(fd_c);
    if (n <= 0)
        return -1;

    /* Replace every embedded NUL with a space, except the last one. */
    for (ssize_t i = 0; i < n - 1; i++)
        if (out[i] == '\0')
            out[i] = ' ';
    out[n] = '\0';
    /* Trim any trailing space left by the last NUL. */
    while (n > 0 && out[n - 1] == ' ')
        out[--n] = '\0';
    return (int)n;
}

static int allowlist_match(const char *binary, int *ttl_out)
{
    int i;
    if (!g_config)
        return 0;
    for (i = 0; i < g_config->allowlist_count; i++)
    {
        if (strcmp(g_config->allowlist[i].binary, binary) == 0)
        {
            *ttl_out = g_config->allowlist[i].ttl_seconds;
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  process call-chain (parent → grandparent → great-grandparent)     */
/* ------------------------------------------------------------------ */

typedef struct
{
    pid_t pid[PERSIST_CHAIN_MAX];
    char comm[PERSIST_CHAIN_MAX][256];
    char exe[PERSIST_CHAIN_MAX][PATH_MAX];
    char sha512[PERSIST_CHAIN_MAX][129]; /* lowercase hex SHA-512 of each ancestor exe */
    int depth;                           /* how many ancestors were captured            */
} ProcChain;

static void build_proc_chain(pid_t start_pid, ProcChain *c)
{
    memset(c, 0, sizeof(*c));
    pid_t cur = start_pid;
    for (int i = 0; i < PERSIST_CHAIN_MAX; i++)
    {
        pid_t p = get_ppid(cur);
        if (p <= 1)
            break;
        c->pid[i] = p;
        read_comm(p, c->comm[i], sizeof(c->comm[i]));
        char *exe = proc_exe_path(p);
        if (exe)
        {
            snprintf(c->exe[i], sizeof(c->exe[i]), "%s", exe);
            free(exe);
        }
        /* Hash via /proc/<pid>/exe so containerised binaries (Podman/Docker)
         * are reachable even if their path doesn't exist on the host. */
        sha512_proc_exe(p, c->sha512[i]); /* best-effort; empty on failure */
        c->depth = i + 1;
        cur = p;
    }
}

/* ------------------------------------------------------------------ */
/*  runtime dynamic allowlist / denylist ("Always" decisions)         */
/* ------------------------------------------------------------------ */

#define DYN_MAX 256

typedef struct
{
    char binary[PATH_MAX];
    char binary_sha512[129];
    char target_path[PATH_MAX]; /* audit only — not used for matching */
    char chain_comm[PERSIST_CHAIN_MAX][256];
    char chain_sha512[PERSIST_CHAIN_MAX][129];
    int chain_depth;
} DynEntry;

static DynEntry g_dyn_allow[DYN_MAX];
static int g_dyn_allow_count = 0;

static DynEntry g_dyn_deny[DYN_MAX];
static int g_dyn_deny_count = 0;

/* ------------------------------------------------------------------ */
/*  shared persistence helpers for allowlist / denylist               */
/* ------------------------------------------------------------------ */

/* Copy a DynEntry array to PersistEntry and write to disk. */
static void persist_dyn_list(const char *filepath, const DynEntry *entries,
                             int count, const char *name)
{
    PersistEntry *buf = calloc(DYN_MAX, sizeof(PersistEntry));
    if (!buf)
    {
        log_msg(LOG_ERR, "out of memory persisting %s", name);
        return;
    }
    for (int i = 0; i < count; i++)
    {
        const DynEntry *src = &entries[i];
        PersistEntry *dst = &buf[i];
        memcpy(dst->binary, src->binary, sizeof(src->binary));
        dst->binary[sizeof(dst->binary) - 1] = '\0';
        memcpy(dst->binary_sha512, src->binary_sha512, sizeof(src->binary_sha512));
        dst->binary_sha512[sizeof(dst->binary_sha512) - 1] = '\0';
        memcpy(dst->target_path, src->target_path, sizeof(src->target_path));
        dst->target_path[sizeof(dst->target_path) - 1] = '\0';
        dst->chain_depth = src->chain_depth;
        for (int j = 0; j < src->chain_depth; j++)
        {
            memcpy(dst->chain_comm[j], src->chain_comm[j], sizeof(src->chain_comm[j]));
            dst->chain_comm[j][sizeof(dst->chain_comm[j]) - 1] = '\0';
            memcpy(dst->chain_sha512[j], src->chain_sha512[j], sizeof(src->chain_sha512[j]));
            dst->chain_sha512[j][sizeof(dst->chain_sha512[j]) - 1] = '\0';
        }
        dst->created_at = time(NULL);
    }
    if (persist_save(filepath, buf, count) < 0)
        log_msg(LOG_WARNING, "persist_save failed; %s entry not persisted", name);
    free(buf);
}

/* Copy DynEntry entries into a PersistEntry array.  Returns count. */
static int dyn_to_persist(const DynEntry *entries, int count,
                          PersistEntry *out, int max)
{
    int n = count < max ? count : max;
    memset(out, 0, sizeof(*out) * max);
    for (int i = 0; i < n; i++)
    {
        const DynEntry *src = &entries[i];
        PersistEntry *dst = &out[i];
        memcpy(dst->binary, src->binary, sizeof(src->binary));
        dst->binary[sizeof(dst->binary) - 1] = '\0';
        memcpy(dst->binary_sha512, src->binary_sha512, sizeof(src->binary_sha512));
        dst->binary_sha512[sizeof(dst->binary_sha512) - 1] = '\0';
        memcpy(dst->target_path, src->target_path, sizeof(src->target_path));
        dst->target_path[sizeof(dst->target_path) - 1] = '\0';
        dst->chain_depth = src->chain_depth;
        for (int j = 0; j < src->chain_depth; j++)
        {
            memcpy(dst->chain_comm[j], src->chain_comm[j], sizeof(src->chain_comm[j]));
            dst->chain_comm[j][sizeof(dst->chain_comm[j]) - 1] = '\0';
            memcpy(dst->chain_sha512[j], src->chain_sha512[j], sizeof(src->chain_sha512[j]));
            dst->chain_sha512[j][sizeof(dst->chain_sha512[j]) - 1] = '\0';
        }
    }
    return n;
}

/* Load PersistEntry entries into a DynEntry array. */
static void load_dyn_list(DynEntry *list, int *list_count,
                          const PersistEntry *entries, int count,
                          const char *name)
{
    if (!entries || count <= 0 || count > DYN_MAX)
        return;
    memset(list, 0, sizeof(DynEntry) * DYN_MAX);
    *list_count = 0;
    for (int i = 0; i < count; i++)
    {
        const PersistEntry *src = &entries[i];
        DynEntry *dst = &list[i];
        snprintf(dst->binary, sizeof(dst->binary), "%s", src->binary);
        snprintf(dst->binary_sha512, sizeof(dst->binary_sha512), "%s", src->binary_sha512);
        snprintf(dst->target_path, sizeof(dst->target_path), "%s", src->target_path);
        int depth = src->chain_depth;
        if (depth > PERSIST_CHAIN_MAX)
            depth = PERSIST_CHAIN_MAX;
        dst->chain_depth = depth;
        for (int j = 0; j < depth; j++)
        {
            snprintf(dst->chain_comm[j], sizeof(dst->chain_comm[j]), "%s", src->chain_comm[j]);
            snprintf(dst->chain_sha512[j], sizeof(dst->chain_sha512[j]), "%s", src->chain_sha512[j]);
        }
    }
    *list_count = count;
    log_msg(LOG_INFO, "loaded %d persisted %s entries", count, name);
}

/* ------------------------------------------------------------------ */
/*  runtime matching functions                                        */
/* ------------------------------------------------------------------ */

/*
 * dyn_allow_match: returns 1 if (binary, bin_sha512, chain) matches a stored
 * "Always Allow" entry, 0 otherwise.
 *
 * Note: target_path is NOT checked during matching -- an "Always Allow"
 * entry grants access to ALL protected files for this binary+chain, not
 * just the file that originally triggered the dialog.  target_path is
 * stored for audit visibility only.
 *
 * Matching rules (fail-secure):
 *   - Binary path must match.
 *   - If both sides have a SHA-512, they must be equal.
 *   - If the stored entry has a SHA-512 but we failed to compute one now
 *     (sha512sum unavailable?), we DENY -- we cannot verify integrity.
 *   - Call-chain depth must match exactly.
 *   - For each ancestor: comm must match AND, if both sides have a SHA-512,
 *     they must be equal; if stored has one but current is missing, DENY.
 */
static int dyn_allow_match(const char *binary, const char *bin_sha512,
                           const ProcChain *chain)
{
    for (int i = 0; i < g_dyn_allow_count; i++)
    {
        DynEntry *e = &g_dyn_allow[i];

        if (strcmp(e->binary, binary) != 0)
            continue;

        /* SHA-512 check on the binary itself. */
        if (e->binary_sha512[0] != '\0')
        {
            if (bin_sha512[0] == '\0') /* couldn't hash it now — fail secure */
                continue;
            if (strcmp(e->binary_sha512, bin_sha512) != 0)
                continue;
        }

        if (e->chain_depth != chain->depth)
            continue;

        int ok = 1;
        for (int j = 0; j < chain->depth; j++)
        {
            if (strcmp(e->chain_comm[j], chain->comm[j]) != 0)
            {
                ok = 0;
                break;
            }
            if (e->chain_sha512[j][0] != '\0')
            {
                if (chain->sha512[j][0] == '\0') /* can't verify — fail secure */
                {
                    ok = 0;
                    break;
                }
                if (strcmp(e->chain_sha512[j], chain->sha512[j]) != 0)
                {
                    ok = 0;
                    break;
                }
            }
        }
        if (ok)
            return 1;
    }
    return 0;
}

static void dyn_allow_add(const char *binary, const char *bin_sha512,
                          const ProcChain *chain, const char *target)
{
    if (g_dyn_allow_count >= DYN_MAX)
    {
        log_msg(LOG_WARNING, "dynamic allowlist full (%d); dropping oldest entry",
                DYN_MAX);
        memmove(&g_dyn_allow[0], &g_dyn_allow[1],
                sizeof(DynEntry) * (DYN_MAX - 1));
        g_dyn_allow_count = DYN_MAX - 1;
    }

    DynEntry *e = &g_dyn_allow[g_dyn_allow_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->binary, sizeof(e->binary), "%s", binary);
    snprintf(e->binary_sha512, sizeof(e->binary_sha512), "%s", bin_sha512);
    if (target)
        snprintf(e->target_path, sizeof(e->target_path), "%s", target);
    e->chain_depth = chain->depth;
    for (int i = 0; i < chain->depth; i++)
    {
        snprintf(e->chain_comm[i], sizeof(e->chain_comm[i]), "%s", chain->comm[i]);
        snprintf(e->chain_sha512[i], sizeof(e->chain_sha512[i]), "%s", chain->sha512[i]);
    }

    char sha_short[17] = "????????????????";
    if (bin_sha512[0] != '\0')
        memcpy(sha_short, bin_sha512, 16);
    sha_short[16] = '\0';
    log_msg(LOG_INFO,
            "always-allow added: %s (sha512: %s...) chain-depth=%d -> %s",
            binary, sha_short, chain->depth, target ? target : "(unknown)");

    persist_dyn_list(PERSIST_STATE_FILE, g_dyn_allow, g_dyn_allow_count,
                     "allowlist");
}

/*
 * dyn_deny_match: returns 1 if (binary, bin_sha512, chain) matches a stored
 * "Always Deny" entry, 0 otherwise.
 *
 * Note: target_path is NOT checked during matching (audit-only; see
 * dyn_allow_match for rationale).
 *
 * Matching rules (fail-open for denial safety):
 *   - Binary path must match.
 *   - If both sides have a SHA-512, they must be equal.
 *   - If the stored entry has a SHA-512 but the current binary's hash
 *     cannot be computed (e.g., sha512sum missing), we skip the entry
 *     (do NOT deny) — we cannot verify the binary is the one that was
 *     supposed to be blocked.  The user will be re-prompted instead.
 *   - Call-chain depth must match exactly.
 *   - For each ancestor: comm must match AND, if both sides have a SHA-512,
 *     they must be equal; if stored has one but current is missing, skip
 *     (preserve allow — we cannot verify the ancestor).
 */
static int dyn_deny_match(const char *binary, const char *bin_sha512,
                          const ProcChain *chain)
{
    for (int i = 0; i < g_dyn_deny_count; i++)
    {
        DynEntry *e = &g_dyn_deny[i];

        if (strcmp(e->binary, binary) != 0)
            continue;

        if (e->binary_sha512[0] != '\0')
        {
            if (bin_sha512[0] == '\0')
                continue;
            if (strcmp(e->binary_sha512, bin_sha512) != 0)
                continue;
        }

        if (e->chain_depth != chain->depth)
            continue;

        int ok = 1;
        for (int j = 0; j < chain->depth; j++)
        {
            if (strcmp(e->chain_comm[j], chain->comm[j]) != 0)
            {
                ok = 0;
                break;
            }
            if (e->chain_sha512[j][0] != '\0')
            {
                if (chain->sha512[j][0] == '\0')
                {
                    ok = 0;
                    break;
                }
                if (strcmp(e->chain_sha512[j], chain->sha512[j]) != 0)
                {
                    ok = 0;
                    break;
                }
            }
        }
        if (ok)
            return 1;
    }
    return 0;
}

static void dyn_deny_add(const char *binary, const char *bin_sha512,
                         const ProcChain *chain, const char *target)
{
    if (g_dyn_deny_count >= DYN_MAX)
    {
        log_msg(LOG_WARNING, "dynamic denylist full (%d); dropping oldest entry",
                DYN_MAX);
        memmove(&g_dyn_deny[0], &g_dyn_deny[1],
                sizeof(DynEntry) * (DYN_MAX - 1));
        g_dyn_deny_count = DYN_MAX - 1;
    }

    DynEntry *e = &g_dyn_deny[g_dyn_deny_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->binary, sizeof(e->binary), "%s", binary);
    snprintf(e->binary_sha512, sizeof(e->binary_sha512), "%s", bin_sha512);
    if (target)
        snprintf(e->target_path, sizeof(e->target_path), "%s", target);
    e->chain_depth = chain->depth;
    for (int i = 0; i < chain->depth; i++)
    {
        snprintf(e->chain_comm[i], sizeof(e->chain_comm[i]), "%s", chain->comm[i]);
        snprintf(e->chain_sha512[i], sizeof(e->chain_sha512[i]), "%s", chain->sha512[i]);
    }

    char sha_short[17] = "????????????????";
    if (bin_sha512[0] != '\0')
        memcpy(sha_short, bin_sha512, 16);
    sha_short[16] = '\0';
    log_msg(LOG_INFO,
            "always-deny added: %s (sha512: %s...) chain-depth=%d -> %s",
            binary, sha_short, chain->depth, target ? target : "(unknown)");

    persist_dyn_list(PERSIST_DENY_STATE_FILE, g_dyn_deny, g_dyn_deny_count,
                     "denylist");
}

/* ------------------------------------------------------------------ */
/*  Protected inode table  (hard-link bypass detection)               */
/* ------------------------------------------------------------------ */

typedef struct
{
    dev_t dev;
    ino_t ino;
} ProtectedInode;

#define MAX_INODE_TABLE (MAX_PATHS * 32)
#define MAX_INODE_WALK_DEPTH 8 /* max recursion depth for protected-directory inode enumeration */
static ProtectedInode g_inode_table[MAX_INODE_TABLE];
static int g_inode_count = 0;

/* One FAN_MARK_MOUNT per unique filesystem device */
#define MAX_MOUNTS 32
typedef struct
{
    dev_t dev;
    char path[PATH_MAX]; /* any path on that mount, used for mark removal */
} MountEntry;
static MountEntry g_mounts[MAX_MOUNTS];
static int g_mount_count = 0;

static void inode_table_add(dev_t dev, ino_t ino)
{
    for (int i = 0; i < g_inode_count; i++)
        if (g_inode_table[i].dev == dev && g_inode_table[i].ino == ino)
            return;
    if (g_inode_count >= MAX_INODE_TABLE)
    {
        log_msg(LOG_WARNING, "inode table full; hard-link detection may be incomplete");
        return;
    }
    g_inode_table[g_inode_count].dev = dev;
    g_inode_table[g_inode_count].ino = ino;
    g_inode_count++;
}

static int inode_is_protected(dev_t dev, ino_t ino)
{
    for (int i = 0; i < g_inode_count; i++)
        if (g_inode_table[i].dev == dev && g_inode_table[i].ino == ino)
            return 1;
    return 0;
}

/* Recursively walk a directory and add inodes of all regular files.
 * Stays on the same device (no cross-mount traversal).
 * Depth is capped at MAX_INODE_WALK_DEPTH to bound worst-case traversal time. */
static void inode_walk_dir(const char *dirpath, dev_t dev, int depth)
{
    if (depth > MAX_INODE_WALK_DEPTH)
        return;
    DIR *d = opendir(dirpath);
    if (!d)
    {
        log_msg(LOG_WARNING, "inode_walk_dir: cannot open %s: %s", dirpath,
                strerror(errno));
        return;
    }
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL)
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[PATH_MAX];
        if (snprintf(child, sizeof(child), "%s/%s", dirpath, ent->d_name) >= (int)sizeof(child))
            continue;
        struct stat st;
        if (lstat(child, &st) != 0)
            continue;
        if (st.st_dev != dev) /* skip bind mounts / nested filesystems */
            continue;
        if (S_ISREG(st.st_mode))
            inode_table_add(st.st_dev, st.st_ino);
        else if (S_ISDIR(st.st_mode))
            inode_walk_dir(child, dev, depth + 1);
    }
    closedir(d);
}

/*
 * Returns 1 if `path` falls under any currently protected path.
 * Used to distinguish events from directory marks vs. mount marks (hard-link).
 */
static int is_path_under_protected(const char *path)
{
    if (!g_config)
        return 0;
    for (int i = 0; i < g_config->protected_count; i++)
    {
        const char *p = g_config->protected[i].path;
        size_t plen = strlen(p);
        if (strncmp(path, p, plen) == 0)
        {
            if (path[plen] == '\0' || path[plen] == '/' || p[plen - 1] == '/')
                return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  public API                                                         */
/* ------------------------------------------------------------------ */

int fanotify_setup(void)
{
    int fd = fanotify_init(FAN_CLASS_CONTENT | FAN_UNLIMITED_QUEUE,
                           O_RDONLY | O_LARGEFILE);
    if (fd < 0)
    {
        log_msg(LOG_ERR, "fanotify_init: %s", strerror(errno));
        return -1;
    }
    log_msg(LOG_INFO, "fanotify fd %d created", fd);
    return fd;
}

int fanotify_add_mark(int fd, const char *path)
{
    if (fanotify_mark(fd, FAN_MARK_ADD,
                      FAN_OPEN_PERM | FAN_EVENT_ON_CHILD,
                      AT_FDCWD, path) < 0)
    {
        log_msg(LOG_ERR, "fanotify_mark ADD %s: %s", path, strerror(errno));
        return -1;
    }
    log_msg(LOG_INFO, "fanotify mark added: %s", path);

    /* Populate the inode table so hard-link accesses are detected even when
     * the attacker opens the file via a path outside our watched directories. */
    struct stat st;
    if (stat(path, &st) == 0)
    {
        if (S_ISREG(st.st_mode))
            inode_table_add(st.st_dev, st.st_ino);
        else if (S_ISDIR(st.st_mode))
            inode_walk_dir(path, st.st_dev, 0);

        /* Add a FAN_MARK_MOUNT for this filesystem if not already tracked.
         * The mount mark fires for every open on the filesystem; the inode
         * table is used as a fast filter so non-protected opens are allowed
         * with minimal overhead. */
        int found = 0;
        for (int i = 0; i < g_mount_count; i++)
        {
            if (g_mounts[i].dev == st.st_dev)
            {
                found = 1;
                break;
            }
        }
        if (!found && g_mount_count < MAX_MOUNTS)
        {
            if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                              FAN_OPEN_PERM, AT_FDCWD, path) == 0)
            {
                g_mounts[g_mount_count].dev = st.st_dev;
                snprintf(g_mounts[g_mount_count].path,
                         sizeof(g_mounts[g_mount_count].path), "%s", path);
                g_mount_count++;
                log_msg(LOG_INFO, "fanotify mount mark added (dev %lu) for hard-link detection",
                        (unsigned long)st.st_dev);
            }
            else
            {
                log_msg(LOG_WARNING,
                        "fanotify mount mark failed for %s: %s "
                        "(hard-link detection disabled for this filesystem)",
                        path, strerror(errno));
            }
        }
    }
    else
    {
        log_msg(LOG_WARNING, "stat(%s) failed: %s (hard-link detection unavailable for this path)",
                path, strerror(errno));
    }

    return 0;
}

int fanotify_remove_mark(int fd, const char *path)
{
    if (fanotify_mark(fd, FAN_MARK_REMOVE,
                      FAN_OPEN_PERM | FAN_EVENT_ON_CHILD,
                      AT_FDCWD, path) < 0)
    {
        log_msg(LOG_ERR, "fanotify_mark REMOVE %s: %s", path, strerror(errno));
        return -1;
    }
    log_msg(LOG_INFO, "fanotify mark removed: %s", path);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Recent-decision deduplication cache                               */
/* ------------------------------------------------------------------ */
/*
 * When both a directory mark and a mount mark are active, the kernel fires
 * two separate FAN_OPEN_PERM events for the same file open (one per mark).
 * The cache records the (pid, dev, ino) → decision for the most recent
 * RECENT_CACHE_MAX events so the second identical event is resolved
 * instantly without showing a second dialog.
 *
 * Entries expire after RECENT_CACHE_TTL_MS milliseconds.
 */
#define RECENT_CACHE_MAX 32
#define RECENT_CACHE_TTL_MS 2000

typedef struct
{
    pid_t pid;
    dev_t dev;
    ino_t ino;
    int fan_decision; /* FAN_ALLOW or FAN_DENY */
    struct timespec ts;
} RecentDecision;

static RecentDecision g_recent[RECENT_CACHE_MAX];
static int g_recent_count = 0;
static int g_recent_head = 0; /* ring-buffer write head */

static void recent_cache_insert(pid_t pid, dev_t dev, ino_t ino, int decision)
{
    int slot = g_recent_head % RECENT_CACHE_MAX;
    g_recent[slot].pid = pid;
    g_recent[slot].dev = dev;
    g_recent[slot].ino = ino;
    g_recent[slot].fan_decision = decision;
    clock_gettime(CLOCK_MONOTONIC, &g_recent[slot].ts);
    g_recent_head++;
    if (g_recent_count < RECENT_CACHE_MAX)
        g_recent_count++;
}

/* Returns FAN_ALLOW, FAN_DENY, or -1 (not found / expired). */
static int recent_cache_lookup(pid_t pid, dev_t dev, ino_t ino)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    for (int i = 0; i < g_recent_count; i++)
    {
        RecentDecision *e = &g_recent[i];
        if (e->pid != pid || e->dev != dev || e->ino != ino)
            continue;
        long age_ms = (now.tv_sec - e->ts.tv_sec) * 1000L + (now.tv_nsec - e->ts.tv_nsec) / 1000000L;
        if (age_ms > RECENT_CACHE_TTL_MS)
            return -1; /* expired */
        return e->fan_decision;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  fanotify_pump: drain pending events while dialog child is running */
/* ------------------------------------------------------------------ */
/*
 * Called by notify.c in a poll loop while waiting for the dialog child.
 * Reads all currently available FAN_OPEN_PERM events non-blocking and
 * responds to them:
 *   - Events FROM dialog_child_pid: FAN_ALLOW (dialog needs to open files).
 *   - Events that pass the mount-mark fast-path: FAN_ALLOW.
 *   - Everything else: left for the main event loop (NOT responded to here),
 *     so the caller must not close fan_fd.
 *
 * Returns number of events responded to.
 */
int fanotify_pump(int fan_fd, pid_t dialog_child_pid)
{
    char buf[BUF_SIZE]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));

    /* Peek at how much data is available; if none, return immediately. */
    int responded = 0;
    ssize_t n;

    while (1)
    {
        /* Non-blocking read: set O_NONBLOCK transiently. */
        int flags = fcntl(fan_fd, F_GETFL, 0);
        if (flags < 0)
            break;
        fcntl(fan_fd, F_SETFL, flags | O_NONBLOCK);
        n = read(fan_fd, buf, sizeof(buf));
        fcntl(fan_fd, F_SETFL, flags); /* restore */

        if (n <= 0)
            break;

        const struct fanotify_event_metadata *ev =
            (const struct fanotify_event_metadata *)buf;
        ssize_t remaining = n;

        while (FAN_EVENT_OK(ev, (size_t)remaining))
        {
            if ((ev->mask & FAN_OPEN_PERM) && ev->fd != FAN_NOFD)
            {
                int fd_num = (int)ev->fd;
                int allow = 0;

                /* Always allow file opens from the dialog child. */
                if (dialog_child_pid > 0 && ev->pid == dialog_child_pid)
                {
                    log_msg(LOG_DEBUG,
                            "[pump] ALLOW fd=%d pid=%d (dialog child)",
                            fd_num, (int)ev->pid);
                    allow = 1;
                }
                else
                {
                    /* Apply fast-path: allow if neither inode-protected nor
                     * under a protected path. */
                    struct stat st;
                    if (fstat(fd_num, &st) == 0 &&
                        !inode_is_protected(st.st_dev, st.st_ino))
                    {
                        char *tgt = resolve_fd_path(fd_num);
                        if (tgt)
                        {
                            if (!is_path_under_protected(tgt))
                            {
                                log_msg(LOG_DEBUG,
                                        "[pump] ALLOW fd=%d pid=%d path=%s (non-protected)",
                                        fd_num, (int)ev->pid, tgt);
                                allow = 1;
                            }
                            else
                            {
                                log_msg(LOG_DEBUG,
                                        "[pump] SKIP fd=%d pid=%d path=%s (protected, defer to main loop)",
                                        fd_num, (int)ev->pid, tgt);
                            }
                            free(tgt);
                        }
                        else
                        {
                            /* Can't resolve path; allow to avoid stalling. */
                            log_msg(LOG_DEBUG,
                                    "[pump] ALLOW fd=%d pid=%d (path unresolvable)",
                                    fd_num, (int)ev->pid);
                            allow = 1;
                        }
                    }
                }

                if (allow)
                {
                    fanotify_respond(fan_fd, ev, FAN_ALLOW);
                    close(fd_num);
                    responded++;
                }
                /* else: leave unanswered — main event loop will handle it. */
            }
            else if (ev->fd != FAN_NOFD)
            {
                close(ev->fd);
            }

            ev = FAN_EVENT_NEXT(ev, remaining);
        }
    }

    return responded;
}

void fanotify_clear_marks(int fd)
{
    /* Remove all mount marks from the kernel and clear the in-memory tables.
     * Called before a config reload so the tables are rebuilt cleanly by
     * the subsequent fanotify_add_mark() calls. */
    for (int i = 0; i < g_mount_count; i++)
    {
        if (fanotify_mark(fd, FAN_MARK_REMOVE | FAN_MARK_MOUNT,
                          FAN_OPEN_PERM, AT_FDCWD, g_mounts[i].path) < 0)
        {
            log_msg(LOG_WARNING, "fanotify mount mark remove failed for dev %lu: %s",
                    (unsigned long)g_mounts[i].dev, strerror(errno));
        }
    }
    g_mount_count = 0;
    g_inode_count = 0;
    log_msg(LOG_INFO, "mount marks and inode table cleared");
}

int fanotify_respond(int fd, const struct fanotify_event_metadata *ev,
                     unsigned int response)
{
    struct fanotify_response resp;

    resp.fd = ev->fd;
    resp.response = response;
    ssize_t total = 0;
    while (total < (ssize_t)sizeof(resp))
    {
        ssize_t w = write(fd, (char *)&resp + total, sizeof(resp) - (size_t)total);
        if (w < 0)
        {
            if (errno == EINTR)
                continue;
            log_msg(LOG_ERR, "fanotify write response: %s", strerror(errno));
            return -1;
        }
        total += w;
    }
    return 0;
}

void fanotify_loop(int fd)
{
    char buf[BUF_SIZE]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));
    const struct fanotify_event_metadata *ev;
    ssize_t n;
    int event_cnt = 0;
    time_t last_expire = time(NULL);

    while (g_running && !g_need_reload)
    {
        n = read(fd, buf, sizeof(buf));
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            log_msg(LOG_ERR, "fanotify read: %s", strerror(errno));
            break;
        }

        ev = (const struct fanotify_event_metadata *)buf;
        {
            ssize_t remaining = n;

            while (FAN_EVENT_OK(ev, (size_t)remaining))
            {
                if (ev->vers != FANOTIFY_METADATA_VERSION)
                    goto advance;

                if (ev->mask & FAN_OPEN_PERM)
                {
                    pid_t pid = ev->pid;
                    int fd_num = (int)ev->fd;
                    char *binary = NULL;
                    char *target = NULL;
                    int ttl = 0;
                    pid_t ppid = 0;
                    char comm[256] = "";
                    char pcomm[256] = "";
                    char cmdline[512] = "";
                    /* device + inode cached for dedup insert after decision */
                    dev_t ev_dev = 0;
                    ino_t ev_ino = 0;

                    log_msg(LOG_DEBUG, "[event] FAN_OPEN_PERM pid=%d fd=%d",
                            (int)pid, fd_num);

                    if (fd_num == FAN_NOFD)
                    {
                        log_msg(LOG_WARNING, "[event] FAN_NOFD for pid=%d, denying", (int)pid);
                        fanotify_respond(fd, ev, FAN_DENY);
                        goto advance;
                    }

                    /* Resolve the target file path from the daemon's fd table.
                     * Done early so the mount-mark fast-path below can reuse
                     * it, avoiding a redundant readlink(2). */
                    target = resolve_fd_path(fd_num);
                    if (!target)
                    {
                        log_msg(LOG_WARNING, "[event] resolve_fd_path failed for pid=%d fd=%d, denying",
                                (int)pid, fd_num);
                        fanotify_respond(fd, ev, FAN_DENY);
                        close(fd_num);
                        goto advance;
                    }
                    log_msg(LOG_DEBUG, "[event] resolved target: pid=%d target=%s",
                            (int)pid, target);

                    /* Fast-path filter for mount-mark noise.
                     *
                     * When FAN_MARK_MOUNT is active the kernel fires
                     * FAN_OPEN_PERM for every file open on the filesystem,
                     * not just protected paths.  fstat() the event fd and
                     * check the inode table; if the inode is not protected
                     * AND the resolved target path falls outside every
                     * protected directory, allow it immediately.
                     *
                     * A protected inode that arrives via a path outside the
                     * watched directories (hard link) will fail this check
                     * because the path is outside protected dirs; the full
                     * logic below handles it and logs the bypass.
                     *
                     * Files created inside a protected directory after
                     * startup are not in the inode table yet, but they
                     * WILL be caught by is_path_under_protected (directory
                     * mark is the authoritative guard for those). */
                    if (g_mount_count > 0)
                    {
                        struct stat fast_st;
                        if (fstat(fd_num, &fast_st) == 0 &&
                            !inode_is_protected(fast_st.st_dev, fast_st.st_ino) &&
                            !is_path_under_protected(target))
                        {
                            log_msg(LOG_DEBUG,
                                    "[fast-path] ALLOW pid=%d target=%s (mount-mark noise)",
                                    (int)pid, target);
                            fanotify_respond(fd, ev, FAN_ALLOW);
                            close(fd_num);
                            free(target);
                            target = NULL;
                            goto advance;
                        }
                        log_msg(LOG_DEBUG,
                                "[fast-path] MISS pid=%d target=%s "
                                "inode_protected=%d path_protected=%d -- proceeding to full check",
                                (int)pid, target,
                                (fstat(fd_num, &fast_st) == 0) ? inode_is_protected(fast_st.st_dev, fast_st.st_ino) : -1,
                                is_path_under_protected(target));
                    }

                    /* Resolve the binary path of the suspended process.
                     * TOCTOU note: the process is kernel-suspended so it
                     * cannot execve(), but its on-disk binary could be
                     * replaced between readlink() and the cache/allowlist
                     * check.  This is an inherent limitation of the
                     * fanotify approach and is documented in LIMITATIONS.
                     *
                     * Deduplication check: when both a directory mark and a
                     * mount mark are active the kernel fires two separate
                     * FAN_OPEN_PERM events for the same open.  If we already
                     * decided for this (pid, dev, ino) tuple recently, reuse
                     * that decision and skip the dialog. */
                    {
                        struct stat dedup_st;
                        if (fstat(fd_num, &dedup_st) == 0)
                        {
                            ev_dev = dedup_st.st_dev;
                            ev_ino = dedup_st.st_ino;
                            int cached = recent_cache_lookup(pid, ev_dev, ev_ino);
                            if (cached != -1)
                            {
                                log_msg(LOG_DEBUG,
                                        "[dedup] reusing cached decision=%s for pid=%d target=%s",
                                        cached == (int)FAN_ALLOW ? "ALLOW" : "DENY",
                                        (int)pid, target);
                                fanotify_respond(fd, ev, (unsigned int)cached);
                                close(fd_num);
                                free(target);
                                target = NULL;
                                goto advance;
                            }
                        }
                    }
                    binary = proc_exe_path(pid);
                    if (!binary)
                    {
                        fanotify_respond(fd, ev, FAN_DENY);
                        close(fd_num);
                        free(target);
                        target = NULL;
                        goto advance;
                    }

                    /* Hard-link bypass detection: if the resolved path does
                     * not fall under any protected path the event was fired
                     * by the mount mark, meaning the file was accessed via a
                     * hard link outside the watched directories. */
                    if (!is_path_under_protected(target))
                    {
                        log_msg(LOG_WARNING,
                                "hard-link bypass attempt: %s (pid %d) opened "
                                "protected inode via unprotected path \"%s\"",
                                binary, (int)pid, target);
                    }

                    /* allowlist check */
                    if (allowlist_match(binary, &ttl))
                    {
                        cache_insert(pid, binary, ttl);
                        recent_cache_insert(pid, ev_dev, ev_ino, (int)FAN_ALLOW);
                        fanotify_respond(fd, ev, FAN_ALLOW);
                        close(fd_num);
                        goto cleanup;
                    }

                    /* cache check */
                    if (cache_lookup(pid, binary) > 0)
                    {
                        recent_cache_insert(pid, ev_dev, ev_ino, (int)FAN_ALLOW);
                        fanotify_respond(fd, ev, FAN_ALLOW);
                        close(fd_num);
                        goto cleanup;
                    }

                    /* resolve process comm and parent comm */
                    read_comm(pid, comm, sizeof(comm));
                    ppid = get_ppid(pid);
                    if (ppid > 0)
                        read_comm(ppid, pcomm, sizeof(pcomm));
                    read_cmdline(pid, cmdline, sizeof(cmdline));

                    /*
                     * Compute SHA-512 of the binary and build the ancestor
                     * call chain.  Both are done while the target process is
                     * kernel-suspended so its /proc entry is still valid.
                     *
                     * SHA-512 computation is deferred until after the static
                     * allowlist / TTL-cache checks above (those are O(1)).
                     * We only pay the fork+sha512sum cost on genuine cache
                     * misses that will show a dialog anyway.
                     */
                    char bin_sha512[129] = "";
                    ProcChain chain;
                    /* Hash via /proc/<pid>/exe — works for containerised
                     * processes (Podman/Docker) whose binary path does not
                     * exist on the host filesystem. */
                    int sha_ok = sha512_proc_exe(pid, bin_sha512);
                    build_proc_chain(pid, &chain);

                    if (sha_ok < 0)
                        log_msg(LOG_WARNING, "SHA-512 computation failed for %s (pid %d); "
                                             "permanent decisions will rely on path + chain only",
                                binary, (int)pid);

                    /* dynamic allowlist check (runtime "Always Allow") */
                    if (dyn_allow_match(binary, bin_sha512, &chain))
                    {
                        int user_ttl = g_config ? g_config->user_ttl_seconds : 300;
                        cache_insert(pid, binary, user_ttl);
                        log_msg(LOG_INFO,
                                "dynamic allowlist hit: %s (pid %d) -> %s",
                                binary, (int)pid, target);
                        recent_cache_insert(pid, ev_dev, ev_ino, (int)FAN_ALLOW);
                        fanotify_respond(fd, ev, FAN_ALLOW);
                        close(fd_num);
                        goto cleanup;
                    }

                    /* dynamic denylist check (runtime "Always Deny") */
                    if (dyn_deny_match(binary, bin_sha512, &chain))
                    {
                        log_msg(LOG_INFO,
                                "dynamic denylist hit: %s (pid %d) -> %s",
                                binary, (int)pid, target);
                        recent_cache_insert(pid, ev_dev, ev_ino, (int)FAN_DENY);
                        fanotify_respond(fd, ev, FAN_DENY);
                        close(fd_num);
                        goto cleanup;
                    }

                    /* ask user consent */
                    log_msg(LOG_INFO,
                            "[dialog] asking user: pid=%d binary=%s target=%s comm=%s",
                            (int)pid, binary, target, comm);
                    int decision = notify_ask(comm, pid, ppid, pcomm,
                                              binary, cmdline, target);
                    log_msg(LOG_INFO, "[dialog] user decision=%d for pid=%d binary=%s",
                            decision, (int)pid, binary);
                    if (decision == NOTIFY_ALLOW_ONCE ||
                        decision == NOTIFY_ALLOW_ALWAYS)
                    {
                        int user_ttl = g_config ? g_config->user_ttl_seconds : 300;
                        cache_insert(pid, binary, user_ttl);
                        if (decision == NOTIFY_ALLOW_ALWAYS)
                            dyn_allow_add(binary, bin_sha512, &chain, target);
                        recent_cache_insert(pid, ev_dev, ev_ino, (int)FAN_ALLOW);
                        fanotify_respond(fd, ev, FAN_ALLOW);
                    }
                    else if (decision == NOTIFY_DENY_ALWAYS)
                    {
                        dyn_deny_add(binary, bin_sha512, &chain, target);
                        recent_cache_insert(pid, ev_dev, ev_ino, (int)FAN_DENY);
                        fanotify_respond(fd, ev, FAN_DENY);
                    }
                    else
                    {
                        recent_cache_insert(pid, ev_dev, ev_ino, (int)FAN_DENY);
                        fanotify_respond(fd, ev, FAN_DENY);
                    }
                    close(fd_num);

                cleanup:
                    free(binary);
                    free(target);
                }

            advance:
                if (ev->event_len == 0)
                    break;
                remaining -= ev->event_len;
                ev = (const struct fanotify_event_metadata *)((const char *)ev + ev->event_len);
            }
        }

        if (!g_running || g_need_reload)
            break;

        /* periodic cache expiry — every 100 events or 10 seconds */
        event_cnt++;
        {
            time_t now = time(NULL);
            if (event_cnt >= 100 || difftime(now, last_expire) >= 10.0)
            {
                cache_expire();
                event_cnt = 0;
                last_expire = now;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Public API: dynamic allowlist / denylist persistence              */
/* ------------------------------------------------------------------ */

int fanotify_get_dyn_allowlist(PersistEntry *out_entries, int max_entries)
{
    if (!out_entries || max_entries <= 0)
        return 0;
    return dyn_to_persist(g_dyn_allow, g_dyn_allow_count, out_entries, max_entries);
}

void fanotify_load_dyn_allowlist(const PersistEntry *entries, int count)
{
    load_dyn_list(g_dyn_allow, &g_dyn_allow_count, entries, count, "always-allow");
}

int fanotify_get_dyn_denylist(PersistEntry *out_entries, int max_entries)
{
    if (!out_entries || max_entries <= 0)
        return 0;
    return dyn_to_persist(g_dyn_deny, g_dyn_deny_count, out_entries, max_entries);
}

void fanotify_load_dyn_denylist(const PersistEntry *entries, int count)
{
    load_dyn_list(g_dyn_deny, &g_dyn_deny_count, entries, count, "always-deny");
}
