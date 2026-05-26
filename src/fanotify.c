#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/fanotify.h>
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

#define CHAIN_MAX 3

typedef struct
{
    pid_t pid[CHAIN_MAX];
    char comm[CHAIN_MAX][256];
    char exe[CHAIN_MAX][PATH_MAX];
    char sha512[CHAIN_MAX][129]; /* lowercase hex SHA-512 of each ancestor exe */
    int depth;                   /* how many ancestors were captured            */
} ProcChain;

static void build_proc_chain(pid_t start_pid, ProcChain *c)
{
    memset(c, 0, sizeof(*c));
    pid_t cur = start_pid;
    for (int i = 0; i < CHAIN_MAX; i++)
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
/*  runtime dynamic allowlist ("Always Allow" decisions)              */
/* ------------------------------------------------------------------ */

#define DYN_ALLOW_MAX 256

typedef struct
{
    char binary[PATH_MAX];
    char binary_sha512[129];
    char chain_comm[CHAIN_MAX][256];
    char chain_sha512[CHAIN_MAX][129];
    int chain_depth;
} DynAllowEntry;

static DynAllowEntry g_dyn_allow[DYN_ALLOW_MAX];
static int g_dyn_allow_count = 0;

/*
 * dyn_allow_match: returns 1 if (binary, bin_sha512, chain) matches a stored
 * "Always Allow" entry, 0 otherwise.
 *
 * Matching rules (fail-secure):
 *   - Binary path must match.
 *   - If both sides have a SHA-512, they must be equal.
 *   - If the stored entry has a SHA-512 but we failed to compute one now
 *     (sha512sum unavailable?), we DENY — we cannot verify integrity.
 *   - Call-chain depth must match exactly.
 *   - For each ancestor: comm must match AND, if both sides have a SHA-512,
 *     they must be equal; if stored has one but current is missing, DENY.
 */
static int dyn_allow_match(const char *binary, const char *bin_sha512,
                           const ProcChain *chain)
{
    for (int i = 0; i < g_dyn_allow_count; i++)
    {
        DynAllowEntry *e = &g_dyn_allow[i];

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
                          const ProcChain *chain)
{
    if (g_dyn_allow_count >= DYN_ALLOW_MAX)
    {
        /* Ring-buffer: drop the oldest entry to make room. */
        log_msg(LOG_WARNING, "dynamic allowlist full (%d); dropping oldest entry",
                DYN_ALLOW_MAX);
        memmove(&g_dyn_allow[0], &g_dyn_allow[1],
                sizeof(DynAllowEntry) * (DYN_ALLOW_MAX - 1));
        g_dyn_allow_count = DYN_ALLOW_MAX - 1;
    }

    DynAllowEntry *e = &g_dyn_allow[g_dyn_allow_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->binary, sizeof(e->binary), "%s", binary);
    snprintf(e->binary_sha512, sizeof(e->binary_sha512), "%s", bin_sha512);
    e->chain_depth = chain->depth;
    for (int i = 0; i < chain->depth; i++)
    {
        snprintf(e->chain_comm[i], sizeof(e->chain_comm[i]), "%s", chain->comm[i]);
        snprintf(e->chain_sha512[i], sizeof(e->chain_sha512[i]), "%s", chain->sha512[i]);
    }

    /* Log a short fingerprint for auditability. */
    char sha_short[17] = "????????????????";
    if (bin_sha512[0] != '\0')
        memcpy(sha_short, bin_sha512, 16);
    sha_short[16] = '\0';
    log_msg(LOG_INFO,
            "always-allow added: %s (sha512: %s...) chain-depth=%d",
            binary, sha_short, chain->depth);

    /* Persist the updated dynamic allowlist to disk. */
    PersistEntry persist_buf[DYN_ALLOW_MAX];
    memset(persist_buf, 0, sizeof(persist_buf));
    for (int i = 0; i < g_dyn_allow_count; i++)
    {
        DynAllowEntry *src = &g_dyn_allow[i];
        PersistEntry *dst = &persist_buf[i];
        memcpy(dst->binary, src->binary, sizeof(src->binary));
        dst->binary[sizeof(dst->binary) - 1] = '\0';
        memcpy(dst->binary_sha512, src->binary_sha512, sizeof(src->binary_sha512));
        dst->binary_sha512[sizeof(dst->binary_sha512) - 1] = '\0';
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
    if (persist_save(persist_buf, g_dyn_allow_count) < 0)
        log_msg(LOG_WARNING, "persist_save failed; entry not persisted");
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

                    if (fd_num == FAN_NOFD)
                    {
                        fanotify_respond(fd, ev, FAN_DENY);
                        goto advance;
                    }

                    /* Resolve the binary path of the suspended process.
                     * TOCTOU note: the process is kernel-suspended so it
                     * cannot execve(), but its on-disk binary could be
                     * replaced between readlink() and the cache/allowlist
                     * check.  This is an inherent limitation of the
                     * fanotify approach and is documented in LIMITATIONS. */
                    binary = proc_exe_path(pid);
                    if (!binary)
                    {
                        fanotify_respond(fd, ev, FAN_DENY);
                        close(fd_num);
                        goto advance;
                    }

                    /* resolve target file path from daemon's own fd table */
                    target = resolve_fd_path(fd_num);
                    if (!target)
                    {
                        free(binary);
                        fanotify_respond(fd, ev, FAN_DENY);
                        close(fd_num);
                        goto advance;
                    }

                    /* allowlist check */
                    if (allowlist_match(binary, &ttl))
                    {
                        cache_insert(pid, binary, ttl);
                        fanotify_respond(fd, ev, FAN_ALLOW);
                        close(fd_num);
                        goto cleanup;
                    }

                    /* cache check */
                    if (cache_lookup(pid, binary) > 0)
                    {
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
                    sha512_proc_exe(pid, bin_sha512);
                    build_proc_chain(pid, &chain);

                    /* dynamic allowlist check (runtime "Always Allow") */
                    if (dyn_allow_match(binary, bin_sha512, &chain))
                    {
                        int user_ttl = g_config ? g_config->user_ttl_seconds : 300;
                        cache_insert(pid, binary, user_ttl);
                        log_msg(LOG_INFO,
                                "dynamic allowlist hit: %s (pid %d) -> %s",
                                binary, (int)pid, target);
                        fanotify_respond(fd, ev, FAN_ALLOW);
                        close(fd_num);
                        goto cleanup;
                    }

                    /* ask user consent */
                    int decision = notify_ask(comm, pid, ppid, pcomm,
                                              binary, cmdline, target);
                    if (decision == NOTIFY_ALLOW_ONCE ||
                        decision == NOTIFY_ALLOW_ALWAYS)
                    {
                        int user_ttl = g_config ? g_config->user_ttl_seconds : 300;
                        cache_insert(pid, binary, user_ttl);
                        if (decision == NOTIFY_ALLOW_ALWAYS)
                            dyn_allow_add(binary, bin_sha512, &chain);
                        fanotify_respond(fd, ev, FAN_ALLOW);
                    }
                    else
                    {
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
/*  Public API: dynamic allowlist persistence                         */
/* ------------------------------------------------------------------ */

int fanotify_get_dyn_allowlist(PersistEntry *out_entries, int max_entries)
{
    if (!out_entries || max_entries <= 0)
        return 0;

    memset(out_entries, 0, sizeof(*out_entries) * max_entries);

    int count = (g_dyn_allow_count < max_entries) ? g_dyn_allow_count : max_entries;

    for (int i = 0; i < count; i++)
    {
        DynAllowEntry *src = &g_dyn_allow[i];
        PersistEntry *dst = &out_entries[i];

        memcpy(dst->binary, src->binary, sizeof(src->binary));
        dst->binary[sizeof(dst->binary) - 1] = '\0';
        memcpy(dst->binary_sha512, src->binary_sha512, sizeof(src->binary_sha512));
        dst->binary_sha512[sizeof(dst->binary_sha512) - 1] = '\0';
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

    return count;
}

void fanotify_load_dyn_allowlist(const PersistEntry *entries, int count)
{
    if (!entries || count <= 0 || count > DYN_ALLOW_MAX)
        return;

    memset(g_dyn_allow, 0, sizeof(g_dyn_allow));
    g_dyn_allow_count = 0;

    for (int i = 0; i < count; i++)
    {
        const PersistEntry *src = &entries[i];
        DynAllowEntry *dst = &g_dyn_allow[i];

        snprintf(dst->binary, sizeof(dst->binary), "%s", src->binary);
        snprintf(dst->binary_sha512, sizeof(dst->binary_sha512), "%s", src->binary_sha512);
        dst->chain_depth = src->chain_depth;
        for (int j = 0; j < src->chain_depth; j++)
        {
            snprintf(dst->chain_comm[j], sizeof(dst->chain_comm[j]), "%s", src->chain_comm[j]);
            snprintf(dst->chain_sha512[j], sizeof(dst->chain_sha512[j]), "%s", src->chain_sha512[j]);
        }
    }

    g_dyn_allow_count = count;
    log_msg(LOG_INFO, "loaded %d persisted always-allow entries", count);
}
