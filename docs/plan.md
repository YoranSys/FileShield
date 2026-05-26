# FileShield — Implementation Plan

## Language & Philosophy

- **C99**, no external dependencies beyond libc + Linux kernel headers
- **DRY / KISS**: no unnecessary abstraction, single-purpose functions, flat module structure

## Project Layout

```
FileShield/
├── Makefile
├── fileshield.conf              # default config shipped with install
├── fileshield.service           # systemd unit
├── docs/
│   └── plan.md                  # this file
├── src/
│   ├── main.c                   # daemonize, signals, orchestration
│   ├── fanotify.c / fanotify.h  # fanotify init, marks, event loop, responses
│   ├── config.c / config.h      # parse fileshield.conf
│   ├── cache.c / cache.h        # PID-keyed allowlist with TTL (lazy expiry)
│   ├── notify.c / notify.h      # zenity / kdialog popups
│   └── utils.c / utils.h        # /proc/<pid>/exe, path expansion, logging
└── tests/
    ├── test_cache.c             # unit tests for cache module
    ├── test_config.c            # unit tests for config parser
    └── test_utils.c             # unit tests for utility functions
```

## Module API Design

### `utils.h` — shared helpers (no state)

```c
// Resolve /proc/<pid>/exe -> malloc'd path, or NULL on error
char *proc_exe_path(pid_t pid);

// Expand ~ and $HOME in path -> malloc'd string
char *expand_home(const char *path);

// Log to syslog + optional stderr (foreground mode)
void log_msg(int priority, const char *fmt, ...);

// Check if path is inside a watch directory
int path_under(const char *path, const char *dir);
```

### `config.h` — parse `fileshield.conf`

```c
#define MAX_PATHS 256
#define MAX_ALLOWLIST 128

typedef struct {
    char path[PATH_MAX];
} ProtectedPath;

typedef struct {
    char binary[PATH_MAX];
    int  ttl_seconds;
} AllowlistEntry;

typedef struct {
    ProtectedPath  protected[MAX_PATHS];
    int            protected_count;

    AllowlistEntry allowlist[MAX_ALLOWLIST];
    int            allowlist_count;
} Config;

// Parse config file into *cfg. Returns 0 on success, -1 on error.
int  config_load(const char *path, Config *cfg);
void config_free(Config *cfg);

// Singleton accessor for signal handler use
extern Config *g_config;
```

### `cache.h` — PID-based allowlist with TTL

```c
// Lookup: returns remaining TTL seconds (>0 allowed) or 0 if absent/expired
int cache_lookup(pid_t pid, const char *binary);

// Insert with TTL (seconds from now). Overwrites existing.
void cache_insert(pid_t pid, const char *binary, int ttl_seconds);

// Lazy-expire: scan and remove dead entries
void cache_expire(void);

// Stats for tests
int cache_entry_count(void);
```

### `fanotify.h` — kernel interface

```c
// Init fanotify fd. Returns fd >= 0, or -1 on error.
int  fanotify_setup(void);

// Add/remove a mark on a single path. Returns 0 on success, -1 on error.
int  fanotify_add_mark(int fd, const char *path);
int  fanotify_remove_mark(int fd, const char *path);

// Blocking event loop. Returns on fatal error or signal.
void fanotify_loop(int fd);

// Respond to a pending event: FAN_ALLOW or FAN_DENY
int  fanotify_respond(int fd, const struct fanotify_event_metadata *ev, unsigned int response);
```

### `notify.h` — GUI popup

```c
// Returns 0 for ALLOW, 1 for DENY, -1 on popup failure (defaults to DENY)
int notify_ask(const char *comm, pid_t pid, pid_t ppid, const char *comm_parent, const char *path);
```

### `main.c` — daemon lifecycle

```c
// Usage: fileshield [--foreground] [--config /path/to/fileshield.conf]
// Signal handling: SIGTERM/INT -> shutdown, SIGHUP -> reload config
```

## Cache Behavior (per design decision)

| Source              | Match key          | TTL source          |
|---------------------|--------------------|---------------------|
| Config allowlist    | binary path only   | config TTL (e.g. 3600s) |
| Interactive "Allow" | PID + binary path  | 300s (5 min default)    |

Lookup order: check interactive cache (PID+ binary) → check config allowlist (binary only) → prompt.

## Build & Test

- `make` — compile `fileshield` binary + test binaries
- `make test` — compile and run all test suites
- `make install` — install binary, config, systemd unit
- `make clean` — remove artifacts
- `make lint` — cppcheck static analysis
- CFLAGS: `-std=c99 -Wall -Wextra -Wpedantic -O2`

## Testing Strategy

- **`test_cache`**: insert/lookup/expire entries, TTL edge cases, overwrites
- **`test_config`**: parse valid/invalid .conf, ~ expansion, edge cases
- **`test_utils`**: proc_exe_path (mock /proc), home expansion, path_under
- Tests are self-contained C files linked against the module `.o` files
- Each test returns 0 on pass, non-zero on failure. `make test` runs them all and reports aggregate.

## Limitations (from README)
- Root-only (CAP_SYS_ADMIN for fanotify_init)
- GUI session required for popups
- Kernel 5.0+ for FAN_OPEN_PERM on directories
- No NFS/CIFS coverage
