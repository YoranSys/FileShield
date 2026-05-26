#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>
#include <errno.h>

#include "utils.h"
#include "config.h"
#include "cache.h"
#include "fanotify.h"
#include "notify.h"
#include "persist.h"

#define DEFAULT_CONFIG "/etc/fileshield.conf"
#define DEFAULT_TTL 300

volatile sig_atomic_t g_running = 1;
volatile sig_atomic_t g_need_reload = 0;

static void sigterm_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static void sighup_handler(int sig)
{
    (void)sig;
    g_need_reload = 1;
}

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [OPTIONS]\n", prog);
    fprintf(stderr, "  -f, --foreground    Run in foreground (do not daemonize)\n");
    fprintf(stderr, "  -c, --config PATH   Config file path (default: %s)\n", DEFAULT_CONFIG);
    fprintf(stderr, "  -h, --help          Show this help\n");
}

static void daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0)
    {
        log_msg(LOG_ERR, "fork failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (pid > 0)
        exit(EXIT_SUCCESS);
    if (setsid() < 0)
    {
        log_msg(LOG_ERR, "setsid failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    /* Second fork: ensure the daemon is not a session leader and cannot
     * re-acquire a controlling terminal (POSIX SUS v3 convention). */
    pid = fork();
    if (pid < 0)
    {
        log_msg(LOG_ERR, "fork (2) failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (pid > 0)
        exit(EXIT_SUCCESS);
    if (!freopen("/dev/null", "r", stdin))
    {
    }
    if (!freopen("/dev/null", "w", stdout))
    {
    }
    if (!freopen("/dev/null", "w", stderr))
    {
    }
}

int main(int argc, char *argv[])
{
    const char *config_path = DEFAULT_CONFIG;

    static struct option long_opts[] = {
        {"foreground", no_argument, 0, 'f'},
        {"config", required_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "fc:h", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'f':
            g_foreground = 1;
            break;
        case 'c':
            config_path = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    openlog("fileshield", LOG_PID | LOG_CONS, LOG_DAEMON);

    Config *cfg = calloc(1, sizeof(Config));
    if (!cfg) {
        log_msg(LOG_ERR, "out of memory allocating config");
        return EXIT_FAILURE;
    }
    if (config_load(config_path, cfg) < 0)
    {
        log_msg(LOG_ERR, "failed to load config: %s", config_path);
        free(cfg);
        return EXIT_FAILURE;
    }
    g_config = cfg;

    if (!g_foreground)
        daemonize();

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigterm_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    sa.sa_handler = sighup_handler;
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int fan_fd = fanotify_setup();
    if (fan_fd < 0)
    {
        log_msg(LOG_ERR, "fanotify_setup failed");
        free(cfg);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < cfg->protected_count; i++)
    {
        if (fanotify_add_mark(fan_fd, cfg->protected[i].path) < 0)
        {
            log_msg(LOG_WARNING, "failed to add mark for %s", cfg->protected[i].path);
        }
    }

    log_msg(LOG_INFO, "FileShield started, watching %d paths", cfg->protected_count);

    /* Load persisted "Always Allow" entries from the previous session. */
    {
        PersistEntry *persist_buf = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
        if (persist_buf)
        {
            int persist_count = persist_load(PERSIST_STATE_FILE, persist_buf, PERSIST_MAX_ENTRIES);
            if (persist_count > 0)
                fanotify_load_dyn_allowlist(persist_buf, persist_count);
            free(persist_buf);
        }
    }

    /* Load persisted "Always Deny" entries from the previous session. */
    {
        PersistEntry *deny_buf = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
        if (deny_buf)
        {
            int deny_count = persist_load(PERSIST_DENY_STATE_FILE, deny_buf, PERSIST_MAX_ENTRIES);
            if (deny_count > 0)
                fanotify_load_dyn_denylist(deny_buf, deny_count);
            free(deny_buf);
        }
    }

    while (g_running)
    {
        fanotify_loop(fan_fd);
        if (g_need_reload)
        {
            g_need_reload = 0;
            log_msg(LOG_INFO, "reloading config");
            Config *new_cfg = calloc(1, sizeof(Config));
            if (!new_cfg) {
                log_msg(LOG_ERR, "out of memory during reload, keeping old config");
            } else if (config_load(config_path, new_cfg) == 0) {
                /* Remove old marks first so paths present in both configs
                 * are never unprotected (remove-then-add order). */
                for (int i = 0; i < cfg->protected_count; i++)
                    fanotify_remove_mark(fan_fd, cfg->protected[i].path);
                for (int i = 0; i < new_cfg->protected_count; i++)
                    fanotify_add_mark(fan_fd, new_cfg->protected[i].path);
                log_msg(LOG_INFO, "config reloaded, watching %d paths", new_cfg->protected_count);
                free(cfg);
                cfg = new_cfg;
                g_config = cfg;
            } else {
                log_msg(LOG_ERR, "config reload failed, keeping old config");
                free(new_cfg);
            }
            cache_expire();
        }
    }

    log_msg(LOG_INFO, "FileShield shutting down");
    close(fan_fd);
    config_reset(cfg);
    free(cfg);
    closelog();
    return EXIT_SUCCESS;
}
