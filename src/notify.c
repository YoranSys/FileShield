#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>

#include "notify.h"
#include "fanotify.h"
#include "utils.h"

/* UID of the desktop user whose Wayland session we detected. 0 = not found. */
static uid_t g_session_uid = 0;

/*
 * Fanotify fd stored here so run_dialog() can pump pending events while
 * waiting for the dialog child (prevents mount-mark deadlock).
 */
static int g_fan_fd = -1;

void notify_set_fan_fd(int fd)
{
    g_fan_fd = fd;
}

/*
 * setup_display_env: scan /run/user/<uid>/ to find an active Wayland session
 * and export WAYLAND_DISPLAY, XDG_RUNTIME_DIR, DBUS_SESSION_BUS_ADDRESS.
 * Also records the session owner UID so the dialog child can drop privileges.
 */
static void setup_display_env(void)
{
    if (getenv("WAYLAND_DISPLAY") || getenv("DISPLAY"))
        return;

    DIR *top = opendir("/run/user");
    if (!top)
        return;

    struct dirent *uid_ent;
    while ((uid_ent = readdir(top)) != NULL)
    {
        if (uid_ent->d_name[0] == '.')
            continue;

        /* Only consider numeric entries that are not root (uid > 0). */
        char *endptr;
        unsigned long uid_val = strtoul(uid_ent->d_name, &endptr, 10);
        if (*endptr != '\0' || uid_val == 0)
            continue;

        char user_dir[PATH_MAX];
        snprintf(user_dir, sizeof(user_dir), "/run/user/%s", uid_ent->d_name);

        /* Look for a wayland-N socket (not a .lock file). */
        DIR *d = opendir(user_dir);
        if (!d)
            continue;

        char wayland_sock[256] = "";
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL)
        {
            if (strncmp(ent->d_name, "wayland-", 8) == 0 &&
                strstr(ent->d_name, ".lock") == NULL)
            {
                snprintf(wayland_sock, sizeof(wayland_sock), "%s", ent->d_name);
                break;
            }
        }
        closedir(d);

        if (wayland_sock[0] != '\0')
        {
            setenv("WAYLAND_DISPLAY", wayland_sock, 1);
            setenv("XDG_RUNTIME_DIR", user_dir, 1);
            char dbus[PATH_MAX + 32];
            snprintf(dbus, sizeof(dbus), "unix:path=%s/bus", user_dir);
            setenv("DBUS_SESSION_BUS_ADDRESS", dbus, 1);
            g_session_uid = (uid_t)uid_val;
            break;
        }
    }
    closedir(top);
}

/*
 * drop_to_session_user: called in the dialog child after fork().
 * Switches uid/gid to the desktop user so kdialog can connect to their
 * Wayland compositor and D-Bus session (sockets are mode 0600, owner=user).
 */
static void drop_to_session_user(void)
{
    if (g_session_uid == 0 || getuid() != 0)
        return;

    struct passwd *pw = getpwuid(g_session_uid);
    if (!pw)
        return;

    setenv("HOME", pw->pw_dir, 1);

    /* Drop gid first (must happen before dropping uid). */
    if (setgid(pw->pw_gid) < 0 || setuid(g_session_uid) < 0)
        _exit(127);
}

static int run_dialog_confirm(const char *bin, const char *text,
                              const char *yes_label, const char *no_label,
                              int ret_yes, int ret_no)
{
    int pipefd[2];
    if (pipe(pipefd) < 0)
    {
        log_msg(LOG_ERR, "pipe failed for confirm dialog: %m");
        return ret_yes;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        close(pipefd[0]);
        close(pipefd[1]);
        return ret_yes;
    }

    if (pid == 0)
    {
        drop_to_session_user();
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0)
            _exit(127);
        close(pipefd[1]);

        if (strcmp(bin, "zenity") == 0)
        {
            execl("/usr/bin/zenity", "zenity",
                  "--question", "--title=FileShield", "--no-markup",
                  "--timeout=30",
                  "--ok-label", yes_label,
                  "--cancel-label", no_label,
                  "--text", text,
                  "--width=450",
                  (char *)NULL);
        }
        else
        {
            execl("/usr/bin/timeout", "timeout", "30",
                  "/usr/bin/kdialog", "kdialog",
                  "--title", "FileShield",
                  "--yesno", text,
                  "--yes-label", yes_label,
                  "--no-label", no_label,
                  (char *)NULL);
        }
        _exit(127);
    }

    close(pipefd[1]);
    {
        char out[64];
        ssize_t nr = read(pipefd[0], out, sizeof(out) - 1);
        (void)nr;
    }
    close(pipefd[0]);

    int status;
    while (waitpid(pid, &status, 0) < 0)
    {
        if (errno == EINTR)
            continue;
        return ret_yes;
    }

    if (!WIFEXITED(status))
        return ret_yes;

    int ec = WEXITSTATUS(status);

    if (strcmp(bin, "zenity") == 0)
    {
        if (ec == 0)
            return ret_yes;
        return ret_no;
    }
    else
    {
        if (ec == 124) /* timeout → safe default */
            return ret_yes;
        if (ec == 0) /* Yes / Deny Once */
            return ret_yes;
        /* No / Always Deny (ec == 1) or error → explicit user choice */
        return ret_no;
    }
}

static int run_dialog(const char *bin, const char *text)
{
    /*
     * Three-button dialog (zenity --question --extra-button,
     * kdialog --yesnocancel).  The fourth action ("Always Deny")
     * is handled as a follow-up confirmation when the user clicks
     * "Deny" — this adds a safety step for permanent blocks.
     */
    int pipefd[2];
    if (pipe(pipefd) < 0)
    {
        log_msg(LOG_ERR, "pipe failed for dialog: %m");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        close(pipefd[0]);
        close(pipefd[1]);
        log_msg(LOG_ERR, "fork failed for %s: %m", bin);
        return -1;
    }
    log_msg(LOG_DEBUG, "[dialog] forked %s child pid=%d", bin, (int)pid);

    if (pid == 0)
    {
        drop_to_session_user();
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0)
            _exit(127);
        close(pipefd[1]);

        if (strcmp(bin, "zenity") == 0)
        {
            /*
             * Three buttons:
             *   Allow Once   → OK button     → exit 0
             *   Always Allow → extra-button  → exit 1 + stdout="Always Allow"
             *   Deny         → Cancel button → exit 1 + stdout=""
             * Timeout (30 s) → exit 5
             */
            execl("/usr/bin/zenity", "zenity",
                  "--question", "--title=FileShield", "--no-markup",
                  "--timeout=30",
                  "--text", text,
                  "--width=600",
                  "--ok-label=Allow Once",
                  "--cancel-label=Deny",
                  "--extra-button=Always Allow",
                  (char *)NULL);
        }
        else
        {
            /*
             * kdialog --yesnocancel with relabelled buttons:
             *   Allow Once   → Yes    → exit 0
             *   Always Allow → No     → exit 1
             *   Deny         → Cancel → exit 2
             * Timeout via coreutils timeout(1) → exit 124
             */
            execl("/usr/bin/timeout", "timeout", "30",
                  "/usr/bin/kdialog", "kdialog",
                  "--title", "FileShield",
                  "--yesnocancel", text,
                  "--yes-label", "Allow Once",
                  "--no-label", "Always Allow",
                  "--cancel-label", "Deny",
                  (char *)NULL);
        }
        _exit(127);
    }

    /* Parent: close write end, then wait for child using a poll loop.
     *
     * Rationale: when FAN_MARK_MOUNT is active kdialog opens config files
     * on the same filesystem (e.g. ~/.config/kdeglobals) which generates
     * FAN_OPEN_PERM events.  A blocking waitpid() would deadlock because
     * the daemon can't respond to those events.  We pump the fanotify fd
     * on every iteration to keep the kernel queue drained. */
    close(pipefd[1]);
    log_msg(LOG_DEBUG, "[dialog] parent waiting for %s (pid=%d)", bin, (int)pid);
    char out[64] = "";
    int got_output = 0;
    int child_exited = 0;
    int status = 0;

    /* Total timeout slightly longer than the inner "timeout 30" we exec. */
#define DIALOG_OUTER_TIMEOUT_S 40
    time_t deadline = time(NULL) + DIALOG_OUTER_TIMEOUT_S;

    while (!child_exited && time(NULL) < deadline)
    {
        struct pollfd pfds[2];
        int nfds = 0;

        pfds[nfds].fd = pipefd[0];
        pfds[nfds].events = POLLIN;
        nfds++;

        if (g_fan_fd >= 0)
        {
            pfds[nfds].fd = g_fan_fd;
            pfds[nfds].events = POLLIN;
            nfds++;
        }

        int ret = poll(pfds, (nfds_t)nfds, 200); /* 200 ms tick */
        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }

        /* Pump fanotify first so the dialog child is never stalled. */
        for (int i = 0; i < nfds; i++)
        {
            if (pfds[i].fd == g_fan_fd && (pfds[i].revents & POLLIN))
                fanotify_pump(g_fan_fd, pid);
        }

        /* Collect dialog output if pipe is readable. */
        for (int i = 0; i < nfds; i++)
        {
            if (pfds[i].fd == pipefd[0] &&
                (pfds[i].revents & (POLLIN | POLLHUP)) &&
                !got_output)
            {
                ssize_t nr = read(pipefd[0], out, sizeof(out) - 1);
                if (nr > 0)
                    out[nr] = '\0';
                got_output = 1;
            }
        }

        /* Non-blocking child-exit check. */
        pid_t wr = waitpid(pid, &status, WNOHANG);
        if (wr == pid)
        {
            child_exited = 1;
        }
        else if (wr < 0 && errno != EINTR)
        {
            log_msg(LOG_ERR, "waitpid failed: %m");
            close(pipefd[0]);
            return -1;
        }
    }

    if (!child_exited)
    {
        log_msg(LOG_WARNING, "[dialog] %s outer timeout, killing pid=%d", bin, (int)pid);
        kill(pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
            ;
    }

    close(pipefd[0]);
    log_msg(LOG_DEBUG, "[dialog] %s exited status=0x%x ec=%d",
            bin, status, WIFEXITED(status) ? WEXITSTATUS(status) : -1);

    if (!WIFEXITED(status))
        return -1;

    int ec = WEXITSTATUS(status);

    if (strcmp(bin, "zenity") == 0)
    {
        if (ec == 5)
            return NOTIFY_DENY; /* timeout                  */
        if (ec == 0)
            return NOTIFY_ALLOW_ONCE; /* OK / Allow Once          */
        /* ec == 1: extra-button OR Cancel — distinguish by stdout */
        if (strncmp(out, "Always Allow", 12) == 0)
            return NOTIFY_ALLOW_ALWAYS;
        return NOTIFY_DENY; /* Cancel / Deny → may trigger follow-up */
    }
    else
    {
        if (ec == 124)
            return NOTIFY_DENY; /* coreutils timeout        */
        if (ec == 0)
            return NOTIFY_ALLOW_ONCE; /* Yes  / Allow Once        */
        if (ec == 1)
            return NOTIFY_ALLOW_ALWAYS; /* No   / Always Allow      */
        return NOTIFY_DENY;             /* Cancel / Deny → may trigger follow-up */
    }
}

int notify_ask(const char *comm, pid_t pid, pid_t ppid,
               const char *comm_parent, const char *exe,
               const char *cmdline, const char *path)
{
    /* Return values: NOTIFY_ALLOW_ONCE, NOTIFY_DENY,
     *                NOTIFY_ALLOW_ALWAYS, or NOTIFY_DENY_ALWAYS. */
    char msg[2048];

    /* Truncate the command line if it is too long for the dialog. */
    char cmd_display[256] = "(unknown)";
    if (cmdline && cmdline[0] != '\0')
    {
        snprintf(cmd_display, sizeof(cmd_display), "%s", cmdline);
        if (strlen(cmdline) > sizeof(cmd_display) - 4)
        {
            cmd_display[sizeof(cmd_display) - 4] = '.';
            cmd_display[sizeof(cmd_display) - 3] = '.';
            cmd_display[sizeof(cmd_display) - 2] = '.';
            cmd_display[sizeof(cmd_display) - 1] = '\0';
        }
    }

    snprintf(msg, sizeof(msg),
             "Process %s (PID %d, parent: %s (PID %d)) wants to read:\n"
             "%s\n\n"
             "Binary:   %s\n"
             "Command:  %s\n\n"
             "\xe2\x80\xa2 Allow Once    \xe2\x80\x94 grant access this time only\n"
             "\xe2\x80\xa2 Always Allow  \xe2\x80\x94 trust this exact binary (SHA-512 verified)\n"
             "                in this call chain permanently\n"
             "\xe2\x80\xa2 Deny          \xe2\x80\x94 block access (will prompt for once/always)",
             comm, (int)pid, comm_parent, (int)ppid,
             path,
             exe ? exe : "(unknown)",
             cmd_display);

    /* Auto-detect the active graphical session if env vars are not set. */
    setup_display_env();
    log_msg(LOG_DEBUG,
            "[notify_ask] display env: WAYLAND=%s DISPLAY=%s uid=%d",
            getenv("WAYLAND_DISPLAY") ? getenv("WAYLAND_DISPLAY") : "(none)",
            getenv("DISPLAY") ? getenv("DISPLAY") : "(none)",
            (int)g_session_uid);

    /* Determine which dialog binary to use. */
    const char *bin = NULL;

    if (getenv("WAYLAND_DISPLAY"))
    {
        int r = run_dialog("kdialog", msg);
        if (r == NOTIFY_ALLOW_ONCE || r == NOTIFY_ALLOW_ALWAYS)
            return r;
        if (r == NOTIFY_DENY)
            bin = "kdialog";
        else
            log_msg(LOG_WARNING, "kdialog failed, falling back to zenity");
    }

    if (!bin && getenv("DISPLAY"))
    {
        int r = run_dialog("zenity", msg);
        if (r == NOTIFY_ALLOW_ONCE || r == NOTIFY_ALLOW_ALWAYS)
            return r;
        if (r == NOTIFY_DENY)
            bin = "zenity";
        else
            log_msg(LOG_WARNING, "zenity failed");
    }

    if (!bin)
    {
        log_msg(LOG_ERR, "no graphical dialog available; denying access to %s", path);
        return NOTIFY_DENY;
    }

    /* User clicked Deny in the first dialog.  Show a follow-up to
     * distinguish between "Deny Once" and "Always Deny". */
    return run_dialog_confirm(bin,
                              "Block access this time only, or permanently?\n\n"
                              "\xe2\x80\xa2 Deny Once     \xe2\x80\x94 block this time only\n"
                              "\xe2\x80\xa2 Always Deny  \xe2\x80\x94 block this exact binary (SHA-512 verified)\n"
                              "                 in this call chain permanently",
                              "Deny Once", "Always Deny",
                              NOTIFY_DENY, NOTIFY_DENY_ALWAYS);
}
