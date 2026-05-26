#ifndef FILESHIELD_NOTIFY_H
#define FILESHIELD_NOTIFY_H

#include <sys/types.h>

/* Return values for notify_ask(). */
#define NOTIFY_ALLOW_ONCE 0   /* grant access for the current TTL only    */
#define NOTIFY_DENY 1         /* block access                             */
#define NOTIFY_ALLOW_ALWAYS 2 /* add to runtime dynamic allowlist         */
#define NOTIFY_DENY_ALWAYS 3  /* add to runtime dynamic denylist          */

int notify_ask(const char *comm, pid_t pid, pid_t ppid,
               const char *comm_parent, const char *exe,
               const char *cmdline, const char *path);

#endif
