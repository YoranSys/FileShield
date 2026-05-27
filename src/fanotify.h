#ifndef FILESHIELD_FANOTIFY_H
#define FILESHIELD_FANOTIFY_H

#include <sys/fanotify.h>
#include "persist.h"

int fanotify_setup(void);
int fanotify_add_mark(int fd, const char *path);
int fanotify_remove_mark(int fd, const char *path);
void fanotify_loop(int fd);
int fanotify_respond(int fd, const struct fanotify_event_metadata *ev, unsigned int response);

/*
 * Clear mount marks and inode table before a config reload.
 */
void fanotify_clear_marks(int fd);

/*
 * Drain pending FAN_OPEN_PERM events without blocking.
 * Auto-allows events from dialog_child_pid (and its descendants that share
 * the same PPID) and non-protected opens. Events that would require a user
 * decision are left in the queue for the main loop.
 * Called by notify.c while waiting for the dialog child to finish.
 * Returns the number of events processed.
 */
int fanotify_pump(int fan_fd, pid_t dialog_child_pid);

/*
 * Dynamic allowlist / denylist management: export the in-memory lists for
 * persistence.
 */

/* Get the current dynamic allowlist entries. Returns count of entries. */
int fanotify_get_dyn_allowlist(PersistEntry *out_entries, int max_entries);

/* Load persisted entries into the dynamic allowlist. Called on daemon startup. */
void fanotify_load_dyn_allowlist(const PersistEntry *entries, int count);

/* Get the current dynamic denylist entries. Returns count of entries. */
int fanotify_get_dyn_denylist(PersistEntry *out_entries, int max_entries);

/* Load persisted entries into the dynamic denylist. Called on daemon startup. */
void fanotify_load_dyn_denylist(const PersistEntry *entries, int count);

#endif
