#ifndef FILESHIELD_FANOTIFY_H
#define FILESHIELD_FANOTIFY_H

#include <sys/fanotify.h>
#include "persist.h"

int  fanotify_setup(void);
int  fanotify_add_mark(int fd, const char *path);
int  fanotify_remove_mark(int fd, const char *path);
void fanotify_loop(int fd);
int  fanotify_respond(int fd, const struct fanotify_event_metadata *ev, unsigned int response);

/*
 * Dynamic allowlist management: export the in-memory allowlist for persistence.
 */

/* Get the current dynamic allowlist entries. Returns count of entries. */
int fanotify_get_dyn_allowlist(PersistEntry *out_entries, int max_entries);

/* Load persisted entries into the dynamic allowlist. Called on daemon startup. */
void fanotify_load_dyn_allowlist(const PersistEntry *entries, int count);

#endif
