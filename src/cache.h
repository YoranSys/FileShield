#ifndef FILESHIELD_CACHE_H
#define FILESHIELD_CACHE_H

#include <sys/types.h>

int  cache_lookup(pid_t pid, const char *binary);
void cache_insert(pid_t pid, const char *binary, int ttl_seconds);
void cache_expire(void);
int  cache_entry_count(void);

#endif
