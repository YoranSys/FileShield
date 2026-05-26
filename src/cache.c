#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include "cache.h"

#define CACHE_MAX_ENTRIES 4096

typedef struct
{
    pid_t pid;
    char binary_path[PATH_MAX];
    time_t expiry_time;
} cache_entry_t;

static cache_entry_t cache[CACHE_MAX_ENTRIES];
static int cache_initialized = 0;

static void cache_init(void)
{
    memset(cache, 0, sizeof(cache));
    cache_initialized = 1;
}

int cache_lookup(pid_t pid, const char *binary)
{
    time_t now;
    int i;

    if (!binary)
        return 0;

    if (!cache_initialized)
        cache_init();

    now = time(NULL);

    for (i = 0; i < CACHE_MAX_ENTRIES; i++)
    {
        if (cache[i].pid == 0)
            continue;
        if (cache[i].pid != pid)
            continue;
        if (strcmp(cache[i].binary_path, binary) != 0)
            continue;

        if (cache[i].expiry_time < now)
        {
            cache[i].pid = 0;
            return 0;
        }

        return (int)(cache[i].expiry_time - now);
    }

    return 0;
}

void cache_insert(pid_t pid, const char *binary, int ttl_seconds)
{
    time_t now;
    int i;
    int free_slot = -1;

    if (!cache_initialized)
        cache_init();

    if (binary == NULL)
        return;

    now = time(NULL);

    for (i = 0; i < CACHE_MAX_ENTRIES; i++)
    {
        if (cache[i].pid != 0)
        {
            if (cache[i].pid == pid && strcmp(cache[i].binary_path, binary) == 0)
            {
                free_slot = i;
                break;
            }
            continue;
        }
        if (free_slot < 0)
            free_slot = i;
    }

    if (free_slot < 0)
        return;

    cache[free_slot].pid = pid;
    strncpy(cache[free_slot].binary_path, binary, PATH_MAX - 1);
    cache[free_slot].binary_path[PATH_MAX - 1] = '\0';
    cache[free_slot].expiry_time = now + ttl_seconds;
}

void cache_expire(void)
{
    time_t now;
    int i;

    if (!cache_initialized)
        cache_init();

    now = time(NULL);

    for (i = 0; i < CACHE_MAX_ENTRIES; i++)
    {
        if (cache[i].pid == 0)
            continue;
        if (cache[i].expiry_time < now)
            cache[i].pid = 0;
    }
}

int cache_entry_count(void)
{
    time_t now;
    int count = 0;
    int i;

    if (!cache_initialized)
        cache_init();

    now = time(NULL);

    for (i = 0; i < CACHE_MAX_ENTRIES; i++)
    {
        if (cache[i].pid != 0 && cache[i].expiry_time >= now)
            count++;
    }

    return count;
}
