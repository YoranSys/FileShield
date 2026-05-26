#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "../src/cache.h"

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        failures++; \
    } \
} while(0)

static void test_insert_lookup(void) {
    cache_insert(42, "/usr/bin/evil", 60);
    ASSERT(cache_lookup(42, "/usr/bin/evil") > 0, "lookup after insert");
    ASSERT(cache_lookup(42, "/usr/bin/other") == 0, "lookup wrong binary");
    ASSERT(cache_lookup(99, "/usr/bin/evil") == 0, "lookup wrong pid");
    cache_expire();
    ASSERT(cache_lookup(42, "/usr/bin/evil") > 0, "lookup still valid after expire");
}

static void test_ttl_expiry(void) {
    cache_insert(100, "/bin/ls", 1);
    ASSERT(cache_lookup(100, "/bin/ls") > 0, "lookup before expiry");
    sleep(2);
    ASSERT(cache_lookup(100, "/bin/ls") == 0, "lookup after expiry");
}

static void test_overwrite(void) {
    cache_insert(200, "/bin/a", 60);
    cache_insert(200, "/bin/a", 120);
    int ttl = cache_lookup(200, "/bin/a");
    ASSERT(ttl > 0 && ttl <= 120, "overwrite refresh ttl");
}

static void test_count(void) {
    int before = cache_entry_count();
    cache_insert(300, "/bin/x", 60);
    ASSERT(cache_entry_count() == before + 1, "count after insert");
    cache_insert(300, "/bin/x", 60);
    ASSERT(cache_entry_count() == before + 1, "count unchanged on overwrite");
}

static void test_null_binary(void) {
    cache_insert(400, NULL, 60);
    ASSERT(cache_lookup(400, NULL) == 0, "null binary not inserted");
}

int main(void) {
    printf("=== test_cache ===\n");
    test_insert_lookup();
    test_ttl_expiry();
    test_overwrite();
    test_count();
    test_null_binary();
    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
