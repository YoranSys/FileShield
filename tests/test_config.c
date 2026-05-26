#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "../src/config.h"
#include "../src/utils.h"

static int failures = 0;

#define ASSERT(cond, msg)                       \
    do                                          \
    {                                           \
        if (!(cond))                            \
        {                                       \
            fprintf(stderr, "FAIL: %s\n", msg); \
            failures++;                         \
        }                                       \
    } while (0)

static char *write_temp(const char *content)
{
    char tmpl[] = "/tmp/fileshield_test_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0)
        return NULL;
    if (write(fd, content, strlen(content)) < 0)
    {
        close(fd);
        unlink(tmpl);
        return NULL;
    }
    close(fd);
    return strdup(tmpl);
}

static void test_basic_parse(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/etc/ssh/ssh_config\n" /* absolute paths — no per-user expansion */
        "/etc/ssl/certs\n"
        "# comment line\n"
        "\n"
        "[allowlist]\n"
        "/usr/bin/ssh = 3600\n"
        "/usr/bin/git = 300\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    int r = config_load(path, &cfg);
    ASSERT(r == 0, "config_load success");

    ASSERT(cfg.protected_count == 2, "2 protected paths");
    ASSERT(strstr(cfg.protected[0].path, "ssh_config") != NULL, "first path ssh_config");
    ASSERT(strstr(cfg.protected[1].path, "certs") != NULL, "second path certs");

    ASSERT(cfg.allowlist_count == 2, "2 allowlist entries");
    ASSERT(strcmp(cfg.allowlist[0].binary, "/usr/bin/ssh") == 0, "allowlist ssh binary");
    ASSERT(cfg.allowlist[0].ttl_seconds == 3600, "allowlist ssh ttl");
    ASSERT(strcmp(cfg.allowlist[1].binary, "/usr/bin/git") == 0, "allowlist git binary");
    ASSERT(cfg.allowlist[1].ttl_seconds == 300, "allowlist git ttl");

    config_reset(&cfg);
    ASSERT(cfg.protected_count == 0, "config_reset zeros count");
    ASSERT(cfg.allowlist_count == 0, "config_reset zeros allowlist count");

    unlink(path);
    free(path);
}

static void test_missing_file(void)
{
    Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    ASSERT(config_load("/nonexistent/fileshield_test.conf", &cfg) == -1, "missing file fails");
}

static void test_unknown_section(void)
{
    const char *conf =
        "[protected_paths]\n"
        "/tmp/ok\n"
        "[bogus]\n"
        "/tmp/ignored\n"
        "[allowlist]\n"
        "/usr/bin/x = 60\n";

    char *path = write_temp(conf);
    ASSERT(path != NULL, "write temp config");

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));

    config_load(path, &cfg);
    ASSERT(cfg.protected_count == 1, "ignores unknown section paths");
    ASSERT(cfg.allowlist_count == 1, "allowlist under unknown section still parsed");

    config_reset(&cfg);
    unlink(path);
    free(path);
}

int main(void)
{
    printf("=== test_config ===\n");
    test_basic_parse();
    test_missing_file();
    test_unknown_section();
    if (failures)
    {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
