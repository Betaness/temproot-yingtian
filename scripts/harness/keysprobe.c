/*
 * keysprobe - can an unprivileged process use the keyring as a heap primitive?
 * Allocates user_key_payload objects and reads them back. Read-only in spirit:
 * it never writes kernel memory it did not allocate.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

#define KEY_SPEC_PROCESS_KEYRING (-2)
#define KEYCTL_READ 11
#define KEYCTL_REVOKE 3
#define KEYCTL_UNLINK 9

static long add_key_(const char *type, const char *desc, const void *payload, size_t plen, int ring)
{ return syscall(__NR_add_key, type, desc, payload, plen, ring); }
static long keyctl_(int op, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5)
{ return syscall(__NR_keyctl, op, a2, a3, a4, a5); }

int main(void)
{
    char payload[64], out[128];
    long key;
    long n;
    int i, ok = 0, sprayed = 0;
    unsigned long serial[64];

    printf("uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
    memset(payload, 'A', sizeof(payload));
    printf("payload size = %zu\n", sizeof(payload));

    key = add_key_("user", "trk_test", payload, sizeof(payload), KEY_SPEC_PROCESS_KEYRING);
    if (key < 0) {
        printf("add_key denied: %s (errno=%d)\n", strerror(errno), errno);
        return 1;
    }
    printf("add_key ok, serial=%ld\n", key);

    memset(out, 0, sizeof(out));
    n = keyctl_(KEYCTL_READ, (unsigned long)key, (unsigned long)out, sizeof(out), 0);
    if (n < 0) {
        printf("keyctl_read denied: %s (errno=%d)\n", strerror(errno), errno);
    } else {
        printf("keyctl_read ok, %ld bytes back, first bytes: %.16s\n", n, out);
        if (memcmp(out, payload, 16) == 0) {
            printf("READBACK CONFIRMED: kernel returns the payload verbatim\n");
            ok = 1;
        }
    }

    /* Can we spray many of different sizes? That is what heap reclaim needs. */
    for (i = 0; i < 64; i++) {
        char desc[32];
        size_t sz = 32 + (size_t)(i % 8) * 64;
        char *buf = malloc(sz);
        snprintf(desc, sizeof(desc), "trk_spray_%d", i);
        memset(buf, 'B', sz);
        serial[i] = (unsigned long)add_key_("user", desc, buf, sz, KEY_SPEC_PROCESS_KEYRING);
        if ((long)serial[i] > 0) {
            sprayed++;
        }
        free(buf);
    }
    printf("sprayed %d/64 keys (sizes 32..480)\n", sprayed);

    keyctl_(KEYCTL_REVOKE, (unsigned long)key, 0, 0, 0);
    keyctl_(KEYCTL_UNLINK, (unsigned long)key, KEY_SPEC_PROCESS_KEYRING, 0, 0);
    for (i = 0; i < 64; i++) {
        if ((long)serial[i] > 0) {
            keyctl_(KEYCTL_REVOKE, serial[i], 0, 0, 0);
            keyctl_(KEYCTL_UNLINK, serial[i], KEY_SPEC_PROCESS_KEYRING, 0, 0);
        }
    }
    printf("cleaned up\n");
    return ok ? 0 : 2;
}
