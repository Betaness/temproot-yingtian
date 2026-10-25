/*
 * tr_common.h - shared primitives for the TemporaryRoot native core.
 *
 * Design rule (inherited from KERNEL_ROOT_HANDOFF.md): never guess build
 * specific constants. Everything that depends on the target build is either
 * read at runtime (probe / BTF / kallsyms) or recorded in tr_build_db.c with
 * an explicit evidence path. No hardcoded kernel offsets live in this project.
 */
#ifndef TR_COMMON_H
#define TR_COMMON_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/auxv.h>
#include <sys/resource.h>

#define TR_VERSION "0.3.0"

enum tr_log_level {
    TR_LOG_DEBUG = 0,
    TR_LOG_INFO = 1,
    TR_LOG_WARN = 2,
    TR_LOG_ERROR = 3
};

enum tr_status {
    TR_OK = 0,
    TR_EINVAL = -1,
    TR_ENOMEM = -2,
    TR_EIO = -3,
    TR_EUNSUPPORTED = -4,
    TR_EGUARD = -5,   /* mitigation guard refused to execute */
    TR_ECOMPAT = -6,  /* build identity not in the supported table */
    TR_EPERM = -7,
    TR_EDENIED = -8,  /* rootd authorization denied */
    TR_ETIMEDOUT = -9,
    TR_EAGAIN = -10
};

const char *tr_strerror(int status);

/* ---- logging ---- */
typedef void (*tr_log_sink_fn)(int level, const char *line);
void tr_set_log_sink(tr_log_sink_fn fn);
void tr_logf(int level, const char *fmt, ...);
void tr_log_hexdump(int level, const char *tag, const void *data, size_t len);

/* ---- growable buffer (JSON / protocol building) ---- */
typedef struct {
    char *data;
    size_t len;
    size_t cap;
} tr_buf;

void tr_buf_init(tr_buf *b);
void tr_buf_free(tr_buf *b);
void tr_buf_add(tr_buf *b, const char *s);
void tr_buf_addf(tr_buf *b, const char *fmt, ...);
void tr_buf_add_json_string(tr_buf *b, const char *value);
const char *tr_buf_cstr(tr_buf *b);

/* ---- file / string helpers ---- */
int tr_read_file(const char *path, char *out, size_t cap);
int tr_read_file_alloc(const char *path, unsigned char **out, size_t *len);
int tr_file_exists(const char *path);
int tr_write_file(const char *path, const void *data, size_t len, mode_t mode);
char *tr_trim(char *s);
int tr_parse_hex_u64(const char *s, uint64_t *out);
int tr_read_line(const char *path, char *out, size_t cap);
double tr_now_ms(void);
int tr_sleep_ms(int ms);

#endif /* TR_COMMON_H */
