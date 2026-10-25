#include "tr_common.h"

#include <sys/time.h>

/* ---------------- logging ---------------- */

static tr_log_sink_fn g_sink = NULL;

void tr_set_log_sink(tr_log_sink_fn fn) { g_sink = fn; }

void tr_logf(int level, const char *fmt, ...)
{
    char line[1024];
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n < 0) {
        return;
    }
    if ((size_t)n >= sizeof(line)) {
        line[sizeof(line) - 1] = '\0';
    }
    if (g_sink != NULL) {
        g_sink(level, line);
    } else {
        const char *tag = "INFO";
        if (level == TR_LOG_DEBUG) tag = "DEBUG";
        else if (level == TR_LOG_WARN) tag = "WARN";
        else if (level == TR_LOG_ERROR) tag = "ERROR";
        fprintf(stderr, "[%s] %s\n", tag, line);
    }
}

void tr_log_hexdump(int level, const char *tag, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    char line[128];
    size_t i, k;

    if (level < TR_LOG_INFO && g_sink == NULL) {
        return;
    }
    for (i = 0; i < len; i += 16) {
        size_t off = 0;
        off += (size_t)snprintf(line + off, sizeof(line) - off, "%s+%04zx ",
                                tag != NULL ? tag : "buf", i);
        for (k = 0; k < 16 && i + k < len; k++) {
            off += (size_t)snprintf(line + off, sizeof(line) - off, "%02x ",
                                    p[i + k]);
        }
        tr_logf(level, "%s", line);
    }
}

/* ---------------- status strings ---------------- */

const char *tr_strerror(int status)
{
    switch (status) {
    case TR_OK: return "ok";
    case TR_EINVAL: return "invalid argument";
    case TR_ENOMEM: return "out of memory";
    case TR_EIO: return "i/o error";
    case TR_EUNSUPPORTED: return "unsupported";
    case TR_EGUARD: return "blocked by mitigation guard";
    case TR_ECOMPAT: return "build not supported";
    case TR_EPERM: return "operation not permitted";
    case TR_EDENIED: return "authorization denied";
    case TR_ETIMEDOUT: return "timed out";
    case TR_EAGAIN: return "retry";
    default: return "unknown";
    }
}

/* ---------------- buffer ---------------- */

void tr_buf_init(tr_buf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void tr_buf_free(tr_buf *b)
{
    if (b == NULL) {
        return;
    }
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static int buf_reserve(tr_buf *b, size_t extra)
{
    size_t need = b->len + extra + 1;
    char *grown;

    if (need <= b->cap) {
        return 0;
    }
    size_t cap = b->cap ? b->cap : 256;
    while (cap < need) {
        cap *= 2;
    }
    grown = (char *)realloc(b->data, cap);
    if (grown == NULL) {
        return -1;
    }
    b->data = grown;
    b->cap = cap;
    if (b->len == 0) {
        b->data[0] = '\0';
    }
    return 0;
}

void tr_buf_add(tr_buf *b, const char *s)
{
    size_t n;

    if (b == NULL || s == NULL) {
        return;
    }
    n = strlen(s);
    if (buf_reserve(b, n) != 0) {
        return;
    }
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}

void tr_buf_addf(tr_buf *b, const char *fmt, ...)
{
    va_list ap;
    int n;
    size_t avail;

    if (b == NULL || fmt == NULL) {
        return;
    }
    if (buf_reserve(b, 128) != 0) {
        return;
    }
    for (;;) {
        avail = b->cap - b->len;
        va_start(ap, fmt);
        n = vsnprintf(b->data + b->len, avail, fmt, ap);
        va_end(ap);
        if (n < 0) {
            return;
        }
        if ((size_t)n < avail) {
            b->len += (size_t)n;
            return;
        }
        if (buf_reserve(b, (size_t)n + 1) != 0) {
            return;
        }
    }
}

void tr_buf_add_json_string(tr_buf *b, const char *value)
{
    const unsigned char *p;

    tr_buf_add(b, "\"");
    if (value != NULL) {
        for (p = (const unsigned char *)value; *p != '\0'; p++) {
            switch (*p) {
            case '"': tr_buf_add(b, "\\\""); break;
            case '\\': tr_buf_add(b, "\\\\"); break;
            case '\n': tr_buf_add(b, "\\n"); break;
            case '\r': tr_buf_add(b, "\\r"); break;
            case '\t': tr_buf_add(b, "\\t"); break;
            default:
                /* Strip control characters: keep exported logs printable. */
                if (*p < 0x20) {
                    tr_buf_addf(b, "\\u%04x", *p);
                } else {
                    char one[2];
                    one[0] = (char)*p;
                    one[1] = '\0';
                    tr_buf_add(b, one);
                }
            }
        }
    }
    tr_buf_add(b, "\"");
}

const char *tr_buf_cstr(tr_buf *b)
{
    if (b == NULL) {
        return "";
    }
    if (b->data == NULL) {
        return "";
    }
    return b->data;
}

/* ---------------- file helpers ---------------- */

int tr_read_file(const char *path, char *out, size_t cap)
{
    int fd;
    ssize_t n;
    size_t total = 0;

    if (path == NULL || out == NULL || cap == 0) {
        return -1;
    }
    out[0] = '\0';
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    while (total + 1 < cap) {
        n = read(fd, out + total, cap - 1 - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            out[total] = '\0';
            return -1;
        }
        if (n == 0) {
            break;
        }
        total += (size_t)n;
    }
    close(fd);
    out[total] = '\0';
    return (int)total;
}

int tr_read_line(const char *path, char *out, size_t cap)
{
    int rc = tr_read_file(path, out, cap);
    char *nl;

    if (rc <= 0) {
        out[0] = '\0';
        return -1;
    }
    nl = strchr(out, '\n');
    if (nl != NULL) {
        *nl = '\0';
    }
    return (int)strlen(out);
}

int tr_read_file_alloc(const char *path, unsigned char **out, size_t *len)
{
    int fd;
    size_t cap = 4096, total = 0;
    unsigned char *buf, *grown;
    ssize_t n;

    *out = NULL;
    *len = 0;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    buf = (unsigned char *)malloc(cap);
    if (buf == NULL) {
        close(fd);
        return -1;
    }
    for (;;) {
        if (total == cap) {
            cap *= 2;
            grown = (unsigned char *)realloc(buf, cap);
            if (grown == NULL) {
                free(buf);
                close(fd);
                return -1;
            }
            buf = grown;
        }
        n = read(fd, buf + total, cap - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            free(buf);
            close(fd);
            return -1;
        }
        if (n == 0) {
            break;
        }
        total += (size_t)n;
    }
    close(fd);
    *out = buf;
    *len = total;
    return 0;
}

int tr_file_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

int tr_write_file(const char *path, const void *data, size_t len, mode_t mode)
{
    int fd;
    size_t written = 0;
    ssize_t n;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) {
        return -1;
    }
    while (written < len) {
        n = write(fd, (const char *)data + written, len - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        written += (size_t)n;
    }
    if (fchmod(fd, mode) != 0) {
        /* Non fatal: the umask may already have produced the same mode. */
    }
    close(fd);
    return 0;
}

char *tr_trim(char *s)
{
    char *end;

    if (s == NULL) {
        return NULL;
    }
    while (*s != '\0' && isspace((unsigned char)*s)) {
        s++;
    }
    if (*s == '\0') {
        return s;
    }
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return s;
}

int tr_parse_hex_u64(const char *s, uint64_t *out)
{
    char *end = NULL;
    unsigned long long v;

    if (s == NULL || out == NULL) {
        return -1;
    }
    errno = 0;
    v = strtoull(s, &end, 16);
    if (errno != 0 || end == s) {
        return -1;
    }
    *out = (uint64_t)v;
    return 0;
}

double tr_now_ms(void)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0) {
        return 0.0;
    }
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
}

int tr_sleep_ms(int ms)
{
    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) != 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    return 0;
}
