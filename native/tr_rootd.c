#include "tr_rootd.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>

#ifndef TIOCSPTLCK
#define TIOCSPTLCK 0x40045431
#endif

#define TR_STATE_DIR "/data/local/tmp/temproot"

int tr_rootd_state_dir(char *out, size_t cap)
{
    snprintf(out, cap, "%s", TR_STATE_DIR);
    return 0;
}

static int fill_addr(struct sockaddr_un *addr)
{
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    addr->sun_path[0] = '\0';   /* abstract namespace */
    snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 1, "%s",
             TR_ROOTD_SOCK_ABSTRACT);
    return (int)(offsetof(struct sockaddr_un, sun_path) + 1 +
                 strlen(TR_ROOTD_SOCK_ABSTRACT));
}

/* ---------- pty helpers ---------- */

static int open_pty_pair(int *master_out, int *slave_out)
{
    int master, slave, zero = 0;
    char slave_name[128];

    master = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0) {
        return -1;
    }
    if (ioctl(master, TIOCSPTLCK, &zero) != 0) {
        close(master);
        return -1;
    }
    if (ptsname_r(master, slave_name, sizeof(slave_name)) != 0) {
        close(master);
        return -1;
    }
    slave = open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) {
        close(master);
        return -1;
    }
    *master_out = master;
    *slave_out = slave;
    return 0;
}

/* ---------- allow list ---------- */

static int uid_allowed(const char *allow_file, uid_t peer_uid, uid_t owner_uid)
{
    char blob[2048];
    char *line, *save;
    int all = 0;

    if (peer_uid == owner_uid || peer_uid == 0) {
        return 1;
    }
    if (allow_file == NULL || tr_read_file(allow_file, blob, sizeof(blob)) <= 0) {
        return 0;
    }
    line = strtok_r(blob, "\n", &save);
    while (line != NULL) {
        char *t = tr_trim(line);
        if (t[0] != '\0' && t[0] != '#') {
            if (strcmp(t, "all") == 0) {
                all = 1;
            } else {
                long v = strtol(t, NULL, 10);
                if (v > 0 && (uid_t)v == peer_uid) {
                    return 1;
                }
            }
        }
        line = strtok_r(NULL, "\n", &save);
    }
    return all;
}

/* ---------- server side ---------- */

static int read_full(int fd, void *buf, size_t len)
{
    size_t got = 0;

    while (got < len) {
        ssize_t n = read(fd, (char *)buf + got, len - got);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

static int send_fd(int sock, const void *payload, size_t len, int fd_to_send)
{
    struct msghdr msg;
    struct iovec iov;
    char control[CMSG_SPACE(sizeof(int))];

    memset(&msg, 0, sizeof(msg));
    memset(control, 0, sizeof(control));
    iov.iov_base = (void *)payload;
    iov.iov_len = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    {
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));
        msg.msg_controllen = CMSG_SPACE(sizeof(int));
    }
    return (int)sendmsg(sock, &msg, 0);
}

static int recv_fd(int sock, void *payload, size_t len, int *fd_out)
{
    struct msghdr msg;
    struct iovec iov;
    char control[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;
    ssize_t n;

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = payload;
    iov.iov_len = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    n = recvmsg(sock, &msg, 0);
    if (n < 0) {
        return -1;
    }
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            memcpy(fd_out, CMSG_DATA(cmsg), sizeof(int));
            return (int)n;
        }
    }
    *fd_out = -1;
    return (int)n;
}

static void serve_client(int sock, const char *allow_file, uid_t owner_uid)
{
    tr_su_hdr hdr;
    char args[TR_SU_MAX_ARGC][TR_SU_MAX_ARG];
    char *argv[TR_SU_MAX_ARGC + 1];
    tr_su_reply reply;
    struct ucred cred;
    socklen_t cred_len = sizeof(cred);
    int master = -1, slave = -1, i, status = 0, code = 0;
    pid_t child;
    struct timeval tv = { 5, 0 };

    memset(&reply, 0, sizeof(reply));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) != 0) {
        reply.status = TR_EDENIED;
        (void)!write(sock, &reply, sizeof(reply));
        return;
    }
    if (read_full(sock, &hdr, sizeof(hdr)) != 0 || hdr.magic != TR_SU_MAGIC ||
        hdr.version != TR_SU_VERSION || hdr.argc <= 0 || hdr.argc > TR_SU_MAX_ARGC) {
        reply.status = TR_EINVAL;
        (void)!write(sock, &reply, sizeof(reply));
        return;
    }
    for (i = 0; i < hdr.argc; i++) {
        ssize_t n = read(sock, args[i], TR_SU_MAX_ARG - 1);
        if (n <= 0) {
            reply.status = TR_EINVAL;
            (void)!write(sock, &reply, sizeof(reply));
            return;
        }
        args[i][n] = '\0';
        argv[i] = args[i];
    }
    argv[hdr.argc] = NULL;

    if (!uid_allowed(allow_file, cred.uid, owner_uid)) {
        tr_logf(TR_LOG_WARN, "rootd: 拒绝 uid=%u（调用方自称 uid=%d）", cred.uid, hdr.uid);
        reply.status = TR_EDENIED;
        (void)!write(sock, &reply, sizeof(reply));
        return;
    }

    if (open_pty_pair(&master, &slave) != 0) {
        reply.status = TR_EIO;
        (void)!write(sock, &reply, sizeof(reply));
        return;
    }
    child = fork();
    if (child < 0) {
        close(master);
        close(slave);
        reply.status = TR_EIO;
        (void)!write(sock, &reply, sizeof(reply));
        return;
    }
    if (child == 0) {
        close(sock);
        setsid();
        ioctl(slave, TIOCSCTTY, 0);
        dup2(slave, STDIN_FILENO);
        dup2(slave, STDOUT_FILENO);
        dup2(slave, STDERR_FILENO);
        if (slave > STDERR_FILENO) {
            close(slave);
        }
        close(master);
        /* Run from a neutral directory: never inherit the caller's cwd. */
        if (chdir("/") != 0) {
            /* non fatal */
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    close(slave);
    reply.status = 0;
    reply.child_pid = (int32_t)child;
    if (send_fd(sock, &reply, sizeof(reply), master) < 0) {
        kill(child, SIGKILL);
        close(master);
        return;
    }
    close(master);
    if (waitpid(child, &status, 0) == child) {
        code = WIFEXITED(status) ? WEXITSTATUS(status)
             : WIFSIGNALED(status) ? -(WTERMSIG(status)) : -1;
    }
    /* The exit code travels on the control socket after the pty stream. */
    {
        int32_t msg[2];
        msg[0] = 0x54524558; /* "TREX" */
        msg[1] = code;
        (void)!write(sock, msg, sizeof(msg));
    }
    close(sock);
}

static int daemon_main(const char *allow_file, int ttl_sec, uid_t owner_uid)
{
    int listen_fd, rc;
    struct sockaddr_un addr;
    int addr_len;
    double deadline;

    mkdir(TR_STATE_DIR, 0755);
    listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_fd < 0) {
        return -1;
    }
    addr_len = fill_addr(&addr);
    unlink(addr.sun_path); /* only meaningful for pathname sockets */
    if (bind(listen_fd, (struct sockaddr *)&addr, (socklen_t)addr_len) != 0) {
        close(listen_fd);
        return -1;
    }
    if (listen(listen_fd, 8) != 0) {
        close(listen_fd);
        return -1;
    }
    {
        char pid_path[128];
        char line[32];
        snprintf(pid_path, sizeof(pid_path), "%s/rootd.pid", TR_STATE_DIR);
        snprintf(line, sizeof(line), "%d\n", (int)getpid());
        tr_write_file(pid_path, line, strlen(line), 0600);
    }
    tr_logf(TR_LOG_INFO, "rootd: 已监听抽象 socket @%s（pid=%d, ttl=%ds）",
            TR_ROOTD_SOCK_ABSTRACT, (int)getpid(), ttl_sec);

    deadline = tr_now_ms() + (double)ttl_sec * 1000.0;
    while (tr_now_ms() < deadline) {
        struct timeval tv = { 1, 0 };
        fd_set set;
        FD_ZERO(&set);
        FD_SET(listen_fd, &set);
        rc = select(listen_fd + 1, &set, NULL, NULL, &tv);
        if (rc > 0 && FD_ISSET(listen_fd, &set)) {
            int client = accept(listen_fd, NULL, NULL);
            if (client >= 0) {
                pid_t handler = fork();
                if (handler == 0) {
                    close(listen_fd);
                    serve_client(client, allow_file, owner_uid);
                    _exit(0);
                }
                close(client);
                if (handler > 0) {
                    /* Reap without blocking the accept loop. */
                    waitpid(handler, NULL, WNOHANG);
                }
            }
        }
    }
    close(listen_fd);
    {
        char pid_path[128];
        snprintf(pid_path, sizeof(pid_path), "%s/rootd.pid", TR_STATE_DIR);
        unlink(pid_path);
    }
    tr_logf(TR_LOG_INFO, "rootd: TTL 到期退出");
    return 0;
}

int tr_rootd_start(const char *allow_file, int ttl_sec)
{
    pid_t pid;
    uid_t owner = getuid();
    char pid_path[128];
    char line[32];

    if (geteuid() != 0) {
        tr_logf(TR_LOG_WARN, "rootd: 当前 euid=%d，无法启动特权守护进程", (int)geteuid());
        return TR_EPERM;
    }
    if (tr_rootd_ping() == 1) {
        tr_logf(TR_LOG_INFO, "rootd: 已存在实例，复用");
        return 0;
    }
    if (ttl_sec <= 0) {
        ttl_sec = TR_ROOTD_DEFAULT_TTL_SEC;
    }
    pid = fork();
    if (pid < 0) {
        return TR_EIO;
    }
    if (pid == 0) {
        setsid();
        if (daemon_main(allow_file, ttl_sec, owner) != 0) {
            _exit(1);
        }
        _exit(0);
    }
    /* Wait briefly for the socket to appear. */
    {
        int i;
        for (i = 0; i < 50; i++) {
            if (tr_rootd_ping() == 1) {
                break;
            }
            tr_sleep_ms(20);
        }
    }
    snprintf(pid_path, sizeof(pid_path), "%s/rootd.pid", TR_STATE_DIR);
    snprintf(line, sizeof(line), "%d\n", (int)pid);
    tr_write_file(pid_path, line, strlen(line), 0600);
    return (int)pid;
}

int tr_rootd_ping(void)
{
    int fd, addr_len;
    struct sockaddr_un addr;
    struct timeval tv = { 1, 0 };

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return 0;
    }
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    addr_len = fill_addr(&addr);
    if (connect(fd, (struct sockaddr *)&addr, (socklen_t)addr_len) != 0) {
        close(fd);
        return 0;
    }
    close(fd);
    return 1;
}

int tr_rootd_stop(void)
{
    char pid_path[128], buf[32];
    int pid;

    snprintf(pid_path, sizeof(pid_path), "%s/rootd.pid", TR_STATE_DIR);
    if (tr_read_line(pid_path, buf, sizeof(buf)) <= 0) {
        return TR_OK;
    }
    pid = atoi(buf);
    if (pid > 1) {
        kill(pid, SIGTERM);
    }
    unlink(pid_path);
    return TR_OK;
}

/* ---------- client side ---------- */

static int g_su_sock = -1;

int tr_su_spawn(char *const argv[], int *pty_fd, int *child_pid)
{
    int fd, addr_len, i, argc = 0;
    struct sockaddr_un addr;
    tr_su_hdr hdr;
    tr_su_reply reply;

    *pty_fd = -1;
    *child_pid = -1;
    while (argv[argc] != NULL && argc < TR_SU_MAX_ARGC) {
        argc++;
    }
    if (argc == 0) {
        return TR_EINVAL;
    }
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return TR_EIO;
    }
    addr_len = fill_addr(&addr);
    if (connect(fd, (struct sockaddr *)&addr, (socklen_t)addr_len) != 0) {
        close(fd);
        return TR_EUNSUPPORTED;
    }
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = TR_SU_MAGIC;
    hdr.version = TR_SU_VERSION;
    hdr.uid = (int32_t)getuid();
    hdr.pid = (int32_t)getpid();
    hdr.argc = argc;
    if (write(fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
        close(fd);
        return TR_EIO;
    }
    for (i = 0; i < argc; i++) {
        size_t len = strlen(argv[i]);
        if (len >= TR_SU_MAX_ARG) {
            close(fd);
            return TR_EINVAL;
        }
        if (write(fd, argv[i], len + 1) != (ssize_t)(len + 1)) {
            close(fd);
            return TR_EIO;
        }
    }
    if (recv_fd(fd, &reply, sizeof(reply), pty_fd) != (int)sizeof(reply)) {
        close(fd);
        return TR_EIO;
    }
    if (reply.status != 0) {
        close(fd);
        if (*pty_fd >= 0) {
            close(*pty_fd);
            *pty_fd = -1;
        }
        return reply.status;
    }
    *child_pid = reply.child_pid;
    g_su_sock = fd;
    return TR_OK;
}

int tr_su_wait(int *exit_code, int timeout_ms)
{
    struct timeval tv;
    fd_set set;
    int rc;
    int32_t msg[2];

    *exit_code = -1;
    if (g_su_sock < 0) {
        return TR_EINVAL;
    }
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    FD_ZERO(&set);
    FD_SET(g_su_sock, &set);
    rc = select(g_su_sock + 1, &set, NULL, NULL, &tv);
    if (rc <= 0) {
        close(g_su_sock);
        g_su_sock = -1;
        return TR_ETIMEDOUT;
    }
    if (read_full(g_su_sock, msg, sizeof(msg)) != 0 || msg[0] != 0x54524558) {
        close(g_su_sock);
        g_su_sock = -1;
        return TR_EIO;
    }
    *exit_code = msg[1];
    close(g_su_sock);
    g_su_sock = -1;
    return TR_OK;
}

int tr_su_capture(char *const argv[], tr_buf *out, int *exit_code, int timeout_ms)
{
    int pty_fd = -1, child = -1, rc;
    char chunk[512];
    ssize_t n;
    fd_set set;
    struct timeval tv;
    double deadline;
    size_t total = 0;

    rc = tr_su_spawn(argv, &pty_fd, &child);
    if (rc != TR_OK) {
        return rc;
    }
    deadline = tr_now_ms() + (double)timeout_ms;
    for (;;) {
        double left = deadline - tr_now_ms();
        if (left <= 0) {
            break;
        }
        tv.tv_sec = (time_t)(left / 1000.0);
        tv.tv_usec = (suseconds_t)((long)left % 1000) * 1000;
        FD_ZERO(&set);
        FD_SET(pty_fd, &set);
        if (select(pty_fd + 1, &set, NULL, NULL, &tv) <= 0) {
            break;
        }
        n = read(pty_fd, chunk, sizeof(chunk) - 1);
        if (n <= 0) {
            break;
        }
        chunk[n] = '\0';
        if (total < 64 * 1024) {
            tr_buf_add(out, chunk);
            total += (size_t)n;
        }
    }
    close(pty_fd);
    return tr_su_wait(exit_code, 2000);
}
