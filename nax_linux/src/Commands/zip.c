/* ===== zip.c — zip command ======================================
 *
 * Implements NAX_CMD_ZIP (0x2A): compress a file or directory into a ZIP
 * archive using zlib (deflate). Produces a valid PKZIP-compatible archive.
 *
 * Wire protocol (task args): [src_len(4LE)][src_path][dst_len(4LE)][dst_path]
 * Result: success message or error string.
 * ========================================================================= */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <zlib.h>

#include "../../include/nax_linux.h"

/* ===== ZIP format structs ===== */

#pragma pack(push, 1)
typedef struct {
    uint32_t sig;           /* 0x04034b50 */
    uint16_t ver_needed;
    uint16_t flags;
    uint16_t method;        /* 0=store, 8=deflate */
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint32_t comp_size;
    uint32_t uncomp_size;
    uint16_t fname_len;
    uint16_t extra_len;
} ZipLocalHdr;

typedef struct {
    uint32_t sig;           /* 0x02014b50 */
    uint16_t ver_made;
    uint16_t ver_needed;
    uint16_t flags;
    uint16_t method;
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint32_t comp_size;
    uint32_t uncomp_size;
    uint16_t fname_len;
    uint16_t extra_len;
    uint16_t comment_len;
    uint16_t disk_start;
    uint16_t int_attrs;
    uint32_t ext_attrs;
    uint32_t local_hdr_off;
} ZipCentralHdr;

typedef struct {
    uint32_t sig;           /* 0x06054b50 */
    uint16_t disk_num;
    uint16_t disk_start;
    uint16_t entries_this;
    uint16_t entries_total;
    uint32_t central_size;
    uint32_t central_off;
    uint16_t comment_len;
} ZipEOCD;
#pragma pack(pop)

/* ===== dynamic output buffer ===== */
typedef struct { uint8_t *buf; size_t len; size_t cap; } ZBuf;

static int zbuf_append(ZBuf *b, const void *data, size_t n) {
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 65536;
        while (nc < b->len + n) nc *= 2;
        uint8_t *p = realloc(b->buf, nc);
        if (!p) return -1;
        b->buf = p; b->cap = nc;
    }
    memcpy(b->buf + b->len, data, n);
    b->len += n;
    return 0;
}

/* ===== DOS time conversion ===== */
static void unix_to_dos(time_t t, uint16_t *dos_time, uint16_t *dos_date) {
    struct tm *tm = localtime(&t);
    if (!tm) { *dos_time = 0; *dos_date = 0; return; }
    *dos_time = (uint16_t)(((tm->tm_hour & 0x1F) << 11) |
                            ((tm->tm_min  & 0x3F) << 5)  |
                            ((tm->tm_sec >> 1) & 0x1F));
    *dos_date = (uint16_t)((((tm->tm_year - 80) & 0x7F) << 9) |
                            (((tm->tm_mon + 1)   & 0x0F) << 5) |
                              (tm->tm_mday        & 0x1F));
}

/* ===== central directory entry list ===== */
typedef struct CdEntry {
    uint8_t       *hdr;
    size_t         hdr_len;
    struct CdEntry *next;
} CdEntry;

/* ===== add one file to the zip output buffer ===== */
static int zip_add_file(ZBuf *out, CdEntry **cd_head, size_t *cd_count,
                         const char *zip_name, const char *fs_path, int is_dir)
{
    uint8_t  *file_data   = NULL;
    size_t    file_size   = 0;
    uint8_t  *comp_data   = NULL;
    uLongf    comp_size   = 0;
    uint32_t  crc         = 0;
    uint16_t  method      = 0; /* store by default (dirs + tiny files) */
    uint16_t  dos_time = 0, dos_date = 0;
    time_t    mtime = time(NULL);

    if (!is_dir) {
        struct stat st;
        if (stat(fs_path, &st) != 0) return -1;
        mtime     = st.st_mtime;
        file_size = (size_t)st.st_size;

        if (file_size > 0) {
            file_data = malloc(file_size);
            if (!file_data) return -1;
            int fd = open(fs_path, O_RDONLY);
            if (fd < 0) { free(file_data); return -1; }
            size_t got = 0;
            while (got < file_size) {
                ssize_t r = read(fd, file_data + got, file_size - got);
                if (r <= 0) break;
                got += (size_t)r;
            }
            close(fd);
            file_size = got;

            crc = (uint32_t)crc32(0L, file_data, (uInt)file_size);

            /* Try deflate — only keep if smaller */
            comp_size = compressBound((uLong)file_size);
            comp_data = malloc(comp_size);
            if (comp_data) {
                z_stream zs = {0};
                deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                             -15, 8, Z_DEFAULT_STRATEGY);
                zs.next_in   = file_data;
                zs.avail_in  = (uInt)file_size;
                zs.next_out  = comp_data;
                zs.avail_out = (uInt)comp_size;
                deflate(&zs, Z_FINISH);
                comp_size = (uLongf)zs.total_out;
                deflateEnd(&zs);
                if (comp_size < file_size) {
                    method = 8; /* deflate */
                } else {
                    free(comp_data); comp_data = NULL;
                    comp_size = file_size;
                }
            } else {
                comp_size = file_size;
            }
        }
    } else {
        struct stat st;
        if (stat(fs_path, &st) == 0) mtime = st.st_mtime;
    }

    unix_to_dos(mtime, &dos_time, &dos_date);

    uint16_t fname_len = (uint16_t)strlen(zip_name);
    size_t local_off   = out->len;

    ZipLocalHdr lh = {0};
    lh.sig        = 0x04034b50;
    lh.ver_needed = 20;
    lh.method     = method;
    lh.mod_time   = dos_time;
    lh.mod_date   = dos_date;
    lh.crc32      = crc;
    lh.comp_size  = (uint32_t)(method == 8 ? comp_size : file_size);
    lh.uncomp_size= (uint32_t)file_size;
    lh.fname_len  = fname_len;
    lh.extra_len  = 0;

    zbuf_append(out, &lh, sizeof(lh));
    zbuf_append(out, zip_name, fname_len);

    if (!is_dir && file_size > 0) {
        if (method == 8)
            zbuf_append(out, comp_data, comp_size);
        else
            zbuf_append(out, file_data, file_size);
    }

    free(file_data);
    free(comp_data);

    /* Central directory entry */
    size_t cd_len = sizeof(ZipCentralHdr) + fname_len;
    uint8_t *cd_buf = malloc(cd_len);
    if (!cd_buf) return -1;

    ZipCentralHdr ch = {0};
    ch.sig         = 0x02014b50;
    ch.ver_made    = 20;
    ch.ver_needed  = 20;
    ch.method      = method;
    ch.mod_time    = dos_time;
    ch.mod_date    = dos_date;
    ch.crc32       = crc;
    ch.comp_size   = lh.comp_size;
    ch.uncomp_size = (uint32_t)file_size;
    ch.fname_len   = fname_len;
    ch.ext_attrs   = is_dir ? 0x10 : 0x20;
    ch.local_hdr_off = (uint32_t)local_off;

    memcpy(cd_buf, &ch, sizeof(ch));
    memcpy(cd_buf + sizeof(ch), zip_name, fname_len);

    CdEntry *entry = malloc(sizeof(CdEntry));
    if (!entry) { free(cd_buf); return -1; }
    entry->hdr     = cd_buf;
    entry->hdr_len = cd_len;
    entry->next    = *cd_head;
    *cd_head = entry;
    (*cd_count)++;

    return 0;
}

/* ===== recursively add directory ===== */
static int zip_add_dir(ZBuf *out, CdEntry **cd_head, size_t *cd_count,
                        const char *base_fs, const char *base_zip,
                        const char *rel_path)
{
    char fs_path[4096], zip_name[4096];
    if (rel_path && *rel_path) {
        snprintf(fs_path,  sizeof(fs_path),  "%s/%s", base_fs, rel_path);
        snprintf(zip_name, sizeof(zip_name), "%s/%s/", base_zip, rel_path);
    } else {
        snprintf(fs_path,  sizeof(fs_path),  "%s", base_fs);
        snprintf(zip_name, sizeof(zip_name), "%s/", base_zip);
    }

    zip_add_file(out, cd_head, cd_count, zip_name, fs_path, 1);

    DIR *d = opendir(fs_path);
    if (!d) return -1;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char sub_fs[4096], sub_zip[4096], sub_rel[4096];
        snprintf(sub_fs,  sizeof(sub_fs),  "%s/%s", fs_path, de->d_name);
        if (rel_path && *rel_path)
            snprintf(sub_rel, sizeof(sub_rel), "%s/%s", rel_path, de->d_name);
        else
            snprintf(sub_rel, sizeof(sub_rel), "%s", de->d_name);

        struct stat st;
        if (stat(sub_fs, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            zip_add_dir(out, cd_head, cd_count, base_fs, base_zip, sub_rel);
        } else if (S_ISREG(st.st_mode)) {
            snprintf(sub_zip, sizeof(sub_zip), "%s/%s", base_zip, sub_rel);
            zip_add_file(out, cd_head, cd_count, sub_zip, sub_fs, 0);
        }
    }
    closedir(d);
    return 0;
}

/* ===== public command handler ===== */
uint8_t nax_cmd_zip(NaxAgent *a, NaxTask *t, uint8_t **out, uint32_t *out_len)
{
    (void)a;
    *out = NULL; *out_len = 0;

    /* Parse args: [src_len(4LE)][src][dst_len(4LE)][dst] */
    if (!t->args || t->args_len < 8) {
        const char *msg = "zip: args too short";
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
        return NAX_STATUS_ERR;
    }

    uint32_t src_len = (uint32_t)t->args[0] | ((uint32_t)t->args[1]<<8) |
                       ((uint32_t)t->args[2]<<16) | ((uint32_t)t->args[3]<<24);
    if (t->args_len < 4 + src_len + 4) {
        const char *msg = "zip: bad src_len";
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
        return NAX_STATUS_ERR;
    }

    char src[4096] = {0}, dst[4096] = {0};
    if (src_len >= sizeof(src)) src_len = sizeof(src) - 1;
    memcpy(src, t->args + 4, src_len);

    uint32_t dst_len = (uint32_t)t->args[4+src_len]   | ((uint32_t)t->args[5+src_len]<<8) |
                       ((uint32_t)t->args[6+src_len]<<16) | ((uint32_t)t->args[7+src_len]<<24);
    if (t->args_len < 8 + src_len + dst_len) {
        const char *msg = "zip: bad dst_len";
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
        return NAX_STATUS_ERR;
    }
    if (dst_len >= sizeof(dst)) dst_len = sizeof(dst) - 1;
    memcpy(dst, t->args + 8 + src_len, dst_len);

    /* Determine if src is file or directory */
    struct stat st;
    if (stat(src, &st) != 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "zip: stat '%s': %s", src, strerror(errno));
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
        return NAX_STATUS_ERR;
    }

    /* Build the archive in memory */
    ZBuf out_buf = {0};
    CdEntry *cd_head = NULL;
    size_t   cd_count = 0;

    /* Derive a clean base name for the zip root entry */
    const char *base_name = strrchr(src, '/');
    base_name = base_name ? base_name + 1 : src;

    int rc;
    if (S_ISDIR(st.st_mode)) {
        rc = zip_add_dir(&out_buf, &cd_head, &cd_count, src, base_name, NULL);
    } else {
        rc = zip_add_file(&out_buf, &cd_head, &cd_count, base_name, src, 0);
    }

    if (rc != 0) {
        free(out_buf.buf);
        while (cd_head) { CdEntry *n = cd_head->next; free(cd_head->hdr); free(cd_head); cd_head = n; }
        const char *msg = "zip: failed to compress source";
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
        return NAX_STATUS_ERR;
    }

    /* Write central directory (reverse the list to get correct order) */
    /* Reverse cd_head list first */
    CdEntry *prev = NULL, *cur = cd_head;
    while (cur) { CdEntry *nx = cur->next; cur->next = prev; prev = cur; cur = nx; }
    cd_head = prev;

    uint32_t cd_off = (uint32_t)out_buf.len;
    uint32_t cd_size = 0;
    CdEntry *e = cd_head;
    while (e) {
        zbuf_append(&out_buf, e->hdr, e->hdr_len);
        cd_size += (uint32_t)e->hdr_len;
        CdEntry *nx = e->next; free(e->hdr); free(e); e = nx;
    }

    ZipEOCD eocd = {0};
    eocd.sig          = 0x06054b50;
    eocd.entries_this  = (uint16_t)cd_count;
    eocd.entries_total = (uint16_t)cd_count;
    eocd.central_size  = cd_size;
    eocd.central_off   = cd_off;
    zbuf_append(&out_buf, &eocd, sizeof(eocd));

    /* Write to dst file */
    FILE *f = fopen(dst, "wb");
    if (!f) {
        free(out_buf.buf);
        char msg[512];
        snprintf(msg, sizeof(msg), "zip: fopen '%s': %s", dst, strerror(errno));
        *out = (uint8_t *)strdup(msg); *out_len = strlen(msg);
        return NAX_STATUS_ERR;
    }
    fwrite(out_buf.buf, 1, out_buf.len, f);
    fclose(f);
    free(out_buf.buf);

    /* Return success message */
    char msg[512];
    snprintf(msg, sizeof(msg),
             "Archive '%s' created successfully (%zu bytes)", dst, out_buf.len);
    *out = (uint8_t *)strdup(msg);
    *out_len = (uint32_t)strlen(msg);
    return NAX_STATUS_OK;
}
