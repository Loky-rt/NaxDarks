/* nax_bof_sdk.h — Linux BOF SDK
 * Umbrella header — include this to get the full SDK API.
 *
 * Usage:
 *   #include "nax_bof_sdk.h"
 *
 * Your agent integrates three source files:
 *   src/elf_bof.c    — in-memory ELF loader
 *   src/bof_async.c  — async job system
 *   src/bof_api.c    — BeaconAPI + symbol table
 */

#ifndef NAX_BOF_SDK_H
#define NAX_BOF_SDK_H

#include "bof_api.h"
#include "elf_bof.h"
#include "bof_async.h"

/* ── SDK initialization ──────────────────────────────────────────────────────
 * Call once at agent startup before any BOF execution.
 * Initializes the async job system and the extended symbol table.
 */
void nax_bof_sdk_init(void);

/* ── Custom symbol registration ──────────────────────────────────────────────
 * Register agent-specific symbols so BOFs can call internal agent functions.
 *
 * Example:
 *   nax_bof_register_symbol("AgentSendOutput", my_send_output);
 *   nax_bof_register_symbol("AgentGetConfig",  my_get_config);
 *
 * bof_resolve_symbol() searches the extended table first, then the base table.
 * Registration is not thread-safe — call before spawning any BOF threads.
 *
 * Returns 0 on success, -1 if the table is full (NAX_BOF_CUSTOM_SYMBOLS_MAX).
 */
#define NAX_BOF_CUSTOM_SYMBOLS_MAX 64

int nax_bof_register_symbol(const char *name, void *func);

#endif /* NAX_BOF_SDK_H */
