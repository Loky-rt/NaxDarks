#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

extern int agent_run(void);

__attribute__((visibility("default"))) unsigned char __rodata_xor_key[32]  = {1};
__attribute__((visibility("default"))) unsigned long __rodata_xor_len      = 1;
__attribute__((visibility("default"))) unsigned long __rodata_xor_addr     = 1;

#include <sys/auxv.h>
#include <elf.h>

static unsigned long _find_load_base(void)
{
    unsigned long phdr_addr = getauxval(AT_PHDR);
    unsigned long phnum     = getauxval(AT_PHNUM);
    unsigned long phent     = getauxval(AT_PHENT);

    if (!phdr_addr || !phnum || phent < sizeof(Elf64_Phdr))
        return 0;

    Elf64_Phdr *phdr = (Elf64_Phdr *)phdr_addr;
    unsigned long min_vaddr = (unsigned long)-1;

    for (unsigned long i = 0; i < phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)((unsigned char *)phdr + i * phent);
        if (ph->p_type == PT_LOAD && ph->p_vaddr < min_vaddr)
            min_vaddr = ph->p_vaddr;
    }

    if (min_vaddr == (unsigned long)-1)
        return 0;

    for (unsigned long i = 0; i < phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)((unsigned char *)phdr + i * phent);
        if (ph->p_type != PT_PHDR) continue;
        return phdr_addr - (ph->p_vaddr - min_vaddr);
    }

    return phdr_addr - min_vaddr;
}

__attribute__((constructor(101)))
static void _rodata_decrypt(void)
{
    if (__rodata_xor_len < 64) return; /* not yet patched */

    unsigned long base   = _find_load_base();
    unsigned char *rodata = (unsigned char *)(base + __rodata_xor_addr);
    unsigned long  len   = __rodata_xor_len;

    unsigned long page_size  = 4096;
    unsigned long page_start = (unsigned long)rodata & ~(page_size - 1);
    unsigned long page_end   = ((unsigned long)rodata + len + page_size - 1)
                               & ~(page_size - 1);

    if (mprotect((void *)page_start, page_end - page_start,
                 PROT_READ | PROT_WRITE) != 0)
        return;

    for (unsigned long i = 0; i < len; i++)
        rodata[i] ^= __rodata_xor_key[i % 32];

    mprotect((void *)page_start, page_end - page_start, PROT_READ);

    /* Zero the key from memory after use */
    for (int i = 0; i < 32; i++)
        ((volatile unsigned char *)__rodata_xor_key)[i] = 0;
}

int main(void)
{
    return agent_run();
}
