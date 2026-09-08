/* elf_bof.h — ELF BOF Loader for Linux Agent
 * In-memory loader for ELF relocatable objects (.o files compiled with gcc -c)
 * Supports x86_64 and ARM64 relocations.
 */

#ifndef ELF_BOF_H
#define ELF_BOF_H

#include <stdint.h>
#include <stddef.h>

/* ── ELF64 structures ── */

typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t  Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;

typedef struct {
    unsigned char e_ident[16];
    Elf64_Half    e_type;
    Elf64_Half    e_machine;
    Elf64_Word    e_version;
    Elf64_Addr    e_entry;
    Elf64_Off     e_phoff;
    Elf64_Off     e_shoff;
    Elf64_Word    e_flags;
    Elf64_Half    e_ehsize;
    Elf64_Half    e_phentsize;
    Elf64_Half    e_phnum;
    Elf64_Half    e_shentsize;
    Elf64_Half    e_shnum;
    Elf64_Half    e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    Elf64_Word    sh_name;
    Elf64_Word    sh_type;
    Elf64_Xword   sh_flags;
    Elf64_Addr    sh_addr;
    Elf64_Off     sh_offset;
    Elf64_Xword   sh_size;
    Elf64_Word    sh_link;
    Elf64_Word    sh_info;
    Elf64_Xword   sh_addralign;
    Elf64_Xword   sh_entsize;
} Elf64_Shdr;

typedef struct {
    Elf64_Word    st_name;
    unsigned char st_info;
    unsigned char st_other;
    Elf64_Half    st_shndx;
    Elf64_Addr    st_value;
    Elf64_Xword   st_size;
} Elf64_Sym;

typedef struct {
    Elf64_Addr    r_offset;
    Elf64_Xword   r_info;
    Elf64_Sxword  r_addend;
} Elf64_Rela;

/* ── ELF macros ── */

#define ELF64_R_SYM(i)    ((i) >> 32)
#define ELF64_R_TYPE(i)   ((i) & 0xffffffffL)
#define ELF64_ST_BIND(i)  ((unsigned char)(i) >> 4)
#define ELF64_ST_TYPE(i)  ((i) & 0xf)

#define ELFMAG0  0x7f
#define ELFMAG1  'E'
#define ELFMAG2  'L'
#define ELFMAG3  'F'
#define ELFCLASS64  2
#define ELFDATA2LSB 1

#define ET_REL      1
#define EM_X86_64   62
#define EM_AARCH64  183

#define SHT_NULL     0
#define SHT_PROGBITS 1
#define SHT_SYMTAB   2
#define SHT_STRTAB   3
#define SHT_RELA     4
#define SHT_NOBITS   8

#define SHF_WRITE     0x1
#define SHF_ALLOC     0x2
#define SHF_EXECINSTR 0x4

#define STB_LOCAL  0
#define STB_GLOBAL 1
#define STB_WEAK   2
#define STT_NOTYPE 0
#define STT_FUNC   2
#define SHN_UNDEF  0

/* x86_64 relocation types */
#define R_X86_64_64    1
#define R_X86_64_PC32  2
#define R_X86_64_PLT32 4
#define R_X86_64_32    10
#define R_X86_64_32S   11

/* ARM64 relocation types */
#define R_AARCH64_ABS64              257
#define R_AARCH64_CALL26             283
#define R_AARCH64_JUMP26             282
#define R_AARCH64_ADR_PREL_PG_HI21  275
#define R_AARCH64_ADD_ABS_LO12_NC   277
#define R_AARCH64_LDST8_ABS_LO12_NC   278
#define R_AARCH64_LDST16_ABS_LO12_NC  284
#define R_AARCH64_LDST32_ABS_LO12_NC  285
#define R_AARCH64_LDST64_ABS_LO12_NC  286
#define R_AARCH64_LDST128_ABS_LO12_NC 299

/* ── BOF constants ── */

#define BOF_MAX_SECTIONS    64
#define BOF_MAX_TRAMPOLINES 128
#define BOF_OUTPUT_MAX      (4 * 1024 * 1024) /* 4 MB max output */

/* ── Public API ── */

/* Execute an ELF BOF in-memory (synchronous).
 * elf_data/elf_size: raw .o file content
 * args/args_size:    packed arguments for the BOF (CS-format), NULL if none
 * entry_name:        entry function name (usually "go")
 * output:            receives malloc'd output string, caller must free
 * output_len:        receives output length
 * Returns 0 on success, -1 on error (error message in output). */
int nax_bof_execute(const uint8_t *elf_data, uint32_t elf_size,
                    const uint8_t *args, uint32_t args_size,
                    const char *entry_name,
                    char **output, uint32_t *output_len);

#endif /* ELF_BOF_H */
