/*
 * rodata_crypt.c — Post-build .rodata XOR encryptor (replaces rodata_crypt.py)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <elf.h>

#define KEY_SIZE 32

static void die(const char *msg)
{
    fprintf(stderr, "[-] %s\n", msg);
    exit(1);
}

static void die_errno(const char *msg)
{
    fprintf(stderr, "[-] %s: %s\n", msg, strerror(errno));
    exit(1);
}

static uint8_t *read_file(const char *path, size_t *size)
{
    FILE *f = fopen(path, "rb");
    if (!f) die_errno(path);

    struct stat st;
    if (fstat(fileno(f), &st) != 0) die_errno("fstat");
    *size = (size_t)st.st_size;

    uint8_t *buf = malloc(*size);
    if (!buf) die("out of memory");
    if (fread(buf, 1, *size, f) != *size) die("short read");
    fclose(f);
    return buf;
}

static void write_file(const char *path, const uint8_t *buf, size_t size)
{
    char tmp[4096];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    FILE *f = fopen(tmp, "wb");
    if (!f) die_errno(tmp);
    if (fwrite(buf, 1, size, f) != size) { fclose(f); die("short write"); }
    fclose(f);

    if (rename(tmp, path) != 0) die_errno("rename");
}

static void random_bytes(uint8_t *buf, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) die_errno("/dev/urandom");
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) die_errno("read /dev/urandom");
        got += (size_t)r;
    }
    close(fd);
}

typedef struct {
    uint64_t offset;
    uint64_t size;
    uint64_t addr;
} Section;

typedef struct {
    uint64_t file_offset;
} Symbol;

static void validate_elf(const uint8_t *elf, size_t elf_size)
{
    if (elf_size < sizeof(Elf64_Ehdr))
        die("file too small to be ELF");
    if (memcmp(elf, ELFMAG, SELFMAG) != 0)
        die("not an ELF file");
    if (elf[EI_CLASS] != ELFCLASS64)
        die("only 64-bit ELF supported");
}

static const Elf64_Shdr *shdr_at(const uint8_t *elf, size_t elf_size,
                                   const Elf64_Ehdr *eh, int i)
{
    size_t off = eh->e_shoff + (size_t)i * eh->e_shentsize;
    if (off + sizeof(Elf64_Shdr) > elf_size)
        die("section header out of bounds");
    return (const Elf64_Shdr *)(elf + off);
}

static const char *section_name(const uint8_t *elf, size_t elf_size,
                                 const Elf64_Ehdr *eh, int i)
{
    const Elf64_Shdr *shstr = shdr_at(elf, elf_size, eh, eh->e_shstrndx);
    const Elf64_Shdr *sh    = shdr_at(elf, elf_size, eh, i);

    size_t name_off = shstr->sh_offset + sh->sh_name;
    if (name_off >= elf_size) die("section name out of bounds");
    return (const char *)(elf + name_off);
}

static int find_section(const uint8_t *elf, size_t elf_size,
                         const char *name, Section *out)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)elf;
    for (int i = 0; i < eh->e_shnum; i++) {
        if (strcmp(section_name(elf, elf_size, eh, i), name) == 0) {
            const Elf64_Shdr *sh = shdr_at(elf, elf_size, eh, i);
            out->offset = sh->sh_offset;
            out->size   = sh->sh_size;
            out->addr   = sh->sh_addr;
            return 1;
        }
    }
    return 0;
}

static uint64_t vaddr_to_foff(const uint8_t *elf, size_t elf_size,
                               uint64_t vaddr)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)elf;
    for (int k = 0; k < eh->e_phnum; k++) {
        size_t ph_off = eh->e_phoff + (size_t)k * eh->e_phentsize;
        if (ph_off + sizeof(Elf64_Phdr) > elf_size) continue;
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(elf + ph_off);
        if (ph->p_type != PT_LOAD) continue;
        if (vaddr >= ph->p_vaddr && vaddr < ph->p_vaddr + ph->p_memsz) {
            uint64_t foff = ph->p_offset + (vaddr - ph->p_vaddr);
            if (foff < elf_size) return foff;
        }
    }
    return (uint64_t)-1;
}

static uint64_t search_symtab(const uint8_t *elf, size_t elf_size,
                                const Elf64_Ehdr *eh,
                                int tab_idx, const char *sym_name)
{
    const Elf64_Shdr *symsh  = shdr_at(elf, elf_size, eh, tab_idx);
    const Elf64_Shdr *strsh  = shdr_at(elf, elf_size, eh, symsh->sh_link);

    size_t entsize = symsh->sh_entsize ? symsh->sh_entsize : sizeof(Elf64_Sym);
    size_t nsyms   = symsh->sh_size / entsize;

    for (size_t j = 0; j < nsyms; j++) {
        size_t sym_off = symsh->sh_offset + j * entsize;
        if (sym_off + sizeof(Elf64_Sym) > elf_size) break;
        const Elf64_Sym *sym = (const Elf64_Sym *)(elf + sym_off);

        if (sym->st_value == 0 || sym->st_shndx == SHN_UNDEF) continue;

        size_t name_off = strsh->sh_offset + sym->st_name;
        if (name_off >= elf_size) continue;
        const char *name = (const char *)(elf + name_off);

        if (strcmp(name, sym_name) == 0) {
            uint64_t foff = vaddr_to_foff(elf, elf_size, sym->st_value);
            if (foff != (uint64_t)-1) return foff;
        }
    }
    return (uint64_t)-1;
}

static uint64_t find_symbol(const uint8_t *elf, size_t elf_size,
                              const char *sym_name)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)elf;

    for (int i = 0; i < eh->e_shnum; i++) {
        const Elf64_Shdr *sh = shdr_at(elf, elf_size, eh, i);
        if (sh->sh_type != SHT_DYNSYM && sh->sh_type != SHT_SYMTAB) continue;
        if (sh->sh_link == 0 || sh->sh_link >= eh->e_shnum) continue;

        uint64_t foff = search_symtab(elf, elf_size, eh, i, sym_name);
        if (foff != (uint64_t)-1) return foff;
    }
    return (uint64_t)-1;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <agent.so|agent_exe>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    size_t elf_size;
    uint8_t *elf = read_file(path, &elf_size);

    validate_elf(elf, elf_size);

    Section rodata;
    if (!find_section(elf, elf_size, ".rodata", &rodata))
        die(".rodata section not found");

    uint64_t key_foff  = find_symbol(elf, elf_size, "__rodata_xor_key");
    uint64_t len_foff  = find_symbol(elf, elf_size, "__rodata_xor_len");
    uint64_t addr_foff = find_symbol(elf, elf_size, "__rodata_xor_addr");

    if (key_foff  == (uint64_t)-1) die("symbol __rodata_xor_key not found");
    if (len_foff  == (uint64_t)-1) die("symbol __rodata_xor_len not found");
    if (addr_foff == (uint64_t)-1) die("symbol __rodata_xor_addr not found");

    if (key_foff + KEY_SIZE > elf_size) die("__rodata_xor_key out of bounds");
    if (len_foff  + 8 > elf_size)       die("__rodata_xor_len out of bounds");
    if (addr_foff + 8 > elf_size)       die("__rodata_xor_addr out of bounds");
    if (rodata.offset + rodata.size > elf_size)
        die(".rodata extends beyond file");

    uint8_t key[KEY_SIZE];
    random_bytes(key, KEY_SIZE);

    memcpy(elf + key_foff, key, KEY_SIZE);

    uint64_t rodata_size = rodata.size;
    memcpy(elf + len_foff, &rodata_size, 8);

    uint64_t rodata_addr = rodata.addr;
    memcpy(elf + addr_foff, &rodata_addr, 8);

    uint8_t *rd = elf + rodata.offset;
    for (uint64_t i = 0; i < rodata.size; i++)
        rd[i] ^= key[i % KEY_SIZE];

    write_file(path, elf, elf_size);

    free(elf);
    return 0;
}
