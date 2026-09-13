#!/usr/bin/env python3
"""rodata_crypt.py — Post-build .rodata XOR encryptor for .so files.

Encrypts the .rodata section of a compiled shared library so that
`strings` reveals nothing. A constructor in shared.c decrypts it
at load time before the agent starts.

Usage:
    python3 rodata_crypt.py <agent.so>

The script:
  1. Finds .rodata section in the ELF
  2. Generates a random 32-byte XOR key
  3. XOR-encrypts .rodata in place
  4. Writes the key into the __rodata_xor_key symbol (must exist in the binary)
  5. Writes the section size into __rodata_xor_len (must exist)
  6. Overwrites the .so file with the encrypted version

Requires: the .so must be compiled with shared.c which defines
  __rodata_xor_key[32] and __rodata_xor_len as global variables.
"""

import struct
import sys
import os

KEY_SIZE = 32

def die(msg):
    print(f"[-] {msg}", file=sys.stderr)
    sys.exit(1)

def find_section(elf, name):
    """Find a section by name, return (offset, size, addr)."""
    if elf[:4] != b'\x7fELF':
        die("Not an ELF file")
    ei_class = elf[4]
    if ei_class != 2:
        die("Only 64-bit ELF supported")

    e_shoff = struct.unpack_from('<Q', elf, 40)[0]
    e_shentsize = struct.unpack_from('<H', elf, 58)[0]
    e_shnum = struct.unpack_from('<H', elf, 60)[0]
    e_shstrndx = struct.unpack_from('<H', elf, 62)[0]

    shstr_off = struct.unpack_from('<Q', elf, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    shstr_size = struct.unpack_from('<Q', elf, e_shoff + e_shstrndx * e_shentsize + 32)[0]
    shstrtab = elf[shstr_off:shstr_off + shstr_size]

    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack_from('<I', elf, sh)[0]

        end = shstrtab.index(b'\0', sh_name_idx)
        sec_name = shstrtab[sh_name_idx:end].decode('ascii', errors='replace')

        if sec_name == name:
            sh_addr = struct.unpack_from('<Q', elf, sh + 16)[0]
            sh_offset = struct.unpack_from('<Q', elf, sh + 24)[0]
            sh_size = struct.unpack_from('<Q', elf, sh + 32)[0]
            return sh_offset, sh_size, sh_addr
    return None, None, None

def find_symbol(elf, sym_name):
    """Find a symbol's file offset by walking .dynsym then .symtab."""
    e_shoff = struct.unpack_from('<Q', elf, 40)[0]
    e_shentsize = struct.unpack_from('<H', elf, 58)[0]
    e_shnum = struct.unpack_from('<H', elf, 60)[0]
    e_shstrndx = struct.unpack_from('<H', elf, 62)[0]

    shstr_off = struct.unpack_from('<Q', elf, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    shstr_size = struct.unpack_from('<Q', elf, e_shoff + e_shstrndx * e_shentsize + 32)[0]
    shstrtab = elf[shstr_off:shstr_off + shstr_size]

    e_phoff = struct.unpack_from('<Q', elf, 32)[0]
    e_phentsize = struct.unpack_from('<H', elf, 54)[0]
    e_phnum = struct.unpack_from('<H', elf, 56)[0]
    segments = []
    for k in range(e_phnum):
        ph = e_phoff + k * e_phentsize
        p_type = struct.unpack_from('<I', elf, ph)[0]
        if p_type != 1:  # PT_LOAD
            continue
        p_offset = struct.unpack_from('<Q', elf, ph + 8)[0]
        p_vaddr = struct.unpack_from('<Q', elf, ph + 16)[0]
        p_filesz = struct.unpack_from('<Q', elf, ph + 32)[0]
        p_memsz = struct.unpack_from('<Q', elf, ph + 40)[0]
        segments.append((p_vaddr, p_offset, p_filesz, p_memsz))

    def vaddr_to_foff(vaddr):
        for sv, so, sf, sm in segments:
            if sv <= vaddr < sv + sm:
                off = so + (vaddr - sv)
                if off < len(elf):
                    return off
        return None

    for tab_name in ['.dynsym', '.symtab']:
        symtab_off = None
        symtab_size = 0
        symtab_entsize = 0
        strtab_off = None

        for i in range(e_shnum):
            sh = e_shoff + i * e_shentsize
            sh_name_idx = struct.unpack_from('<I', elf, sh)[0]
            end = shstrtab.index(b'\0', sh_name_idx)
            sec_name = shstrtab[sh_name_idx:end].decode('ascii', errors='replace')
            if sec_name == tab_name:
                symtab_off = struct.unpack_from('<Q', elf, sh + 24)[0]
                symtab_size = struct.unpack_from('<Q', elf, sh + 32)[0]
                symtab_entsize = struct.unpack_from('<Q', elf, sh + 56)[0]
                sh_link = struct.unpack_from('<I', elf, sh + 40)[0]
                link_sh = e_shoff + sh_link * e_shentsize
                strtab_off = struct.unpack_from('<Q', elf, link_sh + 24)[0]

        if symtab_off is None or strtab_off is None:
            continue

        num_syms = symtab_size // symtab_entsize
        for j in range(num_syms):
            sym = symtab_off + j * symtab_entsize
            st_name = struct.unpack_from('<I', elf, sym)[0]
            st_value = struct.unpack_from('<Q', elf, sym + 8)[0]
            st_shndx = struct.unpack_from('<H', elf, sym + 6)[0]

            name_end = elf.index(b'\0', strtab_off + st_name)
            name = elf[strtab_off + st_name:name_end].decode('ascii', errors='replace')

            if name == sym_name and st_value != 0 and st_shndx != 0:
                file_off = vaddr_to_foff(st_value)
                if file_off is not None:
                    return file_off

    return None

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <agent.so>")
        sys.exit(1)

    so_path = sys.argv[1]
    elf = bytearray(open(so_path, 'rb').read())

    rodata_off, rodata_size, rodata_addr = find_section(elf, '.rodata')
    if rodata_off is None:
        die(".rodata section not found")
#    print(f"[+] .rodata: offset=0x{rodata_off:x} size={rodata_size} addr=0x{rodata_addr:x}")

    key_off = find_symbol(elf, '__rodata_xor_key')
    if key_off is None:
        die("Symbol __rodata_xor_key not found — is shared.c compiled in?")
#    print(f"[+] __rodata_xor_key at file offset 0x{key_off:x}")

    len_off = find_symbol(elf, '__rodata_xor_len')
    if len_off is None:
        die("Symbol __rodata_xor_len not found — is shared.c compiled in?")
#    print(f"[+] __rodata_xor_len at file offset 0x{len_off:x}")

    addr_off = find_symbol(elf, '__rodata_xor_addr')
    if addr_off is None:
        die("Symbol __rodata_xor_addr not found — is shared.c compiled in?")
#    print(f"[+] __rodata_xor_addr at file offset 0x{addr_off:x}")

    key = os.urandom(KEY_SIZE)
#    print(f"[+] XOR key: {key.hex()[:16]}...")

    elf[key_off:key_off + KEY_SIZE] = key

    struct.pack_into('<Q', elf, len_off, rodata_size)

    struct.pack_into('<Q', elf, addr_off, rodata_addr)

    for i in range(rodata_size):
        elf[rodata_off + i] ^= key[i % KEY_SIZE]

    with open(so_path, 'wb') as f:
        f.write(elf)

#    print(f"[+] {so_path}: .rodata encrypted ({rodata_size} bytes)")

if __name__ == '__main__':
    main()
