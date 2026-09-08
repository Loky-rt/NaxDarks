#ifndef LINUX_BEACON_API_H
#define LINUX_BEACON_API_H

#include <sys/statvfs.h>
#include <time.h>
#include <stddef.h>
#include <stdarg.h>
#include <sys/wait.h>      // waitpid
#include <signal.h>        // kill
#include <sys/ptrace.h>    // ptrace
#include <sys/uio.h>       // process_vm_readv/writev
#include <sys/stat.h>      // chmod, fchmod
#include <sys/ioctl.h>     // ioctl
#include <sys/sysinfo.h>   // sysinfo
#include <sys/utsname.h>   // uname
#include <linux/io_uring.h>// io_uring

/* ── Data parser types ── */

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} formatp;

/* Output types (CS-compatible) */

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d

/* Data Parser API */

void   BeaconDataParse(datap *parser, char *buffer, int size);
int    BeaconDataInt(datap *parser);
short  BeaconDataShort(datap *parser);
int    BeaconDataLength(datap *parser);
char  *BeaconDataExtract(datap *parser, int *size);

/* Output API */

void   BeaconOutput(int type, const char *data, int len);
void   BeaconPrintf(int type, const char *fmt, ...);

/* Format API */

void   BeaconFormatAlloc(formatp *format, int maxsz);
void   BeaconFormatReset(formatp *format);
void   BeaconFormatAppend(formatp *format, const char *text, int len);
void   BeaconFormatPrintf(formatp *format, const char *fmt, ...);
char  *BeaconFormatToString(formatp *format, int *size);
void   BeaconFormatFree(formatp *format);
void   BeaconFormatInt(formatp *format, int value);

/* Utility */

int    BeaconIsAdmin(void);
int    BeaconGetStopJobEvent(void);

/* File system */

int    AxFstatvfs(int fd, struct statvfs *buf);
int    AxStatvfs(const char *path, struct statvfs *buf);
int    AxWriteFile(int fd, const void *buf, int count);
char   *AxRealpath(const char *path, char *resolved_path);
int    AxOpenFile(const char *path, int flags, int mode);
int    AxCloseFile(int fd);
int    AxReadFile(int fd, void *buf, int count);
int    AxReadFileToBuffer(const char *path, char **out_buf, int max_size);
int    AxFileStat(const char *path, unsigned int *out_mode, long *out_size,
                  unsigned int *out_uid, unsigned int *out_gid);
int    AxOpenDir(const char *path);
int    AxReadDir(int fd, void *buf, int bufsize);

/* Memory */

void  *AxMalloc(int size);
void   AxFree(void *ptr);
void  *AxMemset(void *s, int c, int n);
void  *AxMemcpy(void *dst, const void *src, int n);

/* Strings */

int    AxStrlen(const char *s);
int    AxStrcmp(const char *a, const char *b);
int    AxStrncmp(const char *a, const char *b, int n);
char  *AxStrcpy(char *dst, const char *src);
char  *AxStrncpy(char *dst, const char *src, int n);
char  *AxStrcat(char *dst, const char *src);
char  *AxStrstr(const char *haystack, const char *needle);
char  *AxStrchr(const char *s, int c);
int    AxSnprintf(char *buf, int size, const char *fmt, ...);

/* Process info */

int    AxGetPid(void);
int    AxGetUid(void);
int    AxGetEuid(void);
int    AxGetCwd(char *buf, int size);
int    AxGetEnv(const char *name, char *out_buf, int out_size);

/* File timestamps */

int    AxFileTime(const char *path, long *atime, long *mtime);
int    AxSetFileTime(const char *path, long atime, long mtime);

/* Networking */

int    AxSocket(int domain, int type, int protocol);
int    AxConnect(int sockfd, const void *addr, int addrlen);
int    AxBind(int sockfd, const void *addr, int addrlen);
int    AxListen(int sockfd, int backlog);
int    AxAccept(int sockfd, void *addr, int *addrlen);
int    AxSend(int sockfd, const void *buf, int len, int flags);
int    AxRecv(int sockfd, void *buf, int len, int flags);
int    AxSendto(int sockfd, const void *buf, int len, int flags,
                const void *dest_addr, int addrlen);
int    AxRecvfrom(int sockfd, void *buf, int len, int flags,
                  void *src_addr, int *addrlen);
int    AxClose(int fd);
int    AxSetsockopt(int sockfd, int level, int optname,
                    const void *optval, int optlen);
int    AxGetsockopt(int sockfd, int level, int optname,
                    void *optval, int *optlen);

/* Address conversion */

int            AxInetPton(int af, const char *src, void *dst);
const char    *AxInetNtop(int af, const void *src, char *dst, int size);
char          *AxInetNtoa(unsigned int addr);
unsigned short AxHtons(unsigned short hostshort);
unsigned short AxNtohs(unsigned short netshort);

/* System */

int    AxGetErrno(void);
int    AxFcntl(int fd, int cmd, int arg);
int    AxPoll(void *fds, int nfds, int timeout_ms);

/* NEW APIs Process control */

int     AxClone(int (*fn)(void *), void *child_stack, int flags, void *arg);
int     AxExecveat(int dirfd, const char *pathname, char *const argv[],
                   char *const envp[], int flags);
int     AxSocketpair(int domain, int type, int protocol, int sv[2]);
void AxExit(int status);
int  AxPipe(int fd[2]);
int  AxMemfdCreate(const char *name, unsigned int flags);
int  AxFexecve(int fd, char *const argv[], char *const envp[]);
int     AxFork(void);
int     AxExecve(const char *path, char *const argv[], char *const envp[]);
int     AxWaitpid(int pid, int *status, int options);
int     AxKill(int pid, int sig);
long    AxPtrace(int request, int pid, void *addr, void *data);
ssize_t AxProcessVmReadv(int pid, const struct iovec *local_iov,
                         unsigned long liovcnt,
                         const struct iovec *remote_iov,
                         unsigned long riovcnt, unsigned long flags);
ssize_t AxProcessVmWritev(int pid, const struct iovec *local_iov,
                          unsigned long liovcnt,
                          const struct iovec *remote_iov,
                          unsigned long riovcnt, unsigned long flags);
int     AxPidfdOpen(int pid, unsigned int flags);
int     AxPidfdGetfd(int pidfd, int targetfd, unsigned int flags);

/* Advanced filesystem */

int     AxChdir(const char *path);
int     AxFchdir(int fd);
int     AxChmod(const char *path, mode_t mode);
int     AxFchmod(int fd, mode_t mode);
int     AxChown(const char *path, uid_t owner, gid_t group);
int     AxFchown(int fd, uid_t owner, gid_t group);
int     AxSymlink(const char *target, const char *linkpath);
ssize_t AxReadlink(const char *path, char *buf, size_t bufsiz);
int     AxDup(int oldfd);
int     AxDup2(int oldfd, int newfd);
int     AxIoctl(int fd, unsigned long request, ...);

/* System info */

int     AxSysinfo(struct sysinfo *info);
int     AxUname(struct utsname *buf);

/* io_uring */

int     AxIoUringSetup(unsigned int entries, struct io_uring_params *p);
int     AxIoUringEnter(int fd, unsigned int to_submit,
                       unsigned int min_complete, unsigned int flags);
int     AxIoUringRegister(int fd, unsigned int opcode, void *arg,
                          unsigned int nr_args);

/* Time */
struct tm *AxLocaltime(const time_t *timer);

/* ── Inter-BOF shared globals (persist across BOF executions) ── */

void  *AxGetGlobal(const char *key);
/* key MUST have static or permanent lifetime (e.g. a string literal).
 * The pointer is stored directly — no copy is made. */
void   AxSetGlobal(const char *key, void *ptr);

#endif /* LINUX_BEACON_API_H */
