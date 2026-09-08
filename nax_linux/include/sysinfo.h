#pragma once
#include "nax_linux.h"
#include <stdint.h>

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

void nax_gather_sysinfo(NaxSysInfo *info);
