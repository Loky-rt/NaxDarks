/* opsec.h — Anti-debug, anti-VM, self-destruct */

#ifndef NAX_OPSEC_H
#define NAX_OPSEC_H

#ifdef NAX_OPSEC

void nax_opsec_check(void);      /* once at startup */
void nax_opsec_heartbeat(void);  /* periodic — call from heartbeat loop */
void nax_opsec_cleanup(void);    /* at exit */

#else

#define nax_opsec_check()     ((void)0)
#define nax_opsec_heartbeat() ((void)0)
#define nax_opsec_cleanup()   ((void)0)

#endif
#endif
