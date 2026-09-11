/* nax_linux/src/shared.c — Shared library (.so) entry point
 *
 * When loaded via dlopen() or LD_PRELOAD, the constructor spawns
 * agent_run() in a detached thread so the host process is not blocked.
 *
 * Compiled with: gcc ... -shared -o nax_linux.so (produces .so)
 *
 * Usage:
 *   LD_PRELOAD=./nax_linux.so /usr/bin/target_program
 *   # or from another program:
 *   dlopen("./nax_linux.so", RTLD_NOW);
 */

#include <pthread.h>
#include <unistd.h>

extern int agent_run(void);

static void *_agent_thread(void *arg)
{
    (void)arg;
    agent_run();
    return NULL;
}

__attribute__((constructor))
static void _agent_init(void)
{
    pthread_t tid;
    if (pthread_create(&tid, NULL, _agent_thread, NULL) == 0)
        pthread_detach(tid);
}
