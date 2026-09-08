# Transport

NaxDarks supports three transport modes, selected at compile time. Each mode produces a different binary with its own communication logic.

---

## Transport Modes

| Mode | Flag | Binary suffix | Direction | Use case |
|------|------|---------------|-----------|----------|
| **HTTPS** | `NAX_TCP_MODE=https` | `_https` | Agent → C2 | Primary transport with malleable profiles |
| **TCP Connect-out** | `NAX_TCP_MODE=connect` | _(none)_ | Agent → C2 | Direct TCP, interactive |
| **TCP Bind** | `NAX_TCP_MODE=bind` | `_bind` | Parent → Agent | Pivoting through chained agents |

```
                    ┌──────────┐
Internet ───HTTPS──▶│  Agent A │ (HTTPS parent)
                    │  :443    │
                    └────┬─────┘
                         │ TCP connect
                         ▼
                    ┌──────────┐
                    │  Agent B │ (TCP bind pivot)
                    │  :4444   │
                    └────┬─────┘
                         │ TCP connect
                         ▼
                    ┌──────────┐
                    │  Agent C │ (TCP bind pivot)
                    │  :5555   │
                    └──────────┘
```

---

## HTTPS Transport

The primary transport. Uses TLS with malleable C2 profiles for traffic shaping.

### Connection flow

```
Agent                                    C2 Server
  │                                         │
  ├── TLS connect ─────────────────────────▶│
  │                                         │
  ├── POST /api/submit (pre-profile) ──────▶│  REGISTER
  │   X-Beacon-Id: <session_id>             │
  │   Body: AES(register_frame)             │
  │                                         │
  │◀── 200 OK ─────────────────────────────│  PROFILE frame
  │   Body: AES(profile_v2)                 │
  │                                         │
  │   ← nax_apply_profile() ─              │
  │                                         │
  ├── GET /jquery-3.3.1.min.js ────────────▶│  HEARTBEAT (profile-encoded)
  │   Cookie: __cfduid=<encoded_heartbeat>  │
  │                                         │
  │◀── 200 OK ─────────────────────────────│  TASK or NO_TASKS
  │   Body: <profile-encoded response>      │
  │                                         │
  ├── POST /api/v1/telemetry ──────────────▶│  RESULT (profile-encoded)
  │   Body: <profile-encoded result>        │
  │                                         │
  └── sleep (with jitter) ──── loop ────────┘
```

### Key behaviors

- **Pre-profile bootstrap:** The first POST always uses hardcoded defaults (`/api/submit`, `X-Beacon-Id` header, raw AES body). The server responds with the PROFILE frame.
- **Post-profile:** All subsequent requests use the profile's URIs, headers, encoding, and masking. See [Malleable C2 Profiles](Malleable-C2-Profiles.md).
- **Host rotation:** The `hosts` array in the profile supports `sequential` or `random` rotation. On connection failure, the agent rotates immediately.
- **Sleep and jitter:** Configurable at build time and via the `sleep` command at runtime. Jitter adds ±N% randomness to the interval.
- **Reconnect:** On TLS or HTTP failure, the agent closes the connection, rotates to the next host, and retries with a 3-second backoff.

### Files

| File | Role |
|------|------|
| `src/Transport/https.c` | TLS connection, HTTP GET/POST, heartbeat loop |
| `src/Transport/https_profile.c` | Profile parser, encode/decode pipeline |

---

## TCP Connect-out

Direct TCP connection to the C2 server. Simpler than HTTPS — no TLS, no profiles, no sleep.

### Connection flow

```
Agent                                    C2 Server
  │                                         │
  ├── TCP connect ─────────────────────────▶│
  │                                         │
  ├── [len][beat] ─────────────────────────▶│  REGISTER beat
  │   beat = [wm(4)][session_id(16)][AES(register)]
  │                                         │
  │◀── [len][AES(tasks)] ──────────────────│  TASKS or NO_TASKS
  │                                         │
  ├── [len][AES(result)] ──────────────────▶│  RESULT
  │                                         │
  └── recv blocks (no sleep) ── loop ───────┘
```

### Key behaviors

- **No sleep:** The agent sends a heartbeat and blocks on `recv()` until the server responds. The server controls the timing.
- **Watchdog:** A 30-second `SO_RCVTIMEO` acts as a watchdog — if the server doesn't respond, the agent reconnects.
- **Reconnect:** On any socket error, the agent closes, waits 2 seconds, and reconnects.
- **Wire format:** All messages are length-prefixed: `[4-byte LE length][data]`.

### Files

| File | Role |
|------|------|
| `src/Transport/tcp.c` | TCP connection, heartbeat loop, result sending |

---

## TCP Bind (Pivot)

The agent listens on a local port and waits for a parent agent to connect. Used for pivoting through networks where the target cannot reach the C2 directly.

### Connection flow

```
Parent Agent                             Bind Agent
  │                                         │
  │   operator: link 10.0.0.5 4444          │
  │                                         │
  ├── TCP connect ─────────────────────────▶│ :4444 (listening)
  │                                         │
  │◀── [len][beat] ────────────────────────│  REGISTER beat
  │   beat = [wm(4)][aes_key(16)][session_id(16)][AES(register)]
  │                                         │
  │   parent relays beat to C2 server       │
  │   C2 creates child agent                │
  │                                         │
  ├── [len][AES(tasks)] ──────────────────▶│  TASKS (relayed from C2)
  │                                         │
  │◀── [len][AES(result)] ────────────────│  RESULT (relayed to C2)
  │                                         │
  └── heartbeat + poll ──── loop ───────────┘
```

### Key behaviors

- **AES key in beat:** The bind agent includes its AES key in the registration beat so the parent can register it with the C2 regardless of the parent's own key.
- **Sleep before heartbeat:** The bind agent sleeps _before_ sending each heartbeat, giving the C2 time to queue tasks.
- **Poll with timeout:** After sending a heartbeat, the agent polls for tasks with a timeout of `sleep_ms + 3s`. If no tasks arrive, it loops back to sleep.
- **Reconnect on parent disconnect:** When the parent disconnects, the bind agent generates a new session ID and goes back to `accept()` waiting for a new parent.

### Files

| File | Role |
|------|------|
| `src/Transport/tcp_bind.c` | Bind socket, accept, heartbeat loop, result sending |

---

## Pivoting

Multi-hop pivoting allows chaining agents through internal networks:

```
C2 Server ◀──HTTPS──▶ Agent A ◀──TCP──▶ Agent B ◀──TCP──▶ Agent C
              (DMZ)              (internal)           (isolated)
```

### How it works

1. **Agent B** is compiled in bind mode (`NAX_TCP_MODE=bind`) and deployed on the internal host. It listens on a port.

2. The operator runs `link 10.0.0.5 4444` on **Agent A** (the parent). Agent A connects to Agent B's bind port.

3. Agent B sends its REGISTER beat (including its AES key). Agent A relays this to the C2 server via its own transport.

4. The C2 creates Agent B as a child of Agent A. From now on, all tasks for Agent B are routed through Agent A.

5. **Data relay:** Agent A's heartbeat loop calls `process_pivots()` which reads pending data from all child sockets and sends it to the C2 as RESULT frames. Tasks for children are forwarded down the chain.

6. To disconnect: `unlink <agent_id>` closes the pivot socket and notifies the C2.

### Pivot data format

```
Parent → C2:   [PIV_TYPE_DATA(1)][pivot_id(4LE)][msg_len(4LE)][msg]
Parent → C2:   [PIV_TYPE_UNLINK(1)][pivot_id(4LE)][type(1)]  (on disconnect)
```

### Chain depth

There is no hardcoded limit on chain depth. Each agent relays data for its children during every heartbeat cycle. Latency scales linearly with depth.

---

## Session ID

Each agent generates a 16-character hex session ID at startup. The ID is deterministic — derived from hostname + MAC address — so the same agent on the same host produces the same ID across restarts. This allows the C2 to correlate sessions.

```
raw[0..7] = hostname XOR first_non_loopback_MAC
raw[4..5] ^= PID
raw[6..7] ^= mode_marker + port
```

| Mode | Marker |
|------|--------|
| Connect-out (TCP/HTTPS) | `0xC0` XOR port low byte |
| Bind | `0xB1` XOR bind port bytes |

This ensures that a connect-out agent and a bind agent on the same host always have different session IDs.

---

## Wire Protocol

All transports use the same frame format internally:

```
┌──────────┬──────────┬────────────────┬──────────────────┐
│ type: 1  │ flags: 1 │ bodylen: 4 LE  │ body bytes       │
└──────────┴──────────┴────────────────┴──────────────────┘
```

### Message types

| Type | Value | Direction | Description |
|------|-------|-----------|-------------|
| `REGISTER` | `0x01` | Agent → C2 | Agent registration with sysinfo |
| `HEARTBEAT` | `0x02` | Agent → C2 | Check-in / poll for tasks |
| `RESULT` | `0x03` | Agent → C2 | Command output or tunnel data |
| `NO_TASKS` | `0x80` | C2 → Agent | No pending tasks |
| `TASK` | `0x81` | C2 → Agent | Command to execute |
| `PROFILE` | `0x82` | C2 → Agent | Malleable profile data (HTTPS only) |

### Encryption

All frames are encrypted with **AES-128-CBC** before transmission:

```
Plaintext frame → AES-128-CBC encrypt → [IV(16)][ciphertext]
```

The AES key is compiled into the agent at build time and shared with the listener.

### Length-prefix (TCP)

TCP transports wrap encrypted data in a 4-byte LE length prefix:

```
[length: 4 bytes LE][encrypted_frame]
```

### HTTPS encoding

HTTPS wraps encrypted data using the malleable profile's encoding pipeline (format + mask + prepend/append). See [Malleable C2 Profiles](Malleable-C2-Profiles.md).

---

## In-Memory Execution

The agent supports **fileless execution** via `memfd_create`. When the "In-Memory" option is enabled at build time, the build system produces a small **loader binary** instead of the agent directly:

```
Loader binary
  │
  ├── memfd_create("") → anonymous fd
  ├── write(fd, embedded_agent_elf)
  ├── unlink(self) → delete loader from disk
  ├── double-fork → daemonize
  ├── prctl(PR_SET_NAME, "dbus-daemon")
  └── fexecve(fd) → execute agent from memory
```

The agent runs from an anonymous memory-backed file descriptor — no file on disk, no `/proc/pid/exe` pointing to a real path. The loader deletes itself after launching the agent.

Fallback chain if `memfd_create` is not available: `O_TMPFILE` on `/dev/shm` → `O_TMPFILE` on `/tmp` → unlinked file on `/dev/shm`.

---

## Tunnels

All three transports support the Adaptix tunnel system for **SOCKS proxy** and **reverse port forwarding**. Tunnel data is multiplexed into the heartbeat loop via `nax_process_tunnels_ex()` and sent as `RESULT` frames with `NAX_STATUS_TUNNEL`.

Tunnel I/O is non-blocking and single-threaded — no additional threads are created. See `src/Commands/tunnel.c`.

---

## References

| File | Description |
|------|-------------|
| `src/Transport/https.c` | HTTPS transport + TLS |
| `src/Transport/https_profile.c` | Malleable profile encoder/decoder |
| `src/Transport/tcp.c` | TCP connect-out transport |
| `src/Transport/tcp_bind.c` | TCP bind (pivot) transport |
| `src/Commands/tunnel.c` | Non-blocking tunnel I/O |
| `src/Loader/memfd_loader.c` | In-memory fileless loader |
| `src/Core/packer.c` | Frame encode/decode, AES encrypt/decrypt |
| `include/nax_linux.h` | Wire constants, frame header size |
