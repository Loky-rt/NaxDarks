# Wire Protocol

All communication between the NaxDarks agent and the C2 server uses a binary frame protocol. Frames are encrypted with AES-128-CBC before transmission. The protocol is byte-compatible with the Windows beacon.

All integers are **little-endian**.

---

## Frame Format

Every message is wrapped in a 6-byte header:

```
┌───────────┬───────────┬──────────────────┬──────────────────────┐
│ type: 1B  │ flags: 1B │ body_len: 4B LE  │ body: body_len bytes │
└───────────┴───────────┴──────────────────┴──────────────────────┘
```

| Field | Size | Description |
|-------|------|-------------|
| `type` | 1 byte | Message type (see table below) |
| `flags` | 1 byte | Reserved (always `0x00`) |
| `body_len` | 4 bytes LE | Length of the body in bytes |
| `body` | variable | Message-specific payload |

Header size constant: `NAX_FRAME_HDR = 6`.

---

## Message Types

| Type | Value | Direction | Description |
|------|-------|-----------|-------------|
| `REGISTER` | `0x01` | Agent → Server | Initial registration with system info |
| `HEARTBEAT` | `0x02` | Agent → Server | Check-in (empty body) |
| `RESULT` | `0x03` | Agent → Server | Command output, tunnel data, pivot relay |
| `NO_TASKS` | `0x80` | Server → Agent | No pending tasks |
| `TASK` | `0x81` | Server → Agent | Command to execute |
| `PROFILE` | `0x82` | Server → Agent | Malleable C2 profile (HTTPS only) |

---

## Encryption

All frames are encrypted with **AES-128-CBC** before transmission. The key is compiled into the agent at build time and configured in the listener.

### Encrypt (agent → wire)

```
Plaintext frame
    ↓
PKCS7 pad to 16-byte boundary
    ↓
Generate 16 random bytes (IV) from /dev/urandom
    ↓
AES-128-CBC encrypt with compiled key
    ↓
┌──────────┬─────────────────────┐
│ IV: 16B  │ ciphertext: N bytes │
└──────────┴─────────────────────┘
```

### Decrypt (wire → agent)

```
┌──────────┬─────────────────────┐
│ IV: 16B  │ ciphertext: N bytes │
└──────────┴─────────────────────┘
    ↓
AES-128-CBC decrypt with compiled key
    ↓
Strip PKCS7 padding
    ↓
Plaintext frame
```

The AES implementation is a self-contained public-domain `tiny-AES-c` core with no external dependencies.

---

## Transport Wrapping

### TCP (connect-out and bind)

Encrypted frames are wrapped in a 4-byte length prefix:

```
┌──────────────────┬──────────────────────────────┐
│ length: 4B LE    │ encrypted_frame: length bytes │
└──────────────────┴──────────────────────────────┘
```

### HTTPS

Encrypted frames are wrapped using the malleable profile's encoding pipeline:

```
Encrypted frame → XOR mask → format encode → prepend/append → HTTP body/header/cookie/parameter
```

See [Malleable C2 Profiles](Malleable-C2-Profiles.md) for details.

---

## REGISTER (0x01)

Sent once at startup. Contains system information for agent creation.

### Registration beat (TCP)

```
┌──────────┬────────────────┬───────────────────────────┐
│ wm: 4B   │ session_id: 16B│ AES(REGISTER frame)       │
└──────────┴────────────────┴───────────────────────────┘
```

### Registration beat (TCP bind)

Includes the AES key so the parent can register the child regardless of key mismatch:

```
┌──────────┬──────────────┬────────────────┬───────────────────────────┐
│ wm: 4B   │ aes_key: 16B │ session_id: 16B│ AES(REGISTER frame)       │
└──────────┴──────────────┴────────────────┴───────────────────────────┘
```

### Registration beat (HTTPS)

Sent as a pre-profile POST with `X-Beacon-Id` header and raw AES body. No profile encoding applied.

### REGISTER body

```
┌────────────────────────────────────────────────────────────┐
│ hostname_len: 2B LE │ hostname: N bytes                    │
│ username_len: 2B LE │ username: N bytes                    │
│ arch: 1B                                                   │
│ pid: 4B LE                                                 │
│ sleep_ms: 4B LE                                            │
│ tid: 4B LE                                                 │
│ ip_len: 2B LE       │ ip: N bytes                          │
│ domain_len: 2B LE   │ domain: N bytes                      │
│ procname_len: 2B LE │ procname: N bytes                    │
│ elevated: 1B                                               │
│ os_major: 4B LE                                            │
│ os_minor: 4B LE                                            │
│ os_build: 2B LE                                            │
│ parent_pid: 4B LE                                          │
│ acp: 4B LE                                                 │
│ oem_cp: 4B LE                                              │
│ imgpath_len: 2B LE  │ imgpath: N bytes                     │
└────────────────────────────────────────────────────────────┘
```

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | lpstr | Machine hostname |
| `username` | lpstr | Current username |
| `arch` | byte | `0x02` = x64, `0x04` = ARM64 |
| `pid` | u32 | Process ID |
| `sleep_ms` | u32 | Configured sleep interval |
| `tid` | u32 | Thread ID (main thread) |
| `ip` | lpstr | Internal IPv4 address |
| `domain` | lpstr | Domain or "WORKGROUP" |
| `procname` | lpstr | Short process name |
| `elevated` | byte | `1` if euid == 0 |
| `os_major/minor` | u32 | Kernel major/minor version |
| `os_build` | u16 | Kernel patch level |
| `parent_pid` | u32 | Parent process ID |
| `acp/oem_cp` | u32 | Code pages (0 on Linux) |
| `imgpath` | lpstr | Full binary path |

String encoding: `lpstr` = `[length: 2B LE][string bytes]` (no null terminator).

---

## HEARTBEAT (0x02)

Empty body — just the 6-byte frame header:

```
┌──────┬──────┬──────────┐
│ 0x02 │ 0x00 │ 00000000 │
└──────┴──────┴──────────┘
```

The server responds with one or more TASK frames, or a single NO_TASKS frame.

---

## TASK (0x81)

Sent by the server inside the heartbeat response. Multiple tasks can be concatenated in a single response.

### TASK body

```
┌───────────────┬────────────┬────────────────┬──────────────────┐
│ task_id: 4B   │ cmd_id: 1B │ args_len: 4B   │ args: N bytes    │
└───────────────┴────────────┴────────────────┴──────────────────┘
```

| Field | Type | Description |
|-------|------|-------------|
| `task_id` | u32 | Server-assigned task identifier |
| `cmd_id` | byte | Command to execute (see command table) |
| `args_len` | u32 | Length of arguments |
| `args` | bytes | Command-specific argument data |

### Command IDs

| ID | Command | Description |
|----|---------|-------------|
| `0x10` | `whoami` | User and group info |
| `0x12` | `exit_thread` | Exit current thread |
| `0x13` | `exit_process` | Exit entire process |
| `0x14` | `cd` | Change directory |
| `0x15` | `pwd` | Print working directory |
| `0x16` | `mkdir` | Create directory |
| `0x17` | `rmdir` | Remove directory |
| `0x18` | `cat` | Read file contents |
| `0x19` | `ls` | List directory |
| `0x22` | `download` | Download file from target |
| `0x23` | `ps_list` | List processes |
| `0x24` | `ps_kill` | Kill process |
| `0x25` | `ps_run` | Execute process |
| `0x26` | `upload` | Upload file to target |
| `0x27` | `rm` | Remove file |
| `0x28` | `shell` | Execute shell command (`/bin/sh -c`) |
| `0x29` | `env` | Print environment variables |
| `0x2A` | `zip` | Compress file/directory |
| `0x2B` | `ifconfig` | Network interfaces |
| `0x2C` | `sleep` | Set sleep/jitter |
| `0x38` | `link` | Connect to child bind agent |
| `0x39` | `unlink` | Disconnect child pivot |
| `0x3A` | `profile_update` | Change malleable profile at runtime |
| `0x3E` | `tunnel_connect` | Open tunnel to target |
| `0x40` | `tunnel_write` | Write data to tunnel |
| `0x42` | `tunnel_close` | Close tunnel |
| `0x43` | `tunnel_reverse` | Open reverse port forward |
| `0x44` | `tunnel_accept` | Accept reverse connection |
| `0x45` | `tunnel_pause` | Pause tunnel (flow control) |
| `0x46` | `tunnel_resume` | Resume tunnel |
| `0x50` | `bof` | Execute BOF synchronously |
| `0x51` | `bof_async` | Execute BOF in background |
| `0x52` | `bof_jobs` | List async BOF jobs |
| `0x53` | `bof_kill` | Kill async BOF job |

---

## RESULT (0x03)

Sent by the agent after executing a command, or to relay tunnel/pivot data.

### RESULT body

```
┌───────────────┬─────────────┬────────────────┬──────────────────┐
│ task_id: 4B   │ status: 1B  │ data_len: 4B   │ data: N bytes    │
└───────────────┴─────────────┴────────────────┴──────────────────┘
```

| Field | Type | Description |
|-------|------|-------------|
| `task_id` | u32 | Matches the TASK's task_id (0 for tunnel/pivot) |
| `status` | byte | Result status code |
| `data_len` | u32 | Length of result data |
| `data` | bytes | Command output or tunnel payload |

### Status codes

| Code | Name | Description |
|------|------|-------------|
| `0x00` | `STATUS_OK` | Command completed successfully |
| `0x01` | `STATUS_ERR` | Command failed |
| `0x20` | `STATUS_TUNNEL` | Tunnel data (multiplexed channel I/O) |
| `0xFE` | `STATUS_ASYNC` | Async BOF started — result will arrive later |

---

## NO_TASKS (0x80)

Empty body — signals no pending commands:

```
┌──────┬──────┬──────────┐
│ 0x80 │ 0x00 │ 00000000 │
└──────┴──────┴──────────┘
```

In HTTPS mode with malleable profiles, the server may instead send the profile's `empty_response` string verbatim (not encrypted). The agent detects this and treats it as NO_TASKS.

---

## PROFILE (0x82)

Sent by the server in the REGISTER response (HTTPS only). Contains the malleable C2 profile in v2 binary wire format.

### PROFILE body

```
┌──────────────┬────────────┬────────────────────┬──────────────────────┐
│ version: 1B  │ rotation:1B│ user_agent: lpstr  │ beacon_hdr: lpstr    │
├──────────────┴────────────┴────────────────────┴──────────────────────┤
│ hosts: string_list                                                    │
│ error: status(2B) + body(lpstr) + headers(header_map)                │
│ GET: uris + client_meta + client_headers + client_params +           │
│      server_output + server_headers                                   │
│ POST: uris + client_meta + client_output + client_headers +          │
│       server_output + server_headers                                  │
└──────────────────────────────────────────────────────────────────────┘
```

See [Malleable C2 Profiles — Wire Format](Malleable-C2-Profiles.md#wire-format-v2) for the complete field-by-field specification.

---

## Argument Encoding

Command arguments use two patterns:

### Length-prefixed string (args)

Most commands pass a single argument as a raw string in the `args` field. The `args_len` field gives the length.

### BOF-style packed arguments

BOF commands (`0x50`, `0x51`) use a two-part format:

```
┌───────────────┬──────────────────┬───────────────┬──────────────────┐
│ bof_size: 4B  │ bof_data: N bytes│ args_size: 4B │ args_data: N bytes│
└───────────────┴──────────────────┴───────────────┴──────────────────┘
```

The `args_data` uses Cobalt Strike's `bof_pack` format, parsed with `BeaconDataParse` / `BeaconDataExtract` / `BeaconDataInt` / `BeaconDataShort`.

### Link arguments

```
┌──────────────┬────────────┬───────────────┬──────────────────┐
│ link_type: 1B│ port: 2B LE│ ip_len: 4B LE │ ip: N bytes      │
└──────────────┴────────────┴───────────────┴──────────────────┘
```

### Tunnel arguments

Each tunnel command has its own argument layout. See `tunnel.c` for the exact wire formats.

---

## Multiple Frames in One Response

The server can concatenate multiple TASK frames in a single heartbeat response. The agent walks the buffer by reading the frame header, extracting `body_len`, advancing by `NAX_FRAME_HDR + body_len`, and repeating until the buffer is exhausted:

```
┌─────────────────┬─────────────────┬─────────────────┐
│ TASK frame 1    │ TASK frame 2    │ TASK frame 3    │
│ (6 + body_len)  │ (6 + body_len)  │ (6 + body_len)  │
└─────────────────┴─────────────────┴─────────────────┘
```

A `NO_TASKS` frame always appears alone and terminates parsing.

---

## Session ID

16-character lowercase hex string derived from:

```
raw[0..7] = hostname_bytes XOR first_non_loopback_MAC
raw[4..5] ^= PID (uniqueness per process)
raw[6..7] ^= mode_marker (0xC0=connect, 0xB1=bind) XOR port
```

The session ID is deterministic for a given host + process + mode, allowing the server to correlate reconnections.

---

## References

| File | Description |
|------|-------------|
| `src/Core/packer.c` | Frame encode/decode, REGISTER/HEARTBEAT/RESULT builders |
| `src/Core/crypto.c` | AES-128-CBC encrypt/decrypt (self-contained) |
| `include/nax_linux.h` | Wire constants, message types, command IDs |
| `agent_naxdarks_linux/pl_wire.go` | Server-side frame encode/decode (Go) |
| `agent_naxdarks_linux/pl_results.go` | Server-side RESULT processing |
