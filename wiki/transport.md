# Transport

NaxDarks supports three transport modes, selected at compile time. Each mode produces a different binary with its own communication logic.

---

## Transport Modes

| Mode | Flag | Binary suffix | Direction | Use case |
|------|------|---------------|-----------|----------|
| **HTTPS** | `NAX_TCP_MODE=https` | `_https` | Agent → C2 | Primary transport with malleable profiles |
| **TCP Connect-out** | `NAX_TCP_MODE=connect` | _(none)_ | Agent → C2 | Direct TCP with TLS, configurable sleep |
| **TCP Bind** | `NAX_TCP_MODE=bind` | `_bind` | Parent → Agent | Pivoting through chained agents |
| **Graph (Azure Blob)** | `NAX_TCP_MODE=graph` | `_graph` | Agent → Azure Blob → C2 | Dead-drop via Azure Blob Storage, no direct C2 connection |
| **GitLab** | `NAX_TCP_MODE=gitlab` | `_gitlab` | Agent → GitLab Repo → C2 | Dead-drop via GitLab Repository Files API, no direct C2 connection |

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

                    ┌──────────┐     Azure Blob     ┌──────────┐
Internet            │  Agent D │──── c_*.dat ──────▶│ Listener │
(no direct          │  (Graph) │◀─── r_*.dat ────────│  Graph   │
 C2 reach)          └──────────┘  blob.core.windows  └──────────┘

                    ┌──────────┐     GitLab Repo     ┌──────────┐
Internet            │  Agent E │──── c_*.dat ───────▶│ Listener │
(no direct          │  (GitLab)│◀─── r_*.dat ─────────│  GitLab  │
 C2 reach)          └──────────┘   gitlab.com/API    └──────────┘
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

### Pre-profile and Post-profile

The HTTPS transport operates in two distinct phases:

**Pre-profile (bootstrap):** Before the agent receives a malleable profile, it uses hardcoded defaults to register with the C2:

| Parameter | Value |
|-----------|-------|
| URI | Configured in the listener (`pre_post_uri`) |
| Beacon ID header | `X-Beacon-Id` (or configured `pre_beacon_hdr`) |
| Body encoding | Raw AES-CBC, no masking |
| Method | POST |

The server responds with the full malleable profile (PROFILE frame), which the agent applies immediately.

**Post-profile:** All subsequent requests (heartbeats, results) use the profile's URIs, headers, encoding, and masking pipeline. See [Malleable C2 Profiles](Malleable-C2-Profiles.md).

> **Redirector configuration — common failure point**
>
> When using redirectors (e.g. Apache, nginx, Cloudflare Workers) in front of the C2, **both the pre-profile URI and all post-profile URIs must be forwarded** to the C2 server.
>
> A common mistake is configuring the redirector to only forward the post-profile URIs from the malleable profile, forgetting that the agent's first request uses a different URI (the pre-profile one). This causes the REGISTER to return 404/403 and the agent never connects.
>
> **Example:** If the listener is configured with `pre_post_uri = /api/submit` and the malleable profile uses `/api/v1/telemetry` and `/api/v1/verify`, the redirector must forward **all three**.

### Key behaviors

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

Direct TCP connection to the C2 server with TLS 1.2+ encryption (OpenSSL). No malleable profiles — uses a fixed wire format.

### Connection flow

```
Agent                                    C2 Server
  │                                         │
  ├── TCP connect + TLS handshake ─────────▶│
  │                                         │
  ├── [len][beat] ─────────────────────────▶│  REGISTER beat
  │   beat = [wm(4)][session_id(16)][AES(register)]
  │                                         │
  ├── sleep(configured_ms ± jitter) ────────│
  │                                         │
  ├── [len][AES(heartbeat)] ───────────────▶│  HEARTBEAT
  │                                         │
  │◀── [len][AES(tasks)] ──────────────────│  TASKS or NO_TASKS
  │                                         │
  ├── [len][AES(result)] ──────────────────▶│  RESULT
  │                                         │
  └── sleep ── loop ────────────────────────┘
```

### Key behaviors

- **TLS:** All traffic is wrapped in TLS 1.2+ via OpenSSL. The agent connects as a TLS client without certificate validation (`SSL_VERIFY_NONE`). The listener requires a certificate and private key configured at creation time.
- **Sleep and jitter:** Configurable at build time and via the `sleep` command at runtime. Set `sleep 0` for interactive use (e.g. active SOCKS tunnels).
- **Watchdog:** A 30-second `SO_RCVTIMEO` acts as a watchdog — if the server doesn't respond, the agent reconnects.
- **Reconnect:** On any socket or TLS error, the agent closes, waits 2 seconds, and reconnects.
- **Wire format:** All messages are length-prefixed: `[4-byte LE length][TLS(AES(data))]`.

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

## Graph Transport (Azure Blob Storage)

A dead-drop transport. The agent never connects to the C2 server directly — all communication passes through an Azure Blob Storage container. Traffic blends with legitimate Azure traffic on `*.blob.core.windows.net:443`.

### Azure Transport Operation

The transport listener has the following fields:

* Storage Account: The name of the Storage Account.
* Storage Key: A Base64-encoded string that can be found under Storage browser > Security + networking > Access keys > Key 1 (Key).
* Container Name: This is arbitrary. A container with the specified name will be created to store the blobs.
* Poll Interval (s): The listener's response interval.
* Encryption Key: This can be left blank; it will be generated automatically.
* Beacon Poll Attempts: The number of attempts the agent makes to locate the listener's response before moving on to the next cycle.
* Beacon Poll Interval (ms): The amount of time, in milliseconds, that the agent waits between attempts to retrieve the listener's response from Azure.

### Rules:

* The Listener must always respond faster than the Agent. Therefore, the time configured as Poll Interval (s) + Azure latency must be lower than Beacon Poll Interval (ms).
* Configure at least one additional retry (+1) as a safety margin in case Azure experiences higher-than-usual latency.

### Example of configuration and behavior:

* Poll Interval (s): 5
* Beacon Poll Attempts: 2
* Beacon Poll Interval (ms): 15000

In this configuration, the Listener responds within a maximum of 5 seconds. On the other hand, the Agent is configured to communicate every 15 seconds.

Now, what happens if, for some reason, the Agent does not receive a response from the Listener?

With `Beacon Poll Attempts: 2`, the Agent is guaranteed to make a second attempt within the next **15 seconds** to retrieve the Listener's response. In other words, the Agent waits up to approximately **30 seconds** for a response before moving on to the next cycle.

#### Take the Agent's sleep interval into account:

The sleep interval configured in the Agent affects the actual duration of the complete communication cycle. Below are two example scenarios:

1. **Scenario 1:** Sleep configured to **10 seconds**, `Beacon Poll Attempts: 2`, and `Beacon Poll Interval (ms): 15000`.

```text
10seg           sleep agente
~1seg           Blob_upload (c_*.dat)
~15seg          Sleep inside `graph_poll_response`
~1seg           Blob_download (r_*.dat)
~1seg           Overhead
-----------------------------------------------------
~28 seconds per cycle if the Agent finds `r_*.dat` on the first attempt.
~43s maximum per cycle if the Agent does not find `r_*.dat` on the first attempt
```

2. **Scenario 2:** Sleep configured to **0 seconds**, `Beacon Poll Attempts: 2`, and `Beacon Poll Interval (ms): 15000`.

In this case, the approximate time per cycle is:

```text
0s              Agent sleep
~1s             Blob_upload (c_*.dat)
~15s            Sleep inside graph_poll_response
~1s             Blob_download (r_*.dat)
~1s             Overhead
-----------------------------------------------------
~18s per cycle if the Agent finds r_*.dat on the first attempt
~33s maximum per cycle if the Agent does not find r_*.dat on the first attempt
```

**General formula for the maximum time:**

`Maximum Time = Beacon Sleep + (Beacon Poll Interval × Beacon Poll Attempts) + Latency (Azure/Network)`

### Connection flow

```
Agent                          Azure Blob Container            C2 Listener
  │                                    │                           │
  ├── PUT c_<nonce>.dat ──────────────▶│                           │
  │   [agentCrc(4)][agentUID(16)]      │                           │
  │   [encLen(4)][b64(AES(frame))]     │                           │
  │                                    │◀── GET c_<nonce>.dat ─────│  poll
  │                                    │─── 200 OK ───────────────▶│
  │                                    │                           │  decrypt, process
  │                                    │◀── PUT r_<nonce>.dat ─────│  response
  │◀── GET r_<nonce>.dat ─────────────│                           │
  │    AES(NO_TASKS or TASK frame)     │                           │
  │                                    │                           │
  ├── sleep(configured_ms ± jitter) ───│                           │
  │                                    │                           │
  ├── PUT c_<nonce>.dat ──────────────▶│                           │  HEARTBEAT
  │   ...                              │                           │
  │                                    │                           │
  │   (on task result)                 │                           │
  ├── PUT r_<nonce>.dat ──────────────▶│                           │  RESULT
  │   [agentCrc(4)][agentUID(16)]      │◀── GET r_<nonce>.dat ─────│
  │   [encLen(4)][b64(AES(result))]    │─── 200 OK ───────────────▶│  process result
  └──────────────────────────── loop ──┘                           │
```

### File format

Every file uploaded by the agent uses the same format:

```
[agentCrc(4 BE)][agentUID(16)][encLen(4 BE)][base64(AES-CBC(frame))][bodyData]
```

| Field | Size | Description |
|-------|------|-------------|
| `agentCrc` | 4 bytes BE | Listener watermark in clear — allows the listener to filter its own files |
| `agentUID` | 16 bytes | Raw session UID — allows the listener to identify the agent without decrypting |
| `encLen` | 4 bytes BE | Length of the base64-encoded ciphertext |
| `base64(AES-CBC(frame))` | variable | The frame encrypted with AES-128-CBC and base64-encoded |
| `bodyData` | optional | Additional encrypted payload (tunnel data, pivot results) |

### Blob naming

| Prefix | Direction | Description |
|--------|-----------|-------------|
| `c_<nonce>.dat` | Agent → Listener | Check-in (REGISTER or HEARTBEAT) |
| `r_<nonce>.dat` | Listener → Agent | Response (tasks or NO_TASKS) |
| `r_<nonce>.dat` | Agent → Listener | Command results and pivot relay data |

The nonce is 16 random hex characters, unique per upload.

### Key behaviors

- **No direct C2 connection:** The agent only connects to `<account>.blob.core.windows.net:443`. The C2 listener polls the same container. No ports need to be open toward the C2.
- **SAS token:** A container-scoped SAS token is generated at listener creation time (90-day validity) and compiled into the agent. The token has `rwdl` permissions.
- **Poll and retry:** After uploading `c_<nonce>.dat`, the agent polls for `r_<nonce>.dat` up to `NAX_GRAPH_POLL_MAX` times (default: 15) with `NAX_GRAPH_POLL_MS` ms between attempts (default: 3000ms).
- **Stale cleanup:** When the listener starts, it deletes all existing blobs in the container to avoid processing stale data from previous sessions.
- **Pivoting:** Fully supported. Pivot child data is uploaded as separate `r_*.dat` files so the server can route each frame individually.

### Build-time configuration

Graph parameters are written to `include/nax_config.h` by the builder (not passed as `-D` flags, because the SAS token contains characters unsafe for shell argument parsing):

| Define | Source |
|--------|--------|
| `NAX_GRAPH_ACCOUNT` | Listener `storage_account` |
| `NAX_GRAPH_CONTAINER` | Listener `container_name` |
| `NAX_GRAPH_SAS_TOKEN` | Auto-generated at listener creation |
| `NAX_GRAPH_POLL_MS` | Listener `poll_interval_ms` (default: 3000) |
| `NAX_GRAPH_POLL_MAX` | Listener `poll_attempts` (default: 15) |

### Files

| File | Role |
|------|------|
| `src/Transport/graph.c` | Azure Blob upload/download/delete, heartbeat loop, pivot drain |
| `src_server/listener_naxdarks_linux_graph/pl_main.go` | Listener lifecycle, `InternalHandler` for pivot registration |
| `src_server/listener_naxdarks_linux_graph/pl_transport.go` | Blob polling, checkin processing, result routing |
| `src_server/listener_naxdarks_linux_graph/pl_crypto.go` | AES-128-CBC encrypt/decrypt, SAS generation |

---

## GitLab Transport

A dead-drop transport that uses the GitLab Repository Files API as a communication channel. The agent never connects to the C2 server directly — all communication passes through commits to a GitLab repository. Traffic blends with legitimate GitLab API activity on `gitlab.com:443` (or a self-hosted instance).

Unlike the Azure Blob transport, GitLab uses a Git-backed storage model where every file operation (create, update, delete) is a Git commit on a branch. This introduces a commit serialization constraint: GitLab rejects concurrent commits to the same branch with HTTP 400. The agent handles this with automatic retry and backoff.

### GitLab Transport Operation

The transport listener has the following fields:

* **GitLab URL:** Base URL of the GitLab instance. Defaults to `https://gitlab.com`. Use the full base URL for self-hosted instances (e.g. `https://git.corp.local`).
* **Access Token:** A Personal Access Token or Project Access Token with `api` scope. The token is compiled into the agent using volatile per-byte write macros so it does not appear as a string in the binary.
* **Project ID:** The project in `namespace/project` format (e.g. `myorg/c2-repo`) or its numeric ID.
* **Branch:** The branch to use for file storage. Defaults to `main`.
* **Repo Path (optional):** Subdirectory inside the repository where files are stored (e.g. `loky`). If left empty, files are placed in the repo root.
* **Poll Interval (s):** How often the listener polls the repository for new files.
* **Encrypt Key:** AES-128 encryption key as a 32-character hex string. Can be left blank — generated automatically.
* **Beacon Poll Attempts:** Number of times the agent retries downloading the listener's response before giving up and starting the next cycle.
* **Beacon Poll Interval (ms):** Time the agent waits between poll attempts to retrieve the listener's response file (`r_*.dat`).

### Rules

* The listener must respond faster than the agent times out. Therefore: `Poll Interval (s) + GitLab API latency` must be less than `Poll Interval (ms) × Beacon Poll Attempts`.
* Configure at least one extra poll attempt (+1) as a safety margin for GitLab latency spikes.
* GitLab serializes commits per branch. Uploading multiple files in rapid succession will trigger HTTP 400 conflict errors. The agent retries automatically with backoff, but this limits throughput. **Do not reduce the per-cycle chunk limit** — it exists specifically to avoid saturating the branch.

### Example configuration and behavior

* Poll Interval (s): 5
* Beacon Poll Attempts: 2
* Beacon Poll Interval (ms): 20000

In this configuration the listener responds within 5 seconds. The agent waits up to 40 seconds for a response before moving on.

#### Cycle timing

**With sleep configured to 5 seconds:**

```text
5s      Agent sleep
~2s     gitlab_upload (c_*.dat) — includes commit
~20s    Sleep inside gitlab_poll_response (first attempt)
~2s     gitlab_download (r_*.dat)
~1s     Overhead
-----------------------------------------------------
~30s per cycle if r_*.dat found on first attempt
~52s maximum per cycle (second poll attempt exhausted)
```

**With sleep configured to 0 seconds (interactive):**

```text
0s      Agent sleep
~2s     gitlab_upload (c_*.dat)
~20s    Sleep inside gitlab_poll_response
~2s     gitlab_download (r_*.dat)
~1s     Overhead
-----------------------------------------------------
~25s per cycle (first attempt)
~47s maximum per cycle
```

**General formula:**

`Maximum time = Sleep + (Poll Interval ms × Poll Attempts) + GitLab API latency`

### Connection flow

```
Agent                        GitLab Repo (branch)           C2 Listener
  │                                  │                           │
  ├── POST files/:path (create) ────▶│                           │
  │   c_<nonce>.dat                  │                           │
  │   [agentCrc(4)][agentUID(16)]    │                           │
  │   [encLen(4)][b64(AES(frame))]   │                           │
  │                                  │◀── list files (tree) ─────│  poll
  │                                  │─── 200 OK ───────────────▶│  detect c_*.dat
  │                                  │                           │  decrypt, process
  │                                  │◀── POST r_<nonce>.dat ────│  response
  │                                  │   AES(NO_TASKS or TASK)   │
  │                                  │◀── DELETE c_<nonce>.dat ──│  cleanup
  │◀── GET files/:path/raw ──────────│                           │
  │    AES(NO_TASKS or TASK frame)   │                           │
  │                                  │                           │
  ├── sleep(configured_ms ± jitter)  │                           │
  │                                  │                           │
  ├── POST c_<nonce>.dat ───────────▶│                           │  HEARTBEAT
  │   ...                            │                           │
  │                                  │                           │
  │   (on task result)               │                           │
  ├── POST r_<nonce>_<seq>.dat ─────▶│                           │  RESULT
  │   [agentCrc(4)][agentUID(16)]    │◀── list → detect r_*_seq──│
  │   [encLen(4)][b64(AES(result))]  │─── 200 OK ───────────────▶│  process result
  │                                  │◀── DELETE r_*_seq.dat ────│  cleanup
  └───────────────────────── loop ───┘                           │
```

### File format

Every file uploaded by the agent uses the same format as the Graph transport:

```
[agentCrc(4 BE)][agentUID(16)][encLen(4 BE)][base64(AES-CBC(frame))][bodyData]
```

| Field | Size | Description |
|-------|------|-------------|
| `agentCrc` | 4 bytes BE | Listener watermark — allows the listener to filter its own files |
| `agentUID` | 16 bytes | Raw session UID — identifies the agent without decryption |
| `encLen` | 4 bytes BE | Length of the base64-encoded ciphertext |
| `base64(AES-CBC(frame))` | variable | Frame encrypted with AES-128-CBC, then base64-encoded for the JSON API |
| `bodyData` | optional | Additional encrypted payload (tunnel data, pivot results) |

The `content` field in the GitLab API payload uses `"encoding": "base64"`, so the file data is base64-encoded once more for the API body. GitLab decodes and stores the original bytes. The agent and listener download raw content via the `/raw` endpoint, recovering the original bytes.

### File naming

| Pattern | Direction | Description |
|---------|-----------|-------------|
| `c_<nonce>.dat` | Agent → Listener | Check-in (REGISTER or HEARTBEAT) |
| `r_<nonce>.dat` | Listener → Agent | Response (tasks or NO_TASKS) |
| `r_<nonce>_<seq8d>.dat` | Agent → Listener | Command result or pivot relay data |

The nonce is 16 random hex characters. Result files include an 8-digit zero-padded sequence number (e.g. `_00000003`) so the listener can process them in strict order and detect gaps.

### Throughput and per-cycle limits

Because every file operation is a Git commit, GitLab serializes writes to the same branch. Uploading too many files in a single cycle triggers HTTP 400 conflict errors. The agent enforces the following limits per heartbeat cycle:

| Data type | Limit per cycle | Rationale |
|-----------|----------------|-----------|
| Download chunks | 2 | Prevents branch saturation during large file transfers |
| Pivot messages ≥ 1 KB | 2 | Prevents branch saturation during pivot data relay |
| Pivot messages < 1 KB | Unlimited | Heartbeats and ACKs are drained without limit so they don't block the chunk queue |

When a commit fails with HTTP 400, the agent retries up to 5 times with linear backoff (1.5 s × attempt number) before giving up on that file.

### Deduplication

The listener maintains a `processedSeqs` in-memory set of result filenames (`r_*_seq.dat`) already delivered to the teamserver. If a delete fails and the file reappears in the next poll cycle, it is skipped rather than processed a second time, preventing duplicate chunks and file corruption.

The set is cleared when the listener stops. Entries are removed from the set only after the file is confirmed deleted from the repository.

### Key behaviors

- **No direct C2 connection:** The agent only connects to `gitlab.com:443` (or the configured self-hosted URL). The C2 listener polls the same repository via the API. No ports need to be open toward the C2.
- **Repo path isolation:** When `RepoPath` is configured, a `.gitkeep` placeholder is created at startup to ensure the directory exists before the first agent check-in.
- **Stale cleanup:** When the listener starts, it deletes all existing `.dat` files in the configured path to avoid processing stale data from previous sessions.
- **Commit conflict retry:** Both agent and listener handle HTTP 400 (commit conflict) gracefully with retry and backoff. The agent retries up to 5 times; the listener's delete retries once and relies on the deduplication set for safety.
- **Sequence ordering:** The listener sorts `r_*_seq.dat` files by sequence number before processing, ensuring results are delivered in order even if uploads arrive out of order.
- **Pivoting:** Fully supported. Pivot child data is uploaded as separate `r_*_seq.dat` files so the server can route each frame individually.
- **Self-hosted GitLab:** Supported by setting `GitLab URL` to the instance base URL.

### Build-time configuration

GitLab parameters are written to `include/nax_config.h` by the builder using volatile per-byte write macros. Sensitive values (token, project ID, URL) never appear as string literals in the binary:

| Define | Source |
|--------|--------|
| `NAX_GITLAB_URL_WRITE` / `NAX_GITLAB_URL_LEN` | Listener `gitlab_url` |
| `NAX_GITLAB_TOKEN_WRITE` / `NAX_GITLAB_TOKEN_LEN` | Listener `access_token` |
| `NAX_GITLAB_PROJECT_WRITE` / `NAX_GITLAB_PROJECT_LEN` | Listener `project_id` |
| `NAX_GITLAB_BRANCH_WRITE` / `NAX_GITLAB_BRANCH_LEN` | Listener `branch` (default: `main`) |
| `NAX_GITLAB_REPO_PATH_WRITE` / `NAX_GITLAB_REPO_PATH_LEN` | Listener `repo_path` (default: empty) |
| `NAX_GITLAB_POLL_MS` | Listener `poll_interval_ms` (default: 3000) |
| `NAX_GITLAB_POLL_MAX` | Listener `poll_attempts` (default: 1) |

### Comparison with Azure Blob (Graph) transport

| | Graph (Azure Blob) | GitLab |
|---|---|---|
| Storage backend | Azure Blob Storage | GitLab Repository Files API |
| Traffic destination | `*.blob.core.windows.net:443` | `gitlab.com:443` (or self-hosted) |
| Write model | Independent blob PUT operations | Git commits (serialized per branch) |
| Concurrent writes | No conflict | HTTP 400 on conflict — retry required |
| File content encoding | Binary (raw bytes) | base64 inside JSON API body |
| Result file naming | `r_<nonce>_<seq>.dat` | `r_<nonce>_<seq8d>.dat` |
| Throughput | Higher (parallel blobs) | Lower (serialized commits) |
| Infrastructure required | Azure Storage account | GitLab account + repository |
| SAS / token expiry | 90-day SAS auto-generated | Token set by user, no auto-expiry |

### Files

| File | Role |
|------|------|
| `src/Transport/gitlab.c` | GitLab API upload/download/delete, heartbeat loop, pivot drain |
| `src_server/listener_naxdarks_linux_gitlab/pl_main.go` | Listener lifecycle, `InternalHandler` for pivot registration |
| `src_server/listener_naxdarks_linux_gitlab/pl_transport.go` | Repository polling, checkin processing, result routing, deduplication |
| `src_server/listener_naxdarks_linux_gitlab/pl_crypto.go` | AES-128-CBC encrypt/decrypt |

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
| `src/Transport/graph.c` | Azure Blob Storage dead-drop transport |
| `src/Commands/tunnel.c` | Non-blocking tunnel I/O |
| `src/Core/packer.c` | Frame encode/decode, AES encrypt/decrypt |
| `include/nax_linux.h` | Wire constants, frame header size |
| `src_server/listener_naxdarks_linux_graph/` | Graph listener (Go plugin) |
| `src/Transport/gitlab.c` | GitLab Repository Files dead-drop transport |
| `src_server/listener_naxdarks_linux_gitlab/` | GitLab listener (Go plugin) |
