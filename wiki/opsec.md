# OPSEC Module

- The OPSEC module provides anti-debug, anti-VM, and self-destruct capabilities. It is a **compile-time option** — when disabled, all OPSEC functions compile to no-ops with zero overhead.

- Sleep Obfuscation: Always active, only on HTTPS transport
---

## Enabling OPSEC

Check the **"OPSEC"** checkbox in the Adaptix build UI, or pass the flag manually:

```bash
make NAX_OPSEC=1
```

When disabled (`NAX_OPSEC=0`, the default), the header stubs all calls to `((void)0)`:

```c
#ifdef NAX_OPSEC
void nax_opsec_check(void);
void nax_opsec_heartbeat(void);
void nax_opsec_cleanup(void);
#else
#define nax_opsec_check()     ((void)0)
#define nax_opsec_heartbeat() ((void)0)
#define nax_opsec_cleanup()   ((void)0)
#endif
```

No binary bloat, no conditional branches — the preprocessor removes everything.

---

## Three Layers

The module operates at three points in the agent lifecycle:

```
Agent start
    │
    ├── nax_opsec_check()           ← Layer 1: Startup
    │     Debugger attached?
    │     Running in a VM?
    │     → self-delete + exit
    │
    ├── C2 communication begins
    │
    ├── nax_opsec_heartbeat()       ← Layer 2: Periodic (every heartbeat)
    │     TracerPid != 0?
    │     → self-delete + exit
    │
    ├── ... agent runs ...
    │
    └── nax_opsec_cleanup()         ← Layer 3: Exit
          Delete binary from disk
          Zero environment memory
```

---

## Layer 1: Startup Checks

`nax_opsec_check()` runs **before any C2 communication**. If any check triggers, the agent self-deletes and exits silently with `_exit(0)` — no error message, no log, no cleanup.

### Debugger Detection

| Check | Method | Threshold |
|-------|--------|-----------|
| **TracerPid** | Read `/proc/self/status`, parse `TracerPid:` field | Any value ≠ 0 |
| **Timing** | Measure 100k loop iterations with `CLOCK_MONOTONIC` | > 50ms (normal: < 5ms) |

TracerPid detects `gdb`, `strace`, `ltrace`, and any `PTRACE_ATTACH`. The timing check catches single-stepping debuggers that don't appear in TracerPid.

### Virtual Machine Detection

| Check | Method | Detects |
|-------|--------|---------|
| **CPUID hypervisor bit** | `CPUID` leaf 1, ECX bit 31 | Any hypervisor (x86_64 only) |
| **DMI/SMBIOS strings** | Read `/sys/class/dmi/id/{product_name,sys_vendor,board_vendor,bios_vendor}` | VirtualBox, VMware, QEMU, KVM, Xen, Hyper-V, Parallels, Bochs, Amazon EC2 |
| **MAC OUI prefix** | Read `/sys/class/net/*/address`, compare first 3 bytes | VirtualBox (`08:00:27`), VMware (`00:0c:29`, `00:50:56`), QEMU/KVM (`52:54:00`), Hyper-V (`00:15:5d`), Xen (`00:16:3e`), Parallels (`00:1c:42`) |

> **Note:** The CPUID check is x86_64 only. On ARM64 it always returns 0 (no detection).

---

## Layer 2: Periodic Heartbeat

`nax_opsec_heartbeat()` is called on **every heartbeat cycle** in all three transports (HTTPS, TCP connect-out, TCP bind). It performs a single lightweight check:

```c
void nax_opsec_heartbeat(void) {
    if (detect_tracer()) {
        self_delete();
        zero_memory();
        _exit(0);
    }
}
```

This catches debuggers attached **after** startup — an analyst who attaches `gdb` or `strace` to the running agent process. The check is a single `open` + `read` + `strstr` on `/proc/self/status`, fast enough to run every heartbeat without measurable overhead.

---

## Layer 3: Exit Cleanup

`nax_opsec_cleanup()` runs when the agent exits normally (operator sends `exit`, or the transport loop terminates). It performs two actions:

### Self-delete

Reads `/proc/self/exe` to find the binary path on disk and calls `unlink()`. Skips if running from `memfd` (the path contains `memfd:` or `(deleted)`), since there's no file to delete.

### Memory zeroing

Zeros all environment variable strings in memory (`environ[]`). This prevents forensic recovery of sensitive data (credentials, paths, hostnames) from a process memory dump after the agent exits.

---

## Layer 4: Sleep Obfuscation

The HTTPS transport automatically obfuscates sensitive data during sleep cycles to protect against memory forensics and runtime analysis.

### What it protects

| Data | Size | Location | Description |
|------|------|----------|-------------|
| `a->cfg.aes_key` | `16 bytes` | `Heap` | `AES-128 session encryption key` |
| `a->session_id` | `16 bytes` | `Heap` | `Hex session identifier` |
| `g_profile` | `~2KB` | `Global` | `Full malleable C2 profile structure` |


### How it works

1. Generate random key — 64 bytes from /dev/urandom per sleep cycle
2. Store key in memfd — Kernel memory (memfd_create), invisible to /proc/<pid>/mem scanners
3. XOR sensitive data — In-place XOR in heap memory: `a->cfg.aes_key`, `a->session_id` & `g_profile`
4. Zero stack key — Overwrite the local key buffer before sleeping
5. Sleep — Data remains obfuscated during the entire sleep period
6. Restore — Retrieve key from memfd, XOR again to decrypt, zero restore buffer


### Key characteristics

1. Per-cycle random key — Each sleep uses a different 64-byte XOR key
2. No mprotect calls — All data stays in heap (no suspicious permission changes)
3. memfd-backed storage — The XOR key never resides in userspace memory
4. Transparent restoration — Data is automatically restored after waking
5. Volatile qualifiers — Prevents compiler optimizations from exposing data

### Verification

Debug output showing the obfuscation in action:

```bash
[NAX-DBG 09:56:05.716] [DEBUG] === BEFORE OBFUSCATION ===
[NAX-DBG 09:56:05.716] [DEBUG] AES key full: 957b7591bc66ac4a3a01dfe0a50139f5
[NAX-DBG 09:56:05.716] [DEBUG] Session ID: fee7236b21a9ad90
[NAX-DBG 09:56:05.716] [DEBUG] Session ID hex[0..3]: 66 65 65 37
[NAX-DBG 09:56:05.717] [DEBUG] === DURING OBFUSCATION ===
[NAX-DBG 09:56:05.717] [DEBUG] AES key full: 5eb5e26f8a764e87de010ee91de06fdd <-- COMPLETELY DIFFERENT
[NAX-DBG 09:56:05.717] [DEBUG] Session ID hex: ffffffb0013f587e45ffffffa155160ffffffff5ffffffba40310e05 <-- COMPLETELY DIFFERENT
[NAX-DBG 09:56:05.717] [DEBUG] Key stored in memfd (fd=4)
[NAX-DBG 09:56:10.717] sleep done — next heartbeat cycle
```

### Limitations

1. Only active in HTTPS transport mode (not TCP connect-out or TCP bind)
2. Only protects data during sleep — not during active communication

---

## Self-Destruct Behavior

When a hostile environment is detected, the agent:

1. **Deletes its binary** from disk via `unlink()`
2. **Zeros environment memory** to prevent forensic recovery
3. **Exits with `_exit(0)`** — no atexit handlers, no stdio flush, no signal

The exit is indistinguishable from a normal process termination. No error message is written to stdout, stderr, or syslog.

---

## Integration Points

| File | Call | When |
|------|------|------|
| `main.c:58` | `nax_opsec_check()` | Before C2 connection |
| `https.c:919` | `nax_opsec_heartbeat()` | Every HTTPS heartbeat |
| `tcp.c:568` | `nax_opsec_heartbeat()` | Every TCP heartbeat |
| `tcp_bind.c:475` | `nax_opsec_heartbeat()` | Every TCP bind heartbeat |
| `main.c:135` | `nax_opsec_cleanup()` | Agent exit |

---

## Considerations

**False positives in labs:** The VM detection will trigger on any virtualized environment, including operator lab VMs. Disable OPSEC when testing in VirtualBox/VMware/QEMU.

**Cloud targets:** EC2, Azure, GCP instances are detected as VMs (DMI strings + MAC OUI). If operating against cloud infrastructure, OPSEC should be disabled or the VM checks should be customized.

**Containers:** Docker/LXC containers on bare metal pass all VM checks (no hypervisor, no VM MAC). The OPSEC module does not detect containers — that's handled by the `container_detect` BOF instead.

---

## References

- **Implementation:** `nax_linux/src/Opsec/opsec.c`
- **Header:** `nax_linux/include/opsec.h`
- **Build flag:** `NAX_OPSEC=1` in Makefile or OPSEC checkbox in Adaptix UI
