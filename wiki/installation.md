# Installation

NaxDarks supports two installation methods: **axtool** (recommended) and the legacy **setup_nax.sh** script.

---

## axtool (Recommended)

`axtool` is the official Adaptix extension manager. It handles dependency installation, compilation, and deployment in a single command.

### Install

From the root of the Adaptix repository:

```bash
./dist/axtool adaptix.spec ext install /path/to/NaxDarks [-f] [-d]
```

| Flag | Description |
|------|-------------|
| `-f` | Force reinstall / overwrite existing extension |
| `-d` | Install apt dependencies declared in `axtool.spec` before building |

**Example:**

```bash
./dist/axtool adaptix.spec ext install ~/Downloads/project/NaxDarks -f -d
```

The `-d` flag installs: `gcc`, `gcc-aarch64-linux-gnu`, `libssl-dev`, `zlib1g-dev`, `python3`, `make`.

### Uninstall

```bash
./dist/axtool adaptix.spec ext uninstall agent_naxdarks_linux -c
./dist/axtool adaptix.spec ext uninstall listener_naxdarks_linux_tcp -c
./dist/axtool adaptix.spec ext uninstall listener_naxdarks_linux_https -c
```

The `-c` flag removes compiled artifacts.

---

## Legacy: setup_nax.sh

The shell script method remains available.

```bash
# From the NaxDarks repository root
bash setup_nax.sh --server /path/to/AdaptixC2/dist
```

This builds all three plugins (agent + both listeners) and copies them to the Adaptix `dist/extenders/` directory.

---

## What Gets Installed

| Component | Type | Description |
|-----------|------|-------------|
| `agent_naxdarks_linux` | Agent plugin (`.so`) | Handles agent builds, command dispatch, result processing |
| `listener_naxdarks_linux_https` | Listener plugin (`.so`) | HTTPS listener with malleable C2 profile support |
| `listener_naxdarks_linux_tcp` | Listener plugin (`.so`) | TCP connect-out/pivot listener |

---

## Requirements

| Tool | Purpose |
|------|---------|
| `gcc` | x86_64 agent compilation |
| `gcc-aarch64-linux-gnu` | ARM64 cross-compilation |
| `libssl-dev` | TLS for HTTPS transport |
| `zlib1g-dev` | Compression (zip command) |
| `python3` | Stub payload generation (`gen_stub_payload.py`) |
| `make` | Build system |
| `go 1.26.5+` | Go plugin compilation |
