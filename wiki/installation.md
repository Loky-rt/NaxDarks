# Installation

## Prerequisites

Install all build dependencies (x64 + ARM64 cross-compilation):

```bash
bash install-dep.sh
```

This installs: `gcc`, `make`, `pkg-config`, `gcc-aarch64-linux-gnu`, `libssl-dev`, `libcurl4-openssl-dev`, `zlib1g-dev` (x64 + arm64).

Go 1.26.5+ is required for the server plugins — install from [go.dev/dl](https://go.dev/dl/).

---

## Install with axtool (Recommended)

`axtool` is the official Adaptix extension manager. From the root of the Adaptix repository:

```bash
./dist/axtool adaptix.spec ext install /path/to/NaxDarks [-f]
```

| Flag | Description |
|------|-------------|
| `-f` | Force reinstall / overwrite existing extension |

**Example:**

```bash
./dist/axtool adaptix.spec ext install ~/Downloads/project/NaxDarks -f
```

### Uninstall

```bash
./dist/axtool adaptix.spec ext uninstall agent_naxdarks_linux -c
./dist/axtool adaptix.spec ext uninstall listener_naxdarks_linux_tcp -c
./dist/axtool adaptix.spec ext uninstall listener_naxdarks_linux_https -c
```

The `-c` flag removes compiled artifacts.

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
| `libssl-dev` | TLS for TCP and pivot transports |
| `libcurl4-openssl-dev` | HTTP/2 HTTPS transport |
| `zlib1g-dev` | Compression (zip command) |
| `python3` | Stub payload generation (`gen_stub_payload.py`) |
| `make` | Build system |
| `go 1.26.5+` | Go plugin compilation |
