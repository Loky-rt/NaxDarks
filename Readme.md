# NaxDarks

![img1](img/img_1.png)

NaxDarks is a Red Team agent for Linux, built for the [Adaptix Framework](https://github.com/Adaptix-Framework/AdaptixC2/tree/main), that brings the flexibility of Beacon Object Files (BOFs) to the Linux ecosystem.

Forget depending on Python or Bash on the target machine. NaxDarks executes compiled C object files (.o) directly in memory using an in-memory ELF loader (mmap + relocate + execute), with a Beacon-style API and native support for asynchronous BOF execution. It includes malleable HTTPS transport, TCP pivoting, and a suite of ready-to-use post-exploitation BOFs.

![Language](https://img.shields.io/badge/agent-C-blue)
![Language](https://img.shields.io/badge/server-Go-00ADD8)
![Platform](https://img.shields.io/badge/target-Linux-FCC624)
![Arch](https://img.shields.io/badge/arch-x64%20%7C%20arm64-lightgrey)
![Framework](https://img.shields.io/badge/framework-Adaptix-purple)

## Features

- **HTTPS transport** - malleable C2 profile v2 with URI and host rotation, configurable sleep and jitter
- **TCP transport** - connect-out and bind/pivot modes
- **Multi-hop pivoting** - chain multiple Linux TCP bind agents through a single HTTPS parent
- **Multi-architecture** - x86_64 and ARM64
- **AES-128-CBC encryption** - all frames encrypted end-to-end
- **SOCKS4/5 proxy** and **reverse port forwarding** via Adaptix tunnel system
- **In-memory execution** - fileless loader via `memfd_create`
- **BOF execution** - In-memory execution of C object files (.o) with full Beacon-compatible API
- **Asynchronous BOFs** - background execution via threading, cooperative cancellation, and job management
- **OPSEC** - anti-debug, anti-VM, and self-destruct capabilities (compile-time optional)
- **Sleep Obfuscation** - Sensitive data only (Transport HTTPS)

## Quick Start

### Prerequisites

```bash
# Required
sudo apt-get install gcc golang libssl-dev

# Optional — ARM64 cross-compilation
sudo apt-get install gcc-aarch64-linux-gnu
sudo dpkg --add-architecture arm64 && sudo apt-get install libssl-dev:arm64
```

### Deploy

```bash
# Full install
bash setup_nax.sh --server /path/to/adaptixserver/dist

# Individual plugins
bash setup_nax.sh --server /path/to/adaptixserver/dist --action agent-linux
bash setup_nax.sh --server /path/to/adaptixserver/dist --action listener-linux-tcp
bash setup_nax.sh --server /path/to/adaptixserver/dist --action listener-linux-https

# Check prerequisites
bash setup_nax.sh --server /path/to/adaptixserver/dist --action prereqs
```

## Commands

| Command | Description |
|---------|-------------|
| `whoami` | Show current user, UID, GID |
| `pwd` | Print current working directory |
| `env` | Print environment variables |
| `cd` | Change working directory |
| `ls` | List directory contents |
| `cat` | Read file contents |
| `mkdir` | Create directory |
| `rmdir` | Remove empty directory |
| `rm` | Delete file |
| `download` | Download file from target |
| `upload` | Upload file to agent machine |
| `shell` | Execute via `/bin/sh -c` |
| `ps` | List running processes |
| `kill` | Kill process by PID |
| `ifconfig` | Show network interfaces |
| `zip` | Compress file or directory into ZIP |
| `sleep` | Set beacon sleep interval in seconds (HTTPS only) |
| `bof` | Execute an ELF BOF (.o file) in-memory |
| `exit` | Terminate the agent |
| `socks` | Manage SOCKS proxy tunnel |
| `rportfwd` | Manage reverse port forwarding |
| `link` | Link to a child Linux pivot agent via TCP |
| `unlink` | Disconnect a linked pivot agent |
| `bof_async` | Execute an ELF BOF in background thread |
| `jobs` | List running async BOF jobs |
| `jobkill` | Stop a running async BOF job |
| `profile_update` | Update HTTPS malleable profile at runtime |

## BOFs

You can find a collection of more than 20 BOFs at [linux-bof](https://github.com/Loky-rt/linux-bof). 

1. Clone the repository
2. compile the BOFs
3. load the `bof.axs` script into Adaptix.

## Transports

### HTTPS

Full malleable C2 profile v2 support — configurable encoding, URI and host rotation, sleep and jitter. The profile is received dynamically from the server on the first connection.

### TCP Connect-out

Direct connection to the Adaptix Linux TCP listener. Sleep intervals are not configurable in this mode.

### TCP Bind (Pivot)

The agent listens on a local port, allowing a parent agent to connect inbound. Supports pivot chains of arbitrary depth. All child traffic is relayed by the parent during its normal beacon cycle.

## Project Structure

```bash
NaxDarks
├── agent_naxdarks_linux
│   ├── ax_config.axs
│   ├── bof_args.go
│   ├── config.yaml
│   ├── go.mod
│   ├── go.sum
│   ├── pl_agent.go
│   ├── pl_commands.go
│   ├── pl_crypto.go
│   ├── pl_format.go
│   ├── pl_main.go
│   ├── pl_profile.go
│   ├── pl_results.go
│   ├── pl_tunnels.go
│   └── pl_wire.go
├── nax_linux
│   ├── deps
│   │   └── elf-bof
│   │       ├── include
│   │       │   ├── bof_api.h
│   │       │   ├── bof_async.h
│   │       │   ├── elf_bof.h
│   │       │   └── nax_bof_sdk.h
│   │       └── lib
│   │           ├── libelf_bof_arm64.a
│   │           └── libelf_bof_x64.a
│   ├── include
│   │   ├── commands.h
│   │   ├── nax_config.h
│   │   ├── nax_linux.h
│   │   ├── opsec.h
│   │   └── sysinfo.h
│   ├── Makefile
│   └── src
│       ├── Commands
│       │   ├── commands.c
│       │   ├── tunnel.c
│       │   └── zip.c
│       ├── Core
│       │   ├── crypto.c
│       │   ├── packer.c
│       │   └── sysinfo.c
│       ├── Loader
│       │   └── memfd_loader.c
│       ├── main.c
│       ├── Opsec
│       │   └── opsec.c
│       └── Transport
│           ├── https.c
│           ├── https_profile.c
│           ├── tcp_bind.c
│           └── tcp.c
├── profiles
│   ├── aws-cloudfront.json
│   ├── jquery-stealth.json
│   └── microsoft-graph.json
├── Readme.md
├── setup_nax.sh
├── src_server
│   ├── listener_naxdarks_linux_https
│   │   ├── ax_config.axs
│   │   ├── config.yaml
│   │   ├── go.mod
│   │   ├── go.sum
│   │   ├── pl_crypto.go
│   │   ├── pl_http.go
│   │   ├── pl_http_profile.go
│   │   ├── pl_http_profile_store.go
│   │   ├── pl_http_transform.go
│   │   ├── pl_main.go
│   │   └── pl_wire.go
│   ├── listener_naxdarks_linux_tcp
│   │   ├── ax_config.axs
│   │   ├── config.yaml
│   │   ├── go.mod
│   │   ├── go.sum
│   │   └── pl_main.go
│   └── Makefile
└── wiki
    ├── Malleable-C2-Profiles.md
    ├── opsec.md
    ├── register_commands.md
    └── transport.md
```

---

# Warning:

Not all implemented techniques represent the best choice for robust OPSEC; feel free to keep your version private or submit a PR to help improve the agent's OPSEC level.

---

# Disclaimer

For authorized security research, penetration testing, red team operations, and security tooling development only. Use only on systems where you have explicit authorization.


---

# Acknowledgments

- [Adaptix Framework](https://github.com/Adaptix-Framework/Adaptix) -- C2 framework
- [Agent NoNameAx](https://github.com/MaorSabag/NaX) -- Windows Agent (Adaptix framework)
- [Agent Darks](https://github.com/ServiceNow/Dark-Agent) -- Linux Agent (Mythic framework)
