# Matchlock

Run AI agents securely in isolated micro-VM sandboxes without worrying about secret exfiltration. Matchlock provides granular network controls — allowlist specific hosts, inject secrets via MITM proxy so they never enter the VM, and block everything else by default.

## Features

- **Micro-VM Isolation**: Each sandbox runs in its own Firecracker (Linux) or Virtualization.framework (macOS) VM
- **Container Images**: Run any Docker/OCI image — Alpine, Ubuntu, Python, Node, etc.
- **Network Control**: Allowlist specific hosts, block everything else. All HTTP/HTTPS traffic intercepted via transparent proxy
- **Secret Protection**: Secrets never enter the VM. The VM sees a placeholder; the MITM proxy replaces it in-flight on allowed hosts only
- **Cross-Platform**: Full feature parity on Linux (x86_64) and macOS (Apple Silicon)
- **Programmable VFS**: Overlay filesystems with copy-on-write, mounted via FUSE
- **Fast Boot**: Sub-second VM startup

## Quick Start

### Prerequisites

- [mise](https://mise.jdx.dev/) for task management
- **Linux**: KVM support
- **macOS**: Apple Silicon, `brew install e2fsprogs`

### Install

```bash
git clone https://github.com/jingkaihe/matchlock.git
cd matchlock
mise install          # Install Go, linters, tools

# macOS (Apple Silicon)
mise run darwin:setup # Build + codesign CLI + ARM64 guest binaries

# Linux
mise run setup        # Build + install Firecracker + configure permissions
```

### Usage

```bash
# Run a command in a sandbox (--image is required)
matchlock run --image alpine:latest cat /etc/os-release
matchlock run --image python:3.12-alpine python3 --version

# Interactive shell
matchlock run --image alpine:latest -it sh

# Keep sandbox alive after command exits
matchlock run --image alpine:latest --rm=false echo hello
# Prints VM ID, e.g. vm-abc12345

# Start a sandbox without running a command
matchlock run --image alpine:latest --rm=false

# Execute command in a running sandbox
matchlock exec vm-abc12345 echo hello
matchlock exec vm-abc12345 -it sh

# With network allowlist
matchlock run --image python:3.12-alpine \
  --allow-host "api.openai.com" \
  python agent.py

# With secrets (MITM replaces placeholder in HTTP requests)
export ANTHROPIC_API_KEY=sk-xxx
matchlock run --image python:3.12-alpine \
  --secret ANTHROPIC_API_KEY@api.anthropic.com \
  python call_api.py

# Lifecycle management
matchlock list                     # List sandboxes
matchlock kill vm-abc123           # Kill a sandbox
matchlock kill --all               # Kill all running sandboxes
matchlock rm vm-abc123             # Remove stopped sandbox state
matchlock prune                    # Remove all stopped/crashed state
```

### How It Works

1. **`matchlock run --image alpine:latest`** pulls the OCI image, extracts layers, injects guest components, creates an ext4 rootfs, and boots a micro-VM
2. Subsequent runs use the cached rootfs for instant startup (`~/.cache/matchlock/images/`)
3. When `--allow-host` or `--secret` is specified, all traffic is routed through a transparent MITM proxy that enforces policy

## Architecture

```
┌─────────────────────────────────────────────────┐
│                     Host                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────┐  │
│  │  Matchlock  │  │   Policy    │  │   VFS   │  │
│  │    CLI      │──│   Engine    │  │  Server  │  │
│  └─────────────┘  └─────────────┘  └─────────┘  │
│         │              │                 │       │
│         ▼              ▼                 │       │
│  ┌──────────────────────────────┐        │       │
│  │ Transparent Proxy + TLS MITM │        │       │
│  └──────────────────────────────┘        │       │
│              │                           │       │
├──────────────│───────────────────────────│───────┤
│              │       Vsock               │       │
│  ┌───────────┴───────────────────────────┴─────┐ │
│  │              Micro-VM                       │ │
│  │  ┌─────────────┐  ┌─────────────────────┐   │ │
│  │  │ Guest Agent │  │ /workspace (FUSE)   │   │ │
│  │  └─────────────┘  └─────────────────────┘   │ │
│  │       Any OCI Image (Alpine, Ubuntu, etc)   │ │
│  └─────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

## Network Modes

**Linux**: nftables transparent proxy — DNAT redirects ports 80/443 to host proxy, kernel handles TCP/IP.

**macOS (Apple Silicon)**:
- **NAT mode** (default): Apple Virtualization.framework built-in NAT with DHCP — no interception
- **Interception mode** (when `--allow-host` or `--secret` is used): gVisor userspace TCP/IP stack intercepts all connections at L4

## Documentation

See [AGENTS.md](AGENTS.md) for full developer reference — project structure, build commands, component details, vsock protocol, and kernel configuration.

## License

MIT
