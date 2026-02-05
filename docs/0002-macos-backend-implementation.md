# ADR-0002: macOS Backend Implementation Plan

## Status

Proposed

## Context

The Linux-based sandbox has been implemented using Firecracker micro-VMs with TAP devices and iptables for network interception. To achieve the cross-platform goals outlined in ADR-0001, we need to implement a macOS backend with feature parity.

### Current Linux Implementation

| Component | Implementation |
|-----------|----------------|
| VM Backend | Firecracker micro-VMs |
| Network I/O | TAP device (`/dev/net/tun`) |
| Guest-Host Comm | Vsock via UDS (Firecracker CONNECT protocol) |
| Traffic Redirect | iptables DNAT to transparent proxy |
| NAT | iptables MASQUERADE |
| VFS | FUSE daemon over vsock |

### macOS Constraints

- No Firecracker support (Linux-only)
- No TAP devices (requires kernel extensions, deprecated on macOS)
- No iptables (Linux netfilter)
- Apple Virtualization.framework available (macOS 11+)

## Decision

Implement macOS backend using **Apple Virtualization.framework** via [code-hex/vz](https://github.com/Code-Hex/vz) with the following architecture:

### Architecture Comparison

| Component | Linux | macOS |
|-----------|-------|-------|
| **VM Backend** | Firecracker | Virtualization.framework (vz) |
| **Network I/O** | TAP FD | Unix socket pair (SOCK_DGRAM) |
| **Guest-Host Comm** | Vsock UDS + CONNECT protocol | Native virtio-vsock (vz API) |
| **Traffic Intercept** | iptables DNAT → proxy | gVisor userspace stack |
| **NAT** | iptables MASQUERADE | pf NAT rules |

### Network Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  macOS                                                                      │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    Virtualization.framework                          │    │
│  │  ┌───────────────┐     ┌─────────────────────────────────────────┐  │    │
│  │  │ Linux Guest   │     │ VZFileHandleNetworkDeviceAttachment     │  │    │
│  │  │ (virtio-net)  │◄───►│ (socket pair guest end)                 │  │    │
│  │  └───────────────┘     └──────────────────┬──────────────────────┘  │    │
│  │                                           │                          │    │
│  │  ┌───────────────┐     ┌──────────────────▼──────────────────────┐  │    │
│  │  │ Linux Guest   │     │ VZVirtioSocketDevice                    │  │    │
│  │  │ (virtio-vsock)│◄───►│ (native vsock, no UDS protocol)        │  │    │
│  │  └───────────────┘     └─────────────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                           │                                  │
│                              Socket pair host end (FD)                       │
│                                           │                                  │
│                                           ▼                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      gVisor tcpip Stack                              │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │  fdbased.New(socketPairFD)  ─── Same as Linux TAP FD        │    │    │
│  │  └──────────────────────────────────────────────────────────────┘    │    │
│  │                              │                                       │    │
│  │  ┌───────────────────────────▼───────────────────────────────────┐  │    │
│  │  │              TCP/UDP Forwarder (L4)                           │  │    │
│  │  │  Port 80  → HTTP Interceptor                                  │  │    │
│  │  │  Port 443 → TLS MITM Interceptor                              │  │    │
│  │  │  Port 53  → DNS Forwarder                                     │  │    │
│  │  │  Other    → Policy-checked passthrough                        │  │    │
│  │  └───────────────────────────────────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                           │                                  │
│                                           ▼                                  │
│                                      Internet                                │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

#### 1. Use gVisor Stack Instead of pf/iptables

**Rationale**: The gVisor userspace TCP/IP stack (`pkg/net/stack.go`) already handles all network interception at the application layer. By feeding the socket pair FD to gVisor's `fdbased` endpoint (identical to how we use TAP FDs on Linux), we get:

- Full HTTP/HTTPS interception without OS-level packet filter rules
- Identical code path for both platforms
- No root/admin privileges needed for packet filtering
- Policy enforcement happens in the same place

**Trade-off**: Slightly higher latency than kernel-based networking, but acceptable for sandbox use cases.

#### 2. Native Vsock via vz API

**Rationale**: Virtualization.framework provides native virtio-vsock support through `VZVirtioSocketDevice`. Unlike Firecracker's UDS-based vsock (which requires the CONNECT protocol), vz exposes vsock directly:

```go
// macOS: Native vsock connection
conn, err := vm.SocketDevice().Connect(port)

// Linux: UDS + CONNECT protocol
conn, err := net.Dial("unix", vsockPath)
conn.Write([]byte(fmt.Sprintf("CONNECT %d\n", port)))
// ... read OK response
```

The guest-side code remains identical (both use virtio-vsock), only the host-side connection method differs.

#### 3. Socket Pair for Network

**Rationale**: macOS doesn't support TAP devices without kernel extensions. The Virtualization.framework provides `VZFileHandleNetworkDeviceAttachment` which accepts a file handle for raw Ethernet frame I/O. A Unix socket pair (`AF_UNIX, SOCK_DGRAM`) provides this:

```go
// Create socket pair
fds, _ := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
guestFD := fds[1]  // → VZFileHandleNetworkDeviceAttachment
hostFD := fds[0]   // → gVisor fdbased.New()
```

## Implementation Plan

### Phase 1: VM Backend Core

**Files**: `pkg/vm/darwin/backend.go`, `pkg/vm/darwin/machine.go`

```go
package darwin

import (
    "github.com/Code-Hex/vz/v4"
    "github.com/jingkaihe/matchlock/pkg/vm"
)

type DarwinBackend struct{}

func (b *DarwinBackend) Name() string { return "virtualization.framework" }

func (b *DarwinBackend) Create(ctx context.Context, config *vm.VMConfig) (vm.Machine, error) {
    // 1. Create boot loader
    bootLoader, _ := vz.NewLinuxBootLoader(
        config.KernelPath,
        vz.WithCommandLine(config.KernelArgs),
    )
    
    // 2. Create VM configuration
    vzConfig, _ := vz.NewVirtualMachineConfiguration(
        bootLoader,
        uint(config.CPUs),
        uint64(config.MemoryMB) * 1024 * 1024,
    )
    
    // 3. Set up storage (rootfs)
    diskAttachment, _ := vz.NewDiskImageStorageDeviceAttachment(
        config.RootfsPath,
        false, // not read-only
    )
    storageConfig, _ := vz.NewVirtioBlockDeviceConfiguration(diskAttachment)
    vzConfig.SetStorageDevicesVirtualMachineConfiguration([]vz.StorageDeviceConfiguration{storageConfig})
    
    // 4. Set up network (socket pair)
    socketPair, _ := createSocketPair()
    netAttachment, _ := vz.NewFileHandleNetworkDeviceAttachment(
        os.NewFile(uintptr(socketPair.guestFD), "guest-net"),
    )
    netConfig, _ := vz.NewVirtioNetworkDeviceConfiguration(netAttachment)
    vzConfig.SetNetworkDevicesVirtualMachineConfiguration([]vz.NetworkDeviceConfiguration{netConfig})
    
    // 5. Set up vsock
    vsockConfig, _ := vz.NewVirtioSocketDeviceConfiguration()
    vzConfig.SetSocketDevicesVirtualMachineConfiguration([]vz.SocketDeviceConfiguration{vsockConfig})
    
    // 6. Set up console
    serialConfig, _ := vz.NewVirtioConsoleDeviceSerialPortConfiguration(...)
    vzConfig.SetSerialPortsVirtualMachineConfiguration([]vz.SerialPortConfiguration{serialConfig})
    
    // 7. Validate and create VM
    validated, _ := vzConfig.Validate()
    vm, _ := vz.NewVirtualMachine(vzConfig)
    
    return &DarwinMachine{
        vm:          vm,
        config:      config,
        socketPair:  socketPair,
        vsockDevice: vm.SocketDevices()[0],
    }, nil
}
```

**Tasks**:
- [ ] Implement `DarwinBackend.Create()` with VZ configuration
- [ ] Implement `DarwinMachine.Start()`, `Stop()`, `Wait()`
- [ ] Implement `DarwinMachine.Exec()` using native vsock
- [ ] Implement socket pair creation and FD management
- [ ] Handle VM lifecycle and cleanup

### Phase 2: Network Setup

**Files**: `pkg/vm/darwin/network.go`

```go
package darwin

import "syscall"

type SocketPair struct {
    hostFD  int  // For gVisor stack
    guestFD int  // For VZ attachment
}

func createSocketPair() (*SocketPair, error) {
    fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
    if err != nil {
        return nil, err
    }
    
    // Set non-blocking for async I/O
    syscall.SetNonblock(fds[0], true)
    syscall.SetNonblock(fds[1], true)
    
    return &SocketPair{
        hostFD:  fds[0],
        guestFD: fds[1],
    }, nil
}

func (sp *SocketPair) HostFD() int  { return sp.hostFD }
func (sp *SocketPair) GuestFD() int { return sp.guestFD }

func (sp *SocketPair) Close() error {
    syscall.Close(sp.hostFD)
    syscall.Close(sp.guestFD)
    return nil
}
```

**Tasks**:
- [ ] Implement socket pair creation
- [ ] Verify Ethernet frame passing through socket pair
- [ ] Test with gVisor fdbased endpoint
- [ ] Handle MTU configuration

### Phase 3: Vsock Implementation

**Files**: `pkg/vm/darwin/vsock.go`

```go
package darwin

import "github.com/Code-Hex/vz/v4"

type VsockDialer struct {
    device *vz.VirtioSocketDevice
}

func (d *VsockDialer) Dial(port uint32) (net.Conn, error) {
    conn, err := d.device.Connect(port)
    if err != nil {
        return nil, err
    }
    return conn, nil
}

// For guest-initiated connections (VFS)
type VsockListener struct {
    device *vz.VirtioSocketDevice
    port   uint32
}

func (l *VsockListener) Accept() (net.Conn, error) {
    listener, err := l.device.Listen(l.port)
    if err != nil {
        return nil, err
    }
    return listener.Accept()
}
```

**Tasks**:
- [ ] Implement vsock dialer for exec/ready ports
- [ ] Implement vsock listener for VFS port
- [ ] Verify compatibility with guest-agent protocol
- [ ] Handle connection timeouts and errors

### Phase 4: Sandbox Integration

**Files**: `pkg/sandbox/sandbox_darwin.go`, `pkg/sandbox/sandbox_linux.go`

Refactor `sandbox.go` to use build tags for platform-specific code:

```go
// pkg/sandbox/sandbox_darwin.go
//go:build darwin

package sandbox

import (
    "github.com/jingkaihe/matchlock/pkg/vm/darwin"
    sandboxnet "github.com/jingkaihe/matchlock/pkg/net"
)

func newBackend() vm.Backend {
    return darwin.NewDarwinBackend()
}

func setupNetworkInterception(machine vm.Machine, config *api.Config, ...) (*sandboxnet.NetworkStack, error) {
    darwinMachine := machine.(*darwin.DarwinMachine)
    
    // Use gVisor stack with socket pair FD (no iptables needed)
    netStack, err := sandboxnet.NewNetworkStack(&sandboxnet.Config{
        FD:        darwinMachine.NetworkFD(),
        GatewayIP: config.GatewayIP,
        GuestIP:   config.GuestIP,
        MTU:       1500,
        Policy:    policyEngine,
        Events:    events,
    })
    
    return netStack, err
}

func setupNAT(tapName, subnet string) error {
    // macOS: Use pf or skip (gVisor handles routing)
    return nil
}
```

```go
// pkg/sandbox/sandbox_linux.go
//go:build linux

package sandbox

import (
    "github.com/jingkaihe/matchlock/pkg/vm/linux"
    sandboxnet "github.com/jingkaihe/matchlock/pkg/net"
)

func newBackend() vm.Backend {
    return linux.NewLinuxBackend()
}

func setupNetworkInterception(machine vm.Machine, config *api.Config, ...) (*sandboxnet.TransparentProxy, *sandboxnet.IPTablesRules, error) {
    // Existing Linux implementation with iptables
    // ...
}

func setupNAT(tapName, subnet string) error {
    return sandboxnet.SetupNAT(tapName, subnet)
}
```

**Tasks**:
- [ ] Extract Linux-specific code to `sandbox_linux.go`
- [ ] Create `sandbox_darwin.go` with VZ integration
- [ ] Update `sandbox.go` to use platform-agnostic interfaces
- [ ] Decide on network interception strategy (gVisor stack vs transparent proxy)

### Phase 5: NAT Configuration (Optional)

**Files**: `pkg/net/pf.go`

If outbound NAT is needed (for traffic not going through gVisor):

```go
package net

import (
    "fmt"
    "os/exec"
)

type PFRules struct {
    anchorName string
}

func NewPFRules(anchorName string) *PFRules {
    return &PFRules{anchorName: anchorName}
}

func (p *PFRules) SetupNAT(internalSubnet, externalIface string) error {
    rules := fmt.Sprintf(`
nat on %s from %s to any -> (%s)
`, externalIface, internalSubnet, externalIface)
    
    // Write rules to anchor
    cmd := exec.Command("pfctl", "-a", p.anchorName, "-f", "-")
    cmd.Stdin = strings.NewReader(rules)
    return cmd.Run()
}

func (p *PFRules) Cleanup() error {
    return exec.Command("pfctl", "-a", p.anchorName, "-F", "all").Run()
}
```

**Tasks**:
- [ ] Implement pf anchor management
- [ ] Add NAT rules for outbound traffic
- [ ] Handle cleanup on sandbox close
- [ ] Test with and without SIP (System Integrity Protection)

### Phase 6: Testing

**Tasks**:
- [ ] Unit tests for darwin backend
- [ ] Integration tests for VM lifecycle
- [ ] Network interception tests (HTTP/HTTPS MITM)
- [ ] Vsock communication tests
- [ ] VFS functionality tests
- [ ] Cross-platform feature parity verification

## File Structure

```
pkg/vm/
├── backend.go                 # Interface (unchanged)
├── linux/
│   ├── backend.go             # Firecracker (unchanged)
│   └── tap.go                 # TAP device (unchanged)
└── darwin/
    ├── backend.go             # VZ backend (new)
    ├── machine.go             # DarwinMachine impl (new)
    ├── network.go             # Socket pair (new)
    └── vsock.go               # Native vsock (new)

pkg/net/
├── stack.go                   # gVisor stack (reused for macOS)
├── proxy.go                   # Transparent proxy (Linux)
├── iptables.go                # Linux traffic redirect
├── pf.go                      # macOS pf rules (new, optional)
├── http.go                    # HTTP interceptor (unchanged)
└── tls.go                     # TLS MITM (unchanged)

pkg/sandbox/
├── sandbox.go                 # Core logic (refactored)
├── sandbox_linux.go           # Linux-specific (new)
├── sandbox_darwin.go          # macOS-specific (new)
└── paths.go                   # Path helpers (unchanged)
```

## Dependencies

### New Go Dependencies

```go
require (
    github.com/Code-Hex/vz/v4 v4.x.x  // Virtualization.framework bindings
)
```

### System Requirements

| Requirement | Version |
|-------------|---------|
| macOS | 11.0+ (Big Sur) |
| Xcode | 12.0+ (for vz) |
| Go | 1.25+ |
| CGO | Required (vz uses Objective-C) |

### Build Constraints

```go
// Darwin-only files
//go:build darwin

// Linux-only files  
//go:build linux

// Requires CGO for vz
// #cgo CFLAGS: -x objective-c
// #cgo LDFLAGS: -framework Virtualization
```

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| vz library stability | Medium | Library is mature, used by Lima/Colima; pin version |
| Apple Silicon vs Intel | Low | VZ framework abstracts differences; test on both |
| Kernel boot format | Medium | Use same vmlinux; VZ supports uncompressed kernels |
| Socket pair performance | Low | Acceptable for sandbox workloads; benchmark if needed |
| SIP restrictions | Medium | pf rules may need adjustment; document requirements |
| CGO requirement | Low | Already acceptable for this project |

## Success Criteria

1. **Feature Parity**: All Linux sandbox features work on macOS
   - VM lifecycle (create, start, stop, exec)
   - VFS mounting and file operations
   - HTTP/HTTPS interception with MITM
   - Secret injection and placeholder replacement
   - Policy enforcement (allowlists, blocking)

2. **Performance**: Acceptable boot time and execution latency
   - VM boot < 2 seconds
   - Exec round-trip < 100ms
   - Network latency overhead < 50ms

3. **Usability**: Same CLI and API on both platforms
   - `matchlock run` works identically
   - SDK client works without changes
   - Configuration format unchanged

## Timeline Estimate

| Phase | Effort | Dependencies |
|-------|--------|--------------|
| Phase 1: VM Backend | 3-4 days | None |
| Phase 2: Network | 1-2 days | Phase 1 |
| Phase 3: Vsock | 1-2 days | Phase 1 |
| Phase 4: Sandbox Integration | 2-3 days | Phases 1-3 |
| Phase 5: NAT (optional) | 1 day | Phase 4 |
| Phase 6: Testing | 2-3 days | All phases |
| **Total** | **10-15 days** | |

## References

- [ADR-0001: Go-Based Cross-Platform Sandbox](../0001-go-based-cross-platform-sandbox.md)
- [code-hex/vz Documentation](https://github.com/Code-Hex/vz)
- [Apple Virtualization.framework](https://developer.apple.com/documentation/virtualization)
- [gVisor Network Stack](https://gvisor.dev/docs/user_guide/networking/)
