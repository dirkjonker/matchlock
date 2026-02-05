package image

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type Builder struct {
	cacheDir       string
	guestAgentPath string
	guestFusedPath string
	forcePull      bool
}

type BuildOptions struct {
	CacheDir       string
	GuestAgentPath string
	GuestFusedPath string
	ForcePull      bool
}

func NewBuilder(opts *BuildOptions) *Builder {
	cacheDir := opts.CacheDir
	if cacheDir == "" {
		home, _ := os.UserHomeDir()
		cacheDir = filepath.Join(home, ".cache", "matchlock", "images")
	}
	return &Builder{
		cacheDir:       cacheDir,
		guestAgentPath: opts.GuestAgentPath,
		guestFusedPath: opts.GuestFusedPath,
		forcePull:      opts.ForcePull,
	}
}

type BuildResult struct {
	RootfsPath string
	Digest     string
	Size       int64
	Cached     bool
}

func (b *Builder) Build(ctx context.Context, imageRef string) (*BuildResult, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parse image reference: %w", err)
	}

	// Check for existing cached rootfs before contacting registry
	cacheDir := filepath.Join(b.cacheDir, sanitizeRef(imageRef))
	if !b.forcePull {
		if entries, err := os.ReadDir(cacheDir); err == nil {
			for _, e := range entries {
				if filepath.Ext(e.Name()) == ".ext4" {
					rootfsPath := filepath.Join(cacheDir, e.Name())
					fi, _ := os.Stat(rootfsPath)
					return &BuildResult{
						RootfsPath: rootfsPath,
						Digest:     strings.TrimSuffix(e.Name(), ".ext4"),
						Size:       fi.Size(),
						Cached:     true,
					}, nil
				}
			}
		}
	}

	// Pull from registry
	remoteOpts := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	}
	remoteOpts = append(remoteOpts, b.platformOptions()...)

	img, err := remote.Image(ref, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("pull image: %w", err)
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("get image digest: %w", err)
	}

	rootfsPath := filepath.Join(cacheDir, digest.Hex[:12]+".ext4")

	if err := os.MkdirAll(filepath.Dir(rootfsPath), 0755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}

	extractDir, err := os.MkdirTemp("", "matchlock-extract-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(extractDir)

	if err := b.extractImage(img, extractDir); err != nil {
		return nil, fmt.Errorf("extract image: %w", err)
	}

	if err := b.injectMatchlockComponents(extractDir); err != nil {
		return nil, fmt.Errorf("inject components: %w", err)
	}

	if err := b.createExt4(extractDir, rootfsPath); err != nil {
		os.Remove(rootfsPath)
		return nil, fmt.Errorf("create ext4: %w", err)
	}

	fi, _ := os.Stat(rootfsPath)
	return &BuildResult{
		RootfsPath: rootfsPath,
		Digest:     digest.String(),
		Size:       fi.Size(),
	}, nil
}

func (b *Builder) extractImage(img v1.Image, destDir string) error {
	reader := mutate.Extract(img)
	defer reader.Close()

	// Use --numeric-owner to preserve UIDs/GIDs from the container image
	cmd := exec.Command("tar", "-xf", "-", "-C", destDir, "--numeric-owner")
	cmd.Stdin = reader
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("extract tar: %w", err)
	}

	return nil
}

func (b *Builder) injectMatchlockComponents(rootDir string) error {
	dirs := []string{
		filepath.Join(rootDir, "opt", "matchlock"),
		filepath.Join(rootDir, "sbin"),
		filepath.Join(rootDir, "run"),
		filepath.Join(rootDir, "proc"),
		filepath.Join(rootDir, "sys"),
		filepath.Join(rootDir, "dev"),
		filepath.Join(rootDir, "workspace"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
	}

	if b.guestAgentPath != "" {
		if err := copyFile(b.guestAgentPath, filepath.Join(rootDir, "opt", "matchlock", "guest-agent"), 0755); err != nil {
			return fmt.Errorf("copy guest-agent: %w", err)
		}
	}

	if b.guestFusedPath != "" {
		if err := copyFile(b.guestFusedPath, filepath.Join(rootDir, "opt", "matchlock", "guest-fused"), 0755); err != nil {
			return fmt.Errorf("copy guest-fused: %w", err)
		}
	}

	// Configure DNS - container images often have broken/empty resolv.conf
	resolvConf := filepath.Join(rootDir, "etc", "resolv.conf")
	os.Remove(resolvConf) // Remove if it's a symlink
	if err := os.WriteFile(resolvConf, []byte("nameserver 8.8.8.8\nnameserver 8.8.4.4\n"), 0644); err != nil {
		return fmt.Errorf("write resolv.conf: %w", err)
	}

	initScript := `#!/bin/sh
# Matchlock minimal init - runs as PID 1
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Remount root read-write (may be mounted ro by initramfs)
mount -o remount,rw / 2>/dev/null || true

mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t devtmpfs dev /dev 2>/dev/null || true

mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts 2>/dev/null || true
mount -t tmpfs tmpfs /dev/shm 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true

hostname matchlock

# Network setup - bring up interface and get IP via DHCP
ip link set eth0 up 2>/dev/null || ifconfig eth0 up 2>/dev/null

# Try DHCP if kernel didn't configure IP (NAT mode)
if ! ip addr show eth0 2>/dev/null | grep -q "inet "; then
    # Alpine/busybox udhcpc
    if command -v udhcpc >/dev/null 2>&1; then
        udhcpc -i eth0 -n -q 2>/dev/null &
    # Debian/Ubuntu dhclient
    elif command -v dhclient >/dev/null 2>&1; then
        dhclient eth0 2>/dev/null &
    fi
    sleep 2
fi

# Start FUSE daemon for VFS
/opt/matchlock/guest-fused &

# Get workspace path from kernel cmdline
WORKSPACE=$(cat /proc/cmdline | tr ' ' '\n' | grep 'matchlock.workspace=' | cut -d= -f2)
[ -z "$WORKSPACE" ] && WORKSPACE="/workspace"

# Wait for VFS mount before starting agent
for i in $(seq 1 50); do
    if mount | grep -q "$WORKSPACE"; then
        break
    fi
    sleep 0.1
done

# CA cert is injected directly into rootfs at /etc/ssl/certs/matchlock-ca.crt
# No VFS-based injection needed

exec /opt/matchlock/guest-agent
`
	initPath := filepath.Join(rootDir, "sbin", "matchlock-init")
	if err := os.WriteFile(initPath, []byte(initScript), 0755); err != nil {
		return fmt.Errorf("write init script: %w", err)
	}

	// Create /init as the actual init script (not a symlink)
	// This ensures it works with switch_root and various init systems
	rootInit := filepath.Join(rootDir, "init")
	os.Remove(rootInit) // Remove if exists (Alpine images may have their own)
	if err := os.WriteFile(rootInit, []byte(initScript), 0755); err != nil {
		return fmt.Errorf("write /init: %w", err)
	}

	// Also replace /sbin/init for compatibility
	originalInit := filepath.Join(rootDir, "sbin", "init")
	os.Remove(originalInit)
	if err := os.WriteFile(originalInit, []byte(initScript), 0755); err != nil {
		return fmt.Errorf("write /sbin/init: %w", err)
	}

	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func sanitizeRef(ref string) string {
	ref = strings.ReplaceAll(ref, "/", "_")
	ref = strings.ReplaceAll(ref, ":", "_")
	return ref
}
