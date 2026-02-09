package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func hasDebugfs() bool {
	_, err := exec.LookPath("debugfs")
	return err == nil
}

func hasMkfsExt4() bool {
	_, err := exec.LookPath("mkfs.ext4")
	return err == nil
}

func createTestExt4(t *testing.T, sizeMB int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.ext4")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(sizeMB) * 1024 * 1024); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	cmd := exec.Command("mkfs.ext4", "-F", "-q", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mkfs.ext4 failed: %v: %s", err, out)
	}
	return path
}

func debugfsStatMode(t *testing.T, rootfsPath, guestPath string) string {
	t.Helper()
	cmd := exec.Command("debugfs", "-R", "stat "+guestPath, rootfsPath)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("debugfs stat failed: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Mode:") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func debugfsCat(t *testing.T, rootfsPath, guestPath string) string {
	t.Helper()
	cmd := exec.Command("debugfs", "-R", "cat "+guestPath, rootfsPath)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("debugfs cat failed: %v", err)
	}
	return string(out)
}

func TestInjectConfigFileIntoRootfs(t *testing.T) {
	if !hasDebugfs() || !hasMkfsExt4() {
		t.Skip("debugfs or mkfs.ext4 not available")
	}

	rootfs := createTestExt4(t, 10)
	content := []byte("test-ca-cert-content")

	if err := injectConfigFileIntoRootfs(rootfs, "/etc/ssl/certs/ca.crt", content); err != nil {
		t.Fatalf("injectConfigFileIntoRootfs failed: %v", err)
	}

	got := debugfsCat(t, rootfs, "/etc/ssl/certs/ca.crt")
	if got != string(content) {
		t.Errorf("content = %q, want %q", got, string(content))
	}
}

func TestInjectConfigFileIntoRootfs_Mode0644(t *testing.T) {
	if !hasDebugfs() || !hasMkfsExt4() {
		t.Skip("debugfs or mkfs.ext4 not available")
	}

	rootfs := createTestExt4(t, 10)

	if err := injectConfigFileIntoRootfs(rootfs, "/etc/test.conf", []byte("data")); err != nil {
		t.Fatal(err)
	}

	modeLine := debugfsStatMode(t, rootfs, "/etc/test.conf")
	if !strings.Contains(modeLine, "0644") {
		t.Errorf("expected mode 0644, got: %s", modeLine)
	}
}

func TestInjectConfigFileIntoRootfs_CreatesParentDirs(t *testing.T) {
	if !hasDebugfs() || !hasMkfsExt4() {
		t.Skip("debugfs or mkfs.ext4 not available")
	}

	rootfs := createTestExt4(t, 10)

	if err := injectConfigFileIntoRootfs(rootfs, "/a/b/c/file.txt", []byte("deep")); err != nil {
		t.Fatal(err)
	}

	got := debugfsCat(t, rootfs, "/a/b/c/file.txt")
	if got != "deep" {
		t.Errorf("content = %q, want %q", got, "deep")
	}
}

func TestInjectConfigFileIntoRootfs_Overwrites(t *testing.T) {
	if !hasDebugfs() || !hasMkfsExt4() {
		t.Skip("debugfs or mkfs.ext4 not available")
	}

	rootfs := createTestExt4(t, 10)

	if err := injectConfigFileIntoRootfs(rootfs, "/etc/test.conf", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := injectConfigFileIntoRootfs(rootfs, "/etc/test.conf", []byte("second")); err != nil {
		t.Fatal(err)
	}

	got := debugfsCat(t, rootfs, "/etc/test.conf")
	if got != "second" {
		t.Errorf("content = %q, want %q", got, "second")
	}
}
