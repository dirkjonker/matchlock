package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveNonExistentVM(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManagerWithDir(dir)

	err := mgr.Remove("vm-nonexistent")
	if err == nil {
		t.Fatal("expected error when removing non-existent VM, got nil")
	}
}

func TestRemoveStoppedVM(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManagerWithDir(dir)

	vmDir := filepath.Join(dir, "vm-test123")
	os.MkdirAll(vmDir, 0700)
	os.WriteFile(filepath.Join(vmDir, "status"), []byte("stopped"), 0600)

	err := mgr.Remove("vm-test123")
	if err != nil {
		t.Fatalf("expected no error removing stopped VM, got: %v", err)
	}

	if _, err := os.Stat(vmDir); !os.IsNotExist(err) {
		t.Fatal("expected VM directory to be removed")
	}
}

func TestRemoveRunningVM(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManagerWithDir(dir)

	vmDir := filepath.Join(dir, "vm-running1")
	os.MkdirAll(vmDir, 0700)
	os.WriteFile(filepath.Join(vmDir, "status"), []byte("running"), 0600)

	err := mgr.Remove("vm-running1")
	if err == nil {
		t.Fatal("expected error when removing running VM, got nil")
	}
}
