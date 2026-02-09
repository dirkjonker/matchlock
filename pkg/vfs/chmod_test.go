package vfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMemoryProvider_Chmod_File(t *testing.T) {
	mp := NewMemoryProvider()
	h, _ := mp.Create("/file.txt", 0644)
	h.Close()

	if err := mp.Chmod("/file.txt", 0755); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}

	info, _ := mp.Stat("/file.txt")
	if info.Mode().Perm() != 0755 {
		t.Errorf("mode = %o, want 0755", info.Mode().Perm())
	}
}

func TestMemoryProvider_Chmod_Dir(t *testing.T) {
	mp := NewMemoryProvider()
	mp.Mkdir("/dir", 0755)

	if err := mp.Chmod("/dir", 0700); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}

	info, _ := mp.Stat("/dir")
	if info.Mode().Perm() != 0700 {
		t.Errorf("mode = %o, want 0700", info.Mode().Perm())
	}
}

func TestMemoryProvider_Chmod_DirDefaultMode(t *testing.T) {
	mp := NewMemoryProvider()
	mp.Mkdir("/dir", 0755)

	info, _ := mp.Stat("/dir")
	if info.Mode().Perm() != 0755 {
		t.Errorf("default mode = %o, want 0755", info.Mode().Perm())
	}
}

func TestMemoryProvider_Chmod_NonExistent(t *testing.T) {
	mp := NewMemoryProvider()
	err := mp.Chmod("/nope", 0644)
	if err == nil {
		t.Error("should fail for non-existent path")
	}
}

func TestMemoryProvider_Chmod_PreservesAfterRename(t *testing.T) {
	mp := NewMemoryProvider()
	mp.Mkdir("/src", 0755)
	mp.Chmod("/src", 0700)
	mp.Mkdir("/dst", 0755)

	mp.Rename("/src", "/renamed")

	info, _ := mp.Stat("/renamed")
	if info.Mode().Perm() != 0700 {
		t.Errorf("mode after rename = %o, want 0700", info.Mode().Perm())
	}
}

func TestMemoryProvider_Mkdir_StoresMode(t *testing.T) {
	mp := NewMemoryProvider()
	mp.Mkdir("/dir", 0700)

	info, _ := mp.Stat("/dir")
	if info.Mode().Perm() != 0700 {
		t.Errorf("mode = %o, want 0700", info.Mode().Perm())
	}
}

func TestOverlayProvider_Chmod_UpperFile(t *testing.T) {
	lower := NewMemoryProvider()
	upper := NewMemoryProvider()
	h, _ := upper.Create("/file.txt", 0644)
	h.Close()

	overlay := NewOverlayProvider(upper, lower)
	if err := overlay.Chmod("/file.txt", 0755); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}

	info, _ := upper.Stat("/file.txt")
	if info.Mode().Perm() != 0755 {
		t.Errorf("mode = %o, want 0755", info.Mode().Perm())
	}
}

func TestOverlayProvider_Chmod_CopiesUpFromLower(t *testing.T) {
	lower := NewMemoryProvider()
	upper := NewMemoryProvider()

	h, _ := lower.Create("/file.txt", 0644)
	h.Write([]byte("lower content"))
	h.Close()

	overlay := NewOverlayProvider(upper, lower)
	if err := overlay.Chmod("/file.txt", 0755); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}

	// File should now exist in upper with new mode
	info, err := upper.Stat("/file.txt")
	if err != nil {
		t.Fatalf("file should exist in upper after copy-up: %v", err)
	}
	if info.Mode().Perm() != 0755 {
		t.Errorf("mode = %o, want 0755", info.Mode().Perm())
	}
}

func TestOverlayProvider_Chmod_NonExistent(t *testing.T) {
	lower := NewMemoryProvider()
	upper := NewMemoryProvider()
	overlay := NewOverlayProvider(upper, lower)

	err := overlay.Chmod("/nope", 0644)
	if err == nil {
		t.Error("should fail for non-existent path")
	}
}

func TestRealFSProvider_Chmod(t *testing.T) {
	dir := t.TempDir()
	p := NewRealFSProvider(dir)

	f, err := os.Create(filepath.Join(dir, "file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	if err := p.Chmod("/file.txt", 0700); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}

	info, _ := p.Stat("/file.txt")
	if info.Mode().Perm() != 0700 {
		t.Errorf("mode = %o, want 0700", info.Mode().Perm())
	}
}

func TestRealFSProvider_Chmod_Dir(t *testing.T) {
	dir := t.TempDir()
	p := NewRealFSProvider(dir)

	os.Mkdir(filepath.Join(dir, "subdir"), 0755)

	if err := p.Chmod("/subdir", 0700); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}

	info, _ := p.Stat("/subdir")
	if info.Mode().Perm() != 0700 {
		t.Errorf("mode = %o, want 0700", info.Mode().Perm())
	}
}

func TestRealFSProvider_Chmod_NonExistent(t *testing.T) {
	dir := t.TempDir()
	p := NewRealFSProvider(dir)

	err := p.Chmod("/nope", 0644)
	if err == nil {
		t.Error("should fail for non-existent path")
	}
}

func TestReadonlyProvider_Chmod_Blocked(t *testing.T) {
	base := NewMemoryProvider()
	h, _ := base.Create("/file.txt", 0644)
	h.Close()

	ro := NewReadonlyProvider(base)
	err := ro.Chmod("/file.txt", 0755)
	if err == nil {
		t.Error("Chmod should fail on readonly provider")
	}
}

func TestRouterProvider_Chmod(t *testing.T) {
	mp := NewMemoryProvider()
	h, _ := mp.Create("/file.txt", 0644)
	h.Close()

	router := NewMountRouter(map[string]Provider{"/mnt": mp})

	if err := router.Chmod("/mnt/file.txt", 0755); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}

	info, _ := mp.Stat("/file.txt")
	if info.Mode().Perm() != 0755 {
		t.Errorf("mode = %o, want 0755", info.Mode().Perm())
	}
}
