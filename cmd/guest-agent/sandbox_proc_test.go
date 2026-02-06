package main

import (
	"runtime"
	"testing"
)

func TestBuildSeccompFilter(t *testing.T) {
	filter := buildSeccompFilter()

	// 3 header instructions + N blocked syscalls + 2 return instructions
	blocked, _ := blockedSyscalls()
	expectedLen := 3 + len(blocked) + 2
	if len(filter) != expectedLen {
		t.Errorf("expected %d instructions, got %d", expectedLen, len(filter))
	}

	// First instruction: load architecture (offset 4 in seccomp_data)
	if filter[0].Code != bpfLD|bpfW|bpfABS || filter[0].K != 4 {
		t.Errorf("first instruction should load arch at offset 4, got code=0x%x k=%d", filter[0].Code, filter[0].K)
	}

	// Second instruction: check architecture
	if filter[1].Code != bpfJMP|bpfJEQ|bpfK {
		t.Errorf("second instruction should be arch check jump, got code=0x%x", filter[1].Code)
	}

	// Third instruction: load syscall number (offset 0)
	if filter[2].Code != bpfLD|bpfW|bpfABS || filter[2].K != 0 {
		t.Errorf("third instruction should load syscall nr at offset 0, got code=0x%x k=%d", filter[2].Code, filter[2].K)
	}

	// Second-to-last: ALLOW
	allowIdx := len(filter) - 2
	if filter[allowIdx].Code != bpfRET|bpfK || filter[allowIdx].K != seccompRetAllow {
		t.Errorf("second-to-last should be RET ALLOW, got code=0x%x k=0x%x", filter[allowIdx].Code, filter[allowIdx].K)
	}

	// Last: ERRNO(EPERM)
	lastIdx := len(filter) - 1
	if filter[lastIdx].Code != bpfRET|bpfK || filter[lastIdx].K != seccompRetErrno|errnoEPERM {
		t.Errorf("last should be RET ERRNO(EPERM), got code=0x%x k=0x%x", filter[lastIdx].Code, filter[lastIdx].K)
	}
}

func TestBlockedSyscalls(t *testing.T) {
	blocked, auditArch := blockedSyscalls()

	if len(blocked) != 5 {
		t.Errorf("expected 5 blocked syscalls, got %d", len(blocked))
	}

	switch runtime.GOARCH {
	case "amd64":
		if auditArch != auditArchX86_64 {
			t.Errorf("expected x86_64 audit arch, got 0x%x", auditArch)
		}
		expected := []uint32{
			sysProcessVMReadvAmd64,
			sysProcessVMWritevAmd64,
			sysPtraceAmd64,
			sysKexecLoadAmd64,
			sysKexecFileLoadAmd64,
		}
		for i, nr := range expected {
			if blocked[i] != nr {
				t.Errorf("blocked[%d] = %d, want %d", i, blocked[i], nr)
			}
		}
	case "arm64":
		if auditArch != auditArchAARCH64 {
			t.Errorf("expected aarch64 audit arch, got 0x%x", auditArch)
		}
	}
}

func TestWipeBytes(t *testing.T) {
	data := []byte("secret-api-key-value")
	wipeBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte %d not wiped: got %d", i, b)
		}
	}
}

func TestWipeMap(t *testing.T) {
	m := map[string]string{
		"ANTHROPIC_API_KEY": "sk-ant-api03-xxx",
		"OTHER_KEY":         "other-value",
	}
	wipeMap(m)
	if len(m) != 0 {
		t.Errorf("map should be empty after wipe, got %d entries", len(m))
	}
}

func TestIsSandboxLauncher(t *testing.T) {
	if isSandboxLauncher() {
		t.Error("should not be sandbox launcher by default")
	}

	t.Setenv(sandboxLauncherEnvKey, "1")
	if !isSandboxLauncher() {
		t.Error("should be sandbox launcher when env var is set")
	}
}
