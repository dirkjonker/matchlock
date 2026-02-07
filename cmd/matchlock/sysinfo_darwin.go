//go:build darwin

package main

import (
	"encoding/binary"
	"syscall"
)

func totalMemoryMB() int {
	val, err := syscall.Sysctl("hw.memsize")
	if err != nil || len(val) < 8 {
		return 2048
	}
	mem := binary.LittleEndian.Uint64([]byte(val + "\x00")[:8])
	return int(mem / (1024 * 1024))
}
