//go:build linux

package main

import "syscall"

func totalMemoryMB() int {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		return 2048
	}
	return int(info.Totalram * uint64(info.Unit) / (1024 * 1024))
}
