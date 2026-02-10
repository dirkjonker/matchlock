//go:build linux

package net

import (
	"fmt"

	"github.com/godbus/dbus/v5"
)

const (
	firewalldDBusName      = "org.fedoraproject.FirewallD1"
	firewalldDBusPath      = "/org/fedoraproject/FirewallD1"
	firewalldDBusInterface = "org.fedoraproject.FirewallD1.zone"
)

// isFirewalldRunning checks if firewalld is active by looking for its name on
// the system D-Bus.
func isFirewalldRunning() bool {
	conn, err := dbus.SystemBus()
	if err != nil {
		return false
	}

	var names []string
	if err := conn.BusObject().Call("org.freedesktop.DBus.ListNames", 0).Store(&names); err != nil {
		return false
	}
	for _, name := range names {
		if name == firewalldDBusName {
			return true
		}
	}
	return false
}

// addInterfaceToTrustedZone adds a network interface to firewalld's trusted
// zone via D-Bus. This ensures that forwarded traffic through the interface is
// not rejected by firewalld's filter_FORWARD chain, which rejects packets from
// interfaces not assigned to any zone.
func addInterfaceToTrustedZone(iface string) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("connect to system bus: %w", err)
	}

	obj := conn.Object(firewalldDBusName, firewalldDBusPath)
	call := obj.Call(firewalldDBusInterface+".addInterface", 0, "trusted", iface)
	return call.Err
}

// removeInterfaceFromTrustedZone removes a network interface from firewalld's
// trusted zone via D-Bus.
func removeInterfaceFromTrustedZone(iface string) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return
	}

	obj := conn.Object(firewalldDBusName, firewalldDBusPath)
	obj.Call(firewalldDBusInterface+".removeInterface", 0, "trusted", iface)
}
