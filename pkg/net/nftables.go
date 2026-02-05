//go:build linux

package net

import (
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	tableName   = "matchlock"
	chainPreNAT = "prerouting"
	chainFwd    = "forward"
)

type NFTablesRules struct {
	tapInterface string
	gatewayIP    net.IP
	httpPort     uint16
	httpsPort    uint16
	conn         *nftables.Conn
	table        *nftables.Table
}

func NewNFTablesRules(tapInterface, gatewayIP string, httpPort, httpsPort int) *NFTablesRules {
	return &NFTablesRules{
		tapInterface: tapInterface,
		gatewayIP:    net.ParseIP(gatewayIP).To4(),
		httpPort:     uint16(httpPort),
		httpsPort:    uint16(httpsPort),
	}
}

func (r *NFTablesRules) Setup() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to open nftables connection: %w", err)
	}
	r.conn = conn

	r.table = conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   tableName + "_" + r.tapInterface,
	})

	preChain := conn.AddChain(&nftables.Chain{
		Name:     chainPreNAT,
		Table:    r.table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})

	fwdChain := conn.AddChain(&nftables.Chain{
		Name:     chainFwd,
		Table:    r.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	ifaceIdx, err := getInterfaceIndex(r.tapInterface)
	if err != nil {
		return fmt.Errorf("failed to get interface index for %s: %w", r.tapInterface, err)
	}

	conn.AddRule(&nftables.Rule{
		Table: r.table,
		Chain: preChain,
		Exprs: r.buildDNATRule(ifaceIdx, 80, r.httpPort),
	})

	conn.AddRule(&nftables.Rule{
		Table: r.table,
		Chain: preChain,
		Exprs: r.buildDNATRule(ifaceIdx, 443, r.httpsPort),
	})

	conn.AddRule(&nftables.Rule{
		Table: r.table,
		Chain: fwdChain,
		Exprs: r.buildForwardRule(ifaceIdx, true),
	})

	conn.AddRule(&nftables.Rule{
		Table: r.table,
		Chain: fwdChain,
		Exprs: r.buildForwardRule(ifaceIdx, false),
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to apply nftables rules: %w", err)
	}

	return nil
}

func (r *NFTablesRules) buildDNATRule(ifaceIdx uint32, srcPort, dstPort uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(r.tapInterface),
		},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.IPPROTO_TCP},
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(srcPort),
		},
		&expr.Immediate{
			Register: 1,
			Data:     r.gatewayIP,
		},
		&expr.Immediate{
			Register: 2,
			Data:     binaryutil.BigEndian.PutUint16(dstPort),
		},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      unix.NFPROTO_IPV4,
			RegAddrMin:  1,
			RegProtoMin: 2,
		},
	}
}

func (r *NFTablesRules) buildForwardRule(ifaceIdx uint32, isInput bool) []expr.Any {
	metaKey := expr.MetaKeyIIFNAME
	if !isInput {
		metaKey = expr.MetaKeyOIFNAME
	}

	return []expr.Any{
		&expr.Meta{Key: metaKey, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname(r.tapInterface),
		},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

func (r *NFTablesRules) Cleanup() error {
	if r.conn == nil {
		conn, err := nftables.New()
		if err != nil {
			return err
		}
		r.conn = conn
	}

	tables, err := r.conn.ListTables()
	if err != nil {
		return err
	}

	tableName := tableName + "_" + r.tapInterface
	for _, t := range tables {
		if t.Name == tableName && t.Family == nftables.TableFamilyIPv4 {
			r.conn.DelTable(t)
			break
		}
	}

	return r.conn.Flush()
}

func getInterfaceIndex(name string) (uint32, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return uint32(iface.Index), nil
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n)
	return b
}

type NFTablesNAT struct {
	tapInterface string
	conn         *nftables.Conn
	table        *nftables.Table
}

func NewNFTablesNAT(tapInterface string) *NFTablesNAT {
	return &NFTablesNAT{
		tapInterface: tapInterface,
	}
}

func (n *NFTablesNAT) Setup() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to open nftables connection: %w", err)
	}
	n.conn = conn

	n.table = conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "matchlock_nat_" + n.tapInterface,
	})

	postChain := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    n.table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	fwdChain := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    n.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})

	conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: postChain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     ifname(n.tapInterface),
			},
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(n.tapInterface),
			},
			&expr.Masq{},
		},
	})

	conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: fwdChain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(n.tapInterface),
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: fwdChain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(n.tapInterface),
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to apply NAT rules: %w", err)
	}

	return nil
}

func (n *NFTablesNAT) Cleanup() error {
	if n.conn == nil {
		conn, err := nftables.New()
		if err != nil {
			return err
		}
		n.conn = conn
	}

	tables, err := n.conn.ListTables()
	if err != nil {
		return err
	}

	tableName := "matchlock_nat_" + n.tapInterface
	for _, t := range tables {
		if t.Name == tableName && t.Family == nftables.TableFamilyIPv4 {
			n.conn.DelTable(t)
			break
		}
	}

	return n.conn.Flush()
}
