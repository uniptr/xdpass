package xdp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

func TestXDPSocket(t *testing.T) {
	brName := "br-xdp-test"
	numRxQueues := 4
	err := netlink.LinkAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: brName, NumRxQueues: numRxQueues}})
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: brName}})

	iface, err := net.InterfaceByName(brName)
	if err != nil {
		t.Fatal(err)
	}

	xsks := make([]*XDPSocket, numRxQueues)
	for queueID := 0; queueID < numRxQueues; queueID++ {
		// Must be different queueID for all xsks
		x, err := NewXDPSocket(uint32(iface.Index), uint32(queueID))
		if err != nil {
			t.Fatal(err)
		}
		xsks[queueID] = x
	}
	for _, x := range xsks {
		x.Close()
	}
}

func TestXDPSocketSharedUmem(t *testing.T) {
	brName := "br-xdp-test"
	numXsks := 4
	err := netlink.LinkAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: brName, NumRxQueues: numXsks}})
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: brName}})

	iface, err := net.InterfaceByName(brName)
	if err != nil {
		t.Fatal(err)
	}

	var (
		umem *XDPUmem
	)

	xsks := make([]*XDPSocket, numXsks)
	for i := 0; i < numXsks; i++ {
		// Must be same queueID for all xsks
		x, err := NewXDPSocket(uint32(iface.Index), 0, WithXDPSharedUmem(&umem))
		if err != nil {
			t.Fatal(err)
		}
		xsks[i] = x
		assert.Equal(t, x.umem.refCount, uint32(i+1))
	}

	for i := 0; i < numXsks; i++ {
		xsks[i].Close()
		assert.Equal(t, umem.refCount, uint32(numXsks-i-1))
	}
}
