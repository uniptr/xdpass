package xdp

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

func newLinkAddCall(t *testing.T, numQ int, fn func(t *testing.T, ifaceIndx int)) {
	brName := "br-xdp-test"
	err := netlink.LinkAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: brName, NumRxQueues: numQ, NumTxQueues: numQ}})
	if err != nil {
		if !os.IsExist(err) {
			t.Fatal(err)
		}
	}
	defer netlink.LinkDel(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: brName}})

	iface, err := net.InterfaceByName(brName)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("New link index: %d", iface.Index)

	fn(t, iface.Index)
}

func TestXDPSocket(t *testing.T) {
	numRxQueues := 4
	newLinkAddCall(t, numRxQueues, func(t *testing.T, ifaceIndex int) {
		xsks := make([]*XDPSocket, numRxQueues)
		for queueID := 0; queueID < numRxQueues; queueID++ {
			// Must be different queueID for all xsks
			x, err := NewXDPSocket(uint32(ifaceIndex), uint32(queueID))
			if err != nil {
				t.Fatal(err)
			}
			xsks[queueID] = x
		}
		for _, x := range xsks {
			x.Close()
		}
	})
}

func TestXDPSocketSharedUmem(t *testing.T) {
	numXsks := 4

	newLinkAddCall(t, numXsks, func(t *testing.T, ifaceIndx int) {
		var (
			umem *XDPUmem
		)

		xsks := make([]*XDPSocket, numXsks)
		for i := 0; i < numXsks; i++ {
			// Must be same queueID for all xsks
			x, err := NewXDPSocket(uint32(ifaceIndx), 0, WithSharedUmem(&umem))
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
	})
}

func TestXDPSocketSingleRing(t *testing.T) {
	newLinkAddCall(t, 1, func(t *testing.T, ifaceIndx int) {
		// Only rx
		x, err := NewXDPSocket(uint32(ifaceIndx), 0, WithTxSize(0))
		if err != nil {
			t.Fatal(err)
		}
		x.Close()

		time.Sleep(1 * time.Millisecond * 300)

		// Only rx
		x, err = NewXDPSocket(uint32(ifaceIndx), 0, WithRxSize(0))
		if err != nil {
			t.Fatal(err)
		}
		x.Close()
	})
}
