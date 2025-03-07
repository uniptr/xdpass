package redirect

import (
	"fmt"
	"sync"

	"github.com/vishvananda/netlink"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/fastpkt"
)

type TuntapHandle struct {
	mu      *sync.RWMutex
	devices map[string]*netlink.Tuntap
}

func NewTuntapHandle() (*TuntapHandle, error) {
	return &TuntapHandle{
		mu:      &sync.RWMutex{},
		devices: make(map[string]*netlink.Tuntap),
	}, nil
}

func (TuntapHandle) RedirectType() protos.RedirectType {
	return protos.RedirectTypeTuntap
}

func (h *TuntapHandle) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, tuntap := range h.devices {
		netlink.LinkDel(tuntap)
	}
	return nil
}

func (h *TuntapHandle) GetTuntaps() []protos.TuntapDevice {
	h.mu.RLock()
	defer h.mu.RUnlock()

	devices := make([]protos.TuntapDevice, 0, len(h.devices))
	for _, device := range h.devices {
		devices = append(devices, protos.TuntapDevice{Name: device.LinkAttrs.Name, Mode: device.Mode})
	}
	return devices
}

func (h *TuntapHandle) AddTuntap(device *protos.TuntapDevice) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.devices[device.Name]; ok {
		return fmt.Errorf("device %s already exists", device.Name)
	}

	tun := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: device.Name},
		Mode:      device.Mode,
		Flags:     netlink.TUNTAP_NO_PI | netlink.TUNTAP_ONE_QUEUE,
		Queues:    1,
	}
	if err := netlink.LinkAdd(tun); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(tun); err != nil {
		return err
	}
	h.devices[device.Name] = tun
	return nil
}

func (h *TuntapHandle) DelTuntap(device *protos.TuntapDevice) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	t, ok := h.devices[device.Name]
	if !ok {
		return fmt.Errorf("device %s not found", device.Name)
	}
	if err := netlink.LinkDel(t); err != nil {
		return err
	}
	delete(h.devices, device.Name)
	return nil
}

func (h *TuntapHandle) HandlePacket(pkt *fastpkt.Packet) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, tun := range h.devices {
		if tun.Mode == netlink.TUNTAP_MODE_TUN {
			tun.Fds[0].Write(pkt.RxData[pkt.L2Len:])
		} else {
			tun.Fds[0].Write(pkt.RxData)
		}
	}
}
