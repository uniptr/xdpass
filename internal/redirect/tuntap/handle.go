package tuntap

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/handle"
)

type TuntapHandle struct {
	mu      *sync.RWMutex
	devices map[string]*netlink.Tuntap
}

func NewTuntapHandle() (handle.RedirectHandle, error) {
	return &TuntapHandle{
		mu:      &sync.RWMutex{},
		devices: make(map[string]*netlink.Tuntap),
	}, nil
}

func (TuntapHandle) RedirectType() protos.RedirectType {
	return protos.RedirectType_Tuntap
}

func (h *TuntapHandle) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, tuntap := range h.devices {
		netlink.LinkDel(tuntap)
	}
	return nil
}

func (h *TuntapHandle) HandleReqData(data []byte) ([]byte, error) {
	var req protos.TuntapReq
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, err
	}

	switch req.Operation {
	case protos.TuntapOperation_List:
		return h.handleOpList()
	case protos.TuntapOperation_Add:
		return h.handleOpAdd(&req)
	case protos.TuntapOperation_Del:
		return h.handleOpDel(&req)
	}
	return nil, fmt.Errorf("invalid operation: %s", req.Operation)
}

func (h *TuntapHandle) handleOpList() ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	resp := protos.TuntapResp{Devices: make([]protos.TuntapDevice, 0, len(h.devices))}
	for _, tun := range h.devices {
		resp.Devices = append(resp.Devices, protos.TuntapDevice{Name: tun.LinkAttrs.Name, Mode: tun.Mode})
	}
	return json.Marshal(resp)
}

func (h *TuntapHandle) handleOpAdd(req *protos.TuntapReq) ([]byte, error) {
	for _, device := range req.Devices {
		h.mu.RLock()
		_, ok := h.devices[device.Name]
		h.mu.RUnlock()
		if ok {
			return nil, fmt.Errorf("device %s already exists", device.Name)
		}

		tun := &netlink.Tuntap{
			LinkAttrs: netlink.LinkAttrs{Name: device.Name},
			Mode:      device.Mode,
			Flags:     netlink.TUNTAP_NO_PI | netlink.TUNTAP_ONE_QUEUE,
			Queues:    1,
		}
		err := netlink.LinkAdd(tun)
		if err != nil {
			return nil, err
		}
		err = netlink.LinkSetUp(tun)
		if err != nil {
			return nil, err
		}
		logrus.WithFields(logrus.Fields{"device": device.Name, "mode": device.Mode}).Info("Add tun device")

		h.mu.Lock()
		h.devices[device.Name] = tun
		h.mu.Unlock()
	}

	return []byte("{}"), nil
}

func (h *TuntapHandle) handleOpDel(req *protos.TuntapReq) ([]byte, error) {
	for _, device := range req.Devices {
		h.mu.RLock()
		t, ok := h.devices[device.Name]
		h.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("device %s not found", device.Name)
		}

		err := netlink.LinkDel(t)
		if err != nil {
			return nil, err
		}

		h.mu.Lock()
		delete(h.devices, device.Name)
		h.mu.Unlock()

		logrus.WithField("device", device.Name).Info("Delete tun device")
	}
	return []byte("{}"), nil
}

func (h *TuntapHandle) HandlePacketData(data *handle.PacketData) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// TODO: support vlan
	for _, tun := range h.devices {
		if tun.Mode == netlink.TUNTAP_MODE_TUN {
			tun.Fds[0].Write(data.Data[14:])
		} else {
			tun.Fds[0].Write(data.Data)
		}
	}
}
