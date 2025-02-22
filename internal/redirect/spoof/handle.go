package spoof

import (
	"encoding/json"
	"net/netip"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/handle"
)

type addrKey struct {
	Source      protos.AddrPort
	Destination protos.AddrPort
}

type SpoofHandle struct {
	ifaceName string
	mu        *sync.RWMutex // TODO: lock free
	rules     map[addrKey]protos.SpoofRule
}

func NewSpoofHandle(ifaceName string) (handle.RedirectHandle, error) {
	return &SpoofHandle{
		ifaceName: ifaceName,
		mu:        &sync.RWMutex{},
		rules:     make(map[addrKey]protos.SpoofRule),
	}, nil
}

func (SpoofHandle) RedirectType() protos.RedirectType {
	return protos.RedirectType_Spoof
}

func (h *SpoofHandle) Close() error {
	return nil
}

func (h *SpoofHandle) HandleReqData(data []byte) ([]byte, error) {
	var req protos.SpoofReq
	err := json.Unmarshal(data, &req)
	if err != nil {
		return nil, err
	}

	switch req.Operation {
	case protos.SpoofOperation_Nop:
		return []byte("{}"), nil
	case protos.SpoofOperation_List:
		return h.handleOpList(&req)
	case protos.SpoofOperation_ListTypes:
		return h.handleOpListTypes(&req)
	case protos.SpoofOperation_Add:
		return h.handleOpAdd(&req)
	case protos.SpoofOperation_Del:
		return h.handleOpDel(&req)
	}

	return nil, protos.ErrNotImpl
}

func (h *SpoofHandle) handleOpList(*protos.SpoofReq) ([]byte, error) {
	var resp protos.SpoofResp
	for _, rule := range h.rules {
		resp.Rules = append(resp.Rules, rule)
	}
	return json.Marshal(resp)
}

func (h *SpoofHandle) handleOpListTypes(*protos.SpoofReq) ([]byte, error) {
	resp := protos.SpoofResp{Rules: []protos.SpoofRule{{
		SpoofType: protos.SpoofType_ICMPEchoReply,
	}}}
	return json.Marshal(resp)
}

func (h *SpoofHandle) handleOpAdd(req *protos.SpoofReq) ([]byte, error) {
	for _, rule := range req.Rules {
		logrus.WithFields(logrus.Fields{
			"source": rule.Source,
			"dest":   rule.Destination,
			"type":   rule.SpoofType,
			"iface":  rule.Interface,
		}).Debug("Add spoof rule")

		h.mu.Lock()
		h.rules[addrKey{Source: rule.Source, Destination: rule.Destination}] = rule
		h.mu.Unlock()
	}
	return []byte("{}"), nil
}

func (h *SpoofHandle) handleOpDel(req *protos.SpoofReq) ([]byte, error) {
	for _, rule := range req.Rules {
		logrus.WithFields(logrus.Fields{
			"source": rule.Source,
			"dest":   rule.Destination,
		}).Debug("Delete spoof rule")

		h.mu.Lock()
		delete(h.rules, addrKey{Source: rule.Source, Destination: rule.Destination})
		h.mu.Unlock()
	}
	return []byte("{}"), nil
}

func (h *SpoofHandle) HandlePacketData(data *handle.PacketData) {
	data.Len = 0

	var eth layers.Ethernet
	err := eth.DecodeFromBytes(data.Data, gopacket.NilDecodeFeedback)
	if err != nil {
		return
	}

	switch eth.EthernetType {
	case layers.EthernetTypeIPv4:
		err = h.handlePacketIPv4(data, &eth)
	}

	if err != nil {
		logrus.WithError(err).Error("Handle packet error")
	}
}

func (h *SpoofHandle) handlePacketIPv4(data *handle.PacketData, eth *layers.Ethernet) error {
	var ip layers.IPv4
	err := ip.DecodeFromBytes(eth.Payload, gopacket.NilDecodeFeedback)
	if err != nil {
		return err
	}

	switch ip.Protocol {
	case layers.IPProtocolICMPv4:
		return h.handlePacketICMPv4(data, eth, &ip)
	}

	return nil
}

func (h *SpoofHandle) handlePacketICMPv4(data *handle.PacketData, eth *layers.Ethernet, ip *layers.IPv4) error {
	src := protos.AddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.SrcIP)), 0))
	dst := protos.AddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip.DstIP)), 0))

	h.mu.RLock()
	rule, ok := h.rules[addrKey{Source: src, Destination: dst}]
	h.mu.RUnlock()
	if !ok {
		return nil
	}

	var icmpv4 layers.ICMPv4
	err := icmpv4.DecodeFromBytes(ip.Payload, gopacket.NilDecodeFeedback)
	if err != nil {
		return err
	}

	if icmpv4.TypeCode.Type() != layers.ICMPv4TypeEchoRequest || rule.SpoofType != protos.SpoofType_ICMPEchoReply {
		return nil
	}

	l2 := *eth
	l2.SrcMAC = eth.DstMAC
	l2.DstMAC = eth.SrcMAC
	l2.EthernetType = eth.EthernetType

	l3 := *ip
	l3.SrcIP = ip.DstIP
	l3.DstIP = ip.SrcIP

	l4 := icmpv4
	l4.TypeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, icmpv4.TypeCode.Code())

	b := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &l2, &l3, &l4, gopacket.Payload(l4.Payload))
	if err != nil {
		return err
	}

	copy(data.Data, b.Bytes())
	data.Len = len(b.Bytes())
	return nil
}
