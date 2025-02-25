package spoof

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kentik/patricia"
	"github.com/kentik/patricia/uint32_tree"
	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/handle"
)

type SpoofHandle struct {
	ifaceName string
	id        uint32
	mu        *sync.RWMutex
	rules     map[uint32]protos.SpoofRule
	ruleIDs   map[protos.SpoofRule]uint32
	srcIPTrie *uint32_tree.TreeV4
	dstIPTrie *uint32_tree.TreeV4
}

func NewSpoofHandle(ifaceName string) (handle.RedirectHandle, error) {
	return &SpoofHandle{
		ifaceName: ifaceName,
		mu:        &sync.RWMutex{},
		rules:     make(map[uint32]protos.SpoofRule),
		ruleIDs:   make(map[protos.SpoofRule]uint32),
		srcIPTrie: uint32_tree.NewTreeV4(),
		dstIPTrie: uint32_tree.NewTreeV4(),
	}, nil
}

func (SpoofHandle) RedirectType() protos.RedirectType {
	return protos.RedirectType_Spoof
}

func (h *SpoofHandle) Close() error {
	return nil
}

func (h *SpoofHandle) HandleReqData(client *commands.MessageClient, data []byte) error {
	var req protos.SpoofReq
	err := json.Unmarshal(data, &req)
	if err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}

	switch req.Operation {
	case protos.SpoofOperation_Nop:
		return handle.ResponseRedirectData(client, []byte("{}"))
	case protos.SpoofOperation_List:
		data, err = h.handleOpList(&req)
	case protos.SpoofOperation_ListTypes:
		data, err = h.handleOpListTypes(&req)
	case protos.SpoofOperation_Add:
		data, err = h.handleOpAdd(&req)
	case protos.SpoofOperation_Del:
		data, err = h.handleOpDel(&req)
	}
	if err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}
	return handle.ResponseRedirectData(client, data)
}

func (h *SpoofHandle) handleOpList(*protos.SpoofReq) ([]byte, error) {
	resp := protos.SpoofResp{Rules: make([]protos.SpoofRule, 0, len(h.rules))}

	h.mu.RLock()
	for _, rule := range h.rules {
		resp.Rules = append(resp.Rules, rule)
	}
	h.mu.RUnlock()

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
		l := logrus.WithFields(logrus.Fields{
			"sip_lpm":  rule.SrcIPAddrLPM,
			"dip_lpm":  rule.DstIPAddrLPM,
			"src_port": rule.SrcPort,
			"dst_port": rule.DstPort,
			"proto":    rule.Proto,
			"type":     rule.SpoofType,
		})

		h.mu.RLock()
		_, ok := h.ruleIDs[rule]
		h.mu.RUnlock()
		if ok {
			l.Debug("Add duplicate spoof rule")
			continue
		}

		h.mu.Lock()
		h.id++
		h.ruleIDs[rule] = h.id
		rule.ID = h.id
		h.rules[h.id] = rule
		h.srcIPTrie.Add(rule.SrcIPAddrLPM.To4(), h.id, nil)
		h.dstIPTrie.Add(rule.DstIPAddrLPM.To4(), h.id, nil)
		h.mu.Unlock()

		l.WithField("id", h.id).Debug("Add spoof rule")
	}
	return []byte("{}"), nil
}

func (h *SpoofHandle) handleOpDel(req *protos.SpoofReq) ([]byte, error) {
	for _, rule := range req.Rules {
		l := logrus.WithFields(logrus.Fields{
			"sip_lpm":  rule.SrcIPAddrLPM,
			"dip_lpm":  rule.DstIPAddrLPM,
			"src_port": rule.SrcPort,
			"dst_port": rule.DstPort,
			"proto":    rule.Proto,
			"type":     rule.SpoofType,
		})

		h.mu.RLock()
		id, ok := h.ruleIDs[rule]
		h.mu.RUnlock()
		if !ok {
			l.Debug("Delete no matched spoof rule")
			continue
		}
		l.WithField("id", rule.ID).Debug("Delete spoof rule")

		h.mu.Lock()
		delete(h.rules, id)
		delete(h.ruleIDs, rule)
		h.srcIPTrie.Delete(rule.SrcIPAddrLPM.To4(), func(_, _ uint32) bool { return true }, id)
		h.dstIPTrie.Delete(rule.DstIPAddrLPM.To4(), func(_, _ uint32) bool { return true }, id)
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
	case layers.IPProtocolTCP:
		return h.handlePacketTCP(data, eth, &ip)
	}

	return nil
}

func (h *SpoofHandle) getIDByIP(sip, dip net.IP) uint32 {
	return h.getIDByIPAddr(
		patricia.NewIPv4Address(binary.BigEndian.Uint32(sip), 32),
		patricia.NewIPv4Address(binary.BigEndian.Uint32(dip), 32),
	)
}

func (h *SpoofHandle) getIDByIPAddr(sip, dip patricia.IPv4Address) uint32 {
	ok, sIDList := h.srcIPTrie.FindDeepestTags(sip)
	if !ok {
		return 0
	}
	ok, dIDList := h.dstIPTrie.FindDeepestTags(dip)
	if !ok {
		return 0
	}
	if logrus.GetLevel() == logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{
			"sip":   sip,
			"dip":   dip,
			"slist": sIDList,
			"dlist": dIDList,
		}).Debug("Find deepest ip lpm")
	}

	for _, sID := range sIDList {
		for _, dID := range dIDList {
			if sID == dID {
				return sID
			}
		}
	}
	return 0
}

func (h *SpoofHandle) getIDByIPAddrPort(sip, dip patricia.IPv4Address, sport, dport uint16) uint32 {
	ok, sIDList := h.srcIPTrie.FindDeepestTags(sip)
	if !ok {
		return 0
	}
	ok, dIDList := h.dstIPTrie.FindDeepestTags(dip)
	if !ok {
		return 0
	}

	for _, sID := range sIDList {
		for _, dID := range dIDList {
			if sID == dID {
				if (h.rules[sID].SrcPort == 0 || h.rules[sID].SrcPort == sport) &&
					(h.rules[dID].DstPort == 0 || h.rules[dID].DstPort == dport) {
					return sID
				}
			}
		}
	}
	return 0
}

func (h *SpoofHandle) handlePacketICMPv4(data *handle.PacketData, eth *layers.Ethernet, ip *layers.IPv4) error {
	var icmpv4 layers.ICMPv4
	err := icmpv4.DecodeFromBytes(ip.Payload, gopacket.NilDecodeFeedback)
	if err != nil {
		return err
	}

	var (
		rule protos.SpoofRule
		ok   bool
	)
	h.mu.RLock()
	id := h.getIDByIP(ip.SrcIP, ip.DstIP)
	if id != 0 {
		rule, ok = h.rules[id]
	}
	h.mu.RUnlock()
	if !ok {
		return nil
	}
	if logrus.GetLevel() == logrus.DebugLevel {
		logrus.WithField("id", id).Debug("Matched rule")
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

func (h *SpoofHandle) handlePacketTCP(data *handle.PacketData, eth *layers.Ethernet, ip *layers.IPv4) error {
	var tcp layers.TCP
	err := tcp.DecodeFromBytes(ip.Payload, gopacket.NilDecodeFeedback)
	if err != nil {
		return err
	}

	var (
		rule protos.SpoofRule
		ok   bool
	)
	h.mu.RLock()
	id := h.getIDByIPAddrPort(
		patricia.NewIPv4Address(binary.BigEndian.Uint32(ip.SrcIP), 32),
		patricia.NewIPv4Address(binary.BigEndian.Uint32(ip.DstIP), 32),
		uint16(tcp.SrcPort),
		uint16(tcp.DstPort),
	)
	if id != 0 {
		rule, ok = h.rules[id]
	}
	h.mu.RUnlock()
	if !ok {
		return nil
	}
	if logrus.GetLevel() == logrus.DebugLevel {
		logrus.WithField("id", id).Debug("Matched rule")
	}

	if rule.SpoofType == protos.SpoofType_TCPReset {
		return h.handlePacketTCPReset(data, eth, ip, &tcp)
	} else if rule.SpoofType == protos.SpoofType_TCPResetSYN && tcp.SYN {
		return h.handlePacketTCPReset(data, eth, ip, &tcp)
	}
	return nil
}

func (h *SpoofHandle) handlePacketTCPReset(data *handle.PacketData, eth *layers.Ethernet, ip *layers.IPv4, tcp *layers.TCP) error {
	l2 := *eth
	l2.SrcMAC = eth.DstMAC
	l2.DstMAC = eth.SrcMAC
	l2.EthernetType = eth.EthernetType

	l3 := *ip
	l3.SrcIP = ip.DstIP
	l3.DstIP = ip.SrcIP
	l3.TTL = 78

	l4 := layers.TCP{
		SrcPort: tcp.DstPort,
		DstPort: tcp.SrcPort,
		Ack:     tcp.Seq + 1,
		RST:     true,
		ACK:     true,
	}
	l4.SetNetworkLayerForChecksum(&l3)

	b := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &l2, &l3, &l4, gopacket.Payload(l4.Payload))
	if err != nil {
		return err
	}

	copy(data.Data, b.Bytes())
	data.Len = len(b.Bytes())
	return nil
}
