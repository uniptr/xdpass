package spoof

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"sync"

	"github.com/kentik/patricia"
	"github.com/kentik/patricia/uint32_tree"
	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/protos/packets"
	"github.com/zxhio/xdpass/internal/redirect/handle"
	"golang.org/x/sys/unix"
)

const (
	ICMPv4TypeEchoRequest = 0x8
	ICMPv4TypeEchoReply   = 0x0
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
	resp := protos.SpoofResp{Rules: []protos.SpoofRule{
		{SpoofType: protos.SpoofType_ICMPEchoReply},
		{SpoofType: protos.SpoofType_TCPReset},
		{SpoofType: protos.SpoofType_TCPResetSYN},
	}}
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

func (h *SpoofHandle) HandlePacket(pkt *packets.Packet) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{
			"l3_proto": pkt.L3Proto,
			"l4_proto": pkt.L4Proto,
			"src_ip":   packets.IPv4FromUint32(pkt.SrcIP),
			"dst_ip":   packets.IPv4FromUint32(pkt.DstIP),
			"src_port": pkt.SrcPort,
			"dst_port": pkt.DstPort,
		}).Debug("Handle packet")
	}

	var err error
	switch pkt.L3Proto {
	case unix.ETH_P_IP:
		err = h.handlePacketIPv4(pkt)
	case unix.ETH_P_IPV6:
		err = h.handlePacketIPv6(pkt)
	default:
		return
	}
	if err != nil {
		logrus.WithError(err).Error("Handle packet error")
	}
}

func (h *SpoofHandle) handlePacketIPv4(pkt *packets.Packet) error {
	switch pkt.L4Proto {
	case unix.IPPROTO_ICMP:
		return h.handlePacketICMPv4(pkt)
	case unix.IPPROTO_TCP:
		return h.handlePacketTCP(pkt)
	case unix.IPPROTO_UDP:
		return h.handlePacketUDP(pkt)
	default:
		return packets.ErrPacketInvalidProtocol
	}
}

func (h *SpoofHandle) handlePacketIPv6(*packets.Packet) error {
	// TODO: add ipv6 implement
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

func (h *SpoofHandle) handlePacketICMPv4(pkt *packets.Packet) error {
	var (
		rule protos.SpoofRule
		ok   bool
	)
	h.mu.RLock()
	id := h.getIDByIPAddr(patricia.NewIPv4Address(pkt.SrcIP, 32), patricia.NewIPv4Address(pkt.DstIP, 32))
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

	rxL4ICMP := pkt.GetRxICMPv4Header()
	if rxL4ICMP.Type != ICMPv4TypeEchoRequest || rule.SpoofType != protos.SpoofType_ICMPEchoReply {
		return nil
	}

	pkt.TxData = pkt.TxData[:packets.SizeofEthernetHeader]

	// L2 Ethernet
	rxL2Ether := pkt.GetRxEthernetHeader()
	txL2Ether := packets.GetPtrWithType[packets.EthernetHeader](pkt.TxData, 0)
	txL2Ether.SrcMAC = rxL2Ether.DestMAC
	txL2Ether.DestMAC = rxL2Ether.SrcMAC
	txL2Ether.EthernetType = rxL2Ether.EthernetType
	txL2Len := packets.SizeofEthernetHeader

	// L2 VLAN
	rxL2Vlan := pkt.GetRxVLANHeader()
	if rxL2Vlan != nil {
		pkt.TxData = pkt.TxData[:packets.SizeofVLANHeader+packets.SizeofVLANHeader]
		txL2Vlan := packets.GetPtrWithType[packets.VLANHeader](pkt.TxData, packets.SizeofEthernetHeader)
		txL2Vlan.VLANID = rxL2Vlan.VLANID
		txL2Vlan.EncapsulatedProto = rxL2Vlan.EncapsulatedProto
		txL2Len += packets.SizeofVLANHeader
	}

	// L3 IPv4
	pkt.TxData = pkt.TxData[:txL2Len+packets.SizeofIPv4Header]
	rxL3 := pkt.GetRxIPv4Header()
	txL3 := packets.GetPtrWithType[packets.IPv4Header](pkt.TxData, txL2Len)
	txL3.Proto = rxL3.Proto
	txL3.VerHdrLen = rxL3.VerHdrLen
	txL3.SrcIP = rxL3.DstIP
	txL3.DstIP = rxL3.SrcIP
	txL3.Len = uint16(txL2Len + packets.SizeofIPv4Header)
	txL3.TTL = 78
	txL3.Checksum = 0
	txL3.Checksum = packets.Htons(checksum(pkt.TxData[txL2Len : txL2Len+packets.SizeofIPv4Header]))

	// L4 ICMPv4
	pkt.TxData = pkt.TxData[:txL2Len+packets.SizeofIPv4Header+packets.SizeofICMPHeader]
	txL4ICMP := packets.GetPtrWithType[packets.ICMPHeader](pkt.TxData, int(txL2Len+packets.SizeofIPv4Header))
	txL4ICMP.Type = ICMPv4TypeEchoReply
	txL4ICMP.Code = 0
	txL4ICMP.ID = rxL4ICMP.ID
	txL4ICMP.Seq = rxL4ICMP.Seq
	txL4ICMP.Checksum = 0

	// Payload
	rxL234Len := int(pkt.L2Len + pkt.L3Len + pkt.L4Len)
	pkt.TxData = pkt.TxData[:txL2Len+packets.SizeofIPv4Header+packets.SizeofICMPHeader+len(pkt.RxData)-rxL234Len]
	copy(pkt.TxData[txL2Len+packets.SizeofIPv4Header+packets.SizeofICMPHeader:], pkt.RxData[rxL234Len:])

	// L4 ICMPv4 checksum
	txL4ICMP.Checksum = packets.Htons(tcpipChecksum(pkt.TxData[txL2Len+packets.SizeofIPv4Header:txL2Len+packets.SizeofIPv4Header+packets.SizeofICMPHeader+len(pkt.TxData)-rxL234Len], 0))

	return nil
}

func (h *SpoofHandle) handlePacketTCP(pkt *packets.Packet) error {
	var (
		rule protos.SpoofRule
		ok   bool
	)
	h.mu.RLock()
	id := h.getIDByIPAddrPort(patricia.NewIPv4Address(pkt.SrcIP, 32), patricia.NewIPv4Address(pkt.DstIP, 32), pkt.SrcPort, pkt.DstPort)
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
		return h.handlePacketTCPReset(pkt)
	} else if rule.SpoofType == protos.SpoofType_TCPResetSYN && pkt.GetRxTCPHeader().Flags.Has(packets.TCPFlagSYN) {
		return h.handlePacketTCPReset(pkt)
	}
	return nil
}

func (h *SpoofHandle) handlePacketTCPReset(pkt *packets.Packet) error {
	pkt.TxData = pkt.TxData[:packets.SizeofEthernetHeader]

	// L2 Ethernet
	rxL2Ether := pkt.GetRxEthernetHeader()
	txL2Ether := packets.GetPtrWithType[packets.EthernetHeader](pkt.TxData, 0)
	txL2Ether.SrcMAC = rxL2Ether.DestMAC
	txL2Ether.DestMAC = rxL2Ether.SrcMAC
	txL2Ether.EthernetType = rxL2Ether.EthernetType
	txL2Len := packets.SizeofEthernetHeader

	// L2 VLAN
	rxL2Vlan := pkt.GetRxVLANHeader()
	if rxL2Vlan != nil {
		pkt.TxData = pkt.TxData[:packets.SizeofVLANHeader+packets.SizeofVLANHeader]
		txL2Vlan := packets.GetPtrWithType[packets.VLANHeader](pkt.TxData, packets.SizeofEthernetHeader)
		txL2Vlan.VLANID = rxL2Vlan.VLANID
		txL2Vlan.EncapsulatedProto = rxL2Vlan.EncapsulatedProto
		txL2Len += packets.SizeofVLANHeader
	}

	// L3 IPv4
	pkt.TxData = pkt.TxData[:txL2Len+packets.SizeofIPv4Header]
	rxL3 := pkt.GetRxIPv4Header()
	txL3 := packets.GetPtrWithType[packets.IPv4Header](pkt.TxData, txL2Len)
	txL3.Proto = rxL3.Proto
	txL3.VerHdrLen = rxL3.VerHdrLen
	txL3.SrcIP = rxL3.DstIP
	txL3.DstIP = rxL3.SrcIP
	txL3.Len = packets.Htons(uint16(packets.SizeofIPv4Header + packets.SizeofTCPHeader))
	txL3.TTL = 78
	txL3.Checksum = 0
	txL3.Checksum = packets.Htons(checksum(pkt.TxData[txL2Len : txL2Len+packets.SizeofIPv4Header]))

	// L4 TCP
	pkt.TxData = pkt.TxData[:txL2Len+packets.SizeofIPv4Header+packets.SizeofTCPHeader]
	rxL4TCP := pkt.GetRxTCPHeader()
	txL4TCP := packets.GetPtrWithType[packets.TCPHeader](pkt.TxData, int(txL2Len+packets.SizeofIPv4Header))
	txL4TCP.SrcPort = rxL4TCP.DstPort
	txL4TCP.DstPort = rxL4TCP.SrcPort
	txL4TCP.AckSeq = packets.Htonl(packets.Ntohl(rxL4TCP.Seq) + 1)
	txL4TCP.DataOff = 90
	txL4TCP.Flags.Clear(packets.TCPFlagsMask)
	txL4TCP.Flags.Set(packets.TCPFlagRST)
	txL4TCP.Flags.Set(packets.TCPFlagACK)

	// Checksum
	csum := rxL3.PseudoHeaderChecksum()
	csum += unix.IPPROTO_TCP
	csum += uint32(20) & 0xffff
	csum += uint32(20) >> 16
	txL4TCP.Check = 0
	txL4TCP.Check = packets.Htons(tcpipChecksum(pkt.TxData[txL2Len+packets.SizeofIPv4Header:txL2Len+packets.SizeofIPv4Header+packets.SizeofTCPHeader], csum))

	return nil
}

func (h *SpoofHandle) handlePacketUDP(*packets.Packet) error {
	// TODO: add udp implement
	return nil
}

func checksum(bytes []byte) uint16 {
	// Clear checksum bytes
	bytes[10] = 0
	bytes[11] = 0

	// Compute checksum
	var csum uint32
	for i := 0; i < len(bytes); i += 2 {
		csum += uint32(bytes[i]) << 8
		csum += uint32(bytes[i+1])
	}
	for {
		// Break when sum is less or equals to 0xFFFF
		if csum <= 65535 {
			break
		}
		// Add carry to the sum
		csum = (csum >> 16) + uint32(uint16(csum))
	}
	// Flip all the bits
	return ^uint16(csum)
}

func tcpipChecksum(data []byte, csum uint32) uint16 {
	// to handle odd lengths, we loop to length - 1, incrementing by 2, then
	// handle the last byte specifically by checking against the original
	// length.
	length := len(data) - 1
	for i := 0; i < length; i += 2 {
		// For our test packet, doing this manually is about 25% faster
		// (740 ns vs. 1000ns) than doing it by calling binary.BigEndian.Uint16.
		csum += uint32(data[i]) << 8
		csum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum += uint32(data[length]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}
