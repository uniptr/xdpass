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
	"github.com/zxhio/xdpass/internal/redirect/handle"
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netutil"
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

func (h *SpoofHandle) HandlePacket(pkt *fastpkt.Packet) {
	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{
			"l3_proto": pkt.L3Proto,
			"l4_proto": pkt.L4Proto,
			"src_ip":   netutil.Uint32ToIPv4(pkt.SrcIP),
			"dst_ip":   netutil.Uint32ToIPv4(pkt.DstIP),
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

func (h *SpoofHandle) handlePacketIPv4(pkt *fastpkt.Packet) error {
	switch pkt.L4Proto {
	case unix.IPPROTO_ICMP:
		return h.handlePacketICMPv4(pkt)
	case unix.IPPROTO_TCP:
		return h.handlePacketTCP(pkt)
	case unix.IPPROTO_UDP:
		return h.handlePacketUDP(pkt)
	default:
		return fastpkt.ErrPacketInvalidProtocol
	}
}

func (h *SpoofHandle) handlePacketIPv6(*fastpkt.Packet) error {
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

func (h *SpoofHandle) handlePacketICMPv4(pkt *fastpkt.Packet) error {
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

	rxICMP := fastpkt.DataPtrICMP(pkt.RxData, int(pkt.L2Len+pkt.L3Len))
	if rxICMP.Type != ICMPv4TypeEchoRequest || rule.SpoofType != protos.SpoofType_ICMPEchoReply {
		return nil
	}

	// L2 Ethernet
	rxEther := fastpkt.DataPtrEthernet(pkt.RxData, 0)
	txL2Len := fastpkt.SizeofEthernet

	pkt.TxData = pkt.TxData[:fastpkt.SizeofEthernet]
	txEther := fastpkt.DataPtrEthernet(pkt.TxData, 0)
	txEther.HwSource = rxEther.HwDest
	txEther.HwDest = rxEther.HwSource
	txEther.HwProto = rxEther.HwProto

	// L2 VLAN
	if netutil.Ntohs(rxEther.HwProto) == unix.ETH_P_8021Q {
		rxVLAN := fastpkt.DataPtrVLAN(pkt.RxData, fastpkt.SizeofEthernet)
		pkt.TxData = pkt.TxData[:fastpkt.SizeofVLAN+fastpkt.SizeofVLAN]
		txVLAN := fastpkt.DataPtrVLAN(pkt.TxData, fastpkt.SizeofEthernet)
		txVLAN.ID = rxVLAN.ID
		txVLAN.EncapsulatedProto = rxVLAN.EncapsulatedProto
		txL2Len += fastpkt.SizeofVLAN
	}

	// L3
	rxIPv4 := fastpkt.DataPtrIPv4(pkt.RxData, txL2Len)
	pkt.TxData = pkt.TxData[:txL2Len+fastpkt.SizeofIPv4]

	txIPv4 := fastpkt.DataPtrIPv4(pkt.TxData, txL2Len)
	txIPv4.Protocol = rxIPv4.Protocol
	txIPv4.VerHdrLen = rxIPv4.VerHdrLen
	txIPv4.SrcIP = rxIPv4.DstIP
	txIPv4.DstIP = rxIPv4.SrcIP
	txIPv4.ID = rxIPv4.ID
	txIPv4.TTL = 78

	// L4
	pkt.TxData = pkt.TxData[:txL2Len+fastpkt.SizeofIPv4+fastpkt.SizeofICMP]

	txICMP := fastpkt.DataPtrICMP(pkt.TxData, int(txL2Len+fastpkt.SizeofIPv4))
	txICMP.Type = ICMPv4TypeEchoReply
	txICMP.Code = 0
	txICMP.ID = rxICMP.ID
	txICMP.Seq = rxICMP.Seq

	// Payload
	rxPayloadLen := int(netutil.Ntohs(rxIPv4.Len)) - rxIPv4.HeaderLen() - fastpkt.SizeofICMP
	rxL234Len := int(pkt.L2Len + pkt.L3Len + pkt.L4Len)
	pkt.TxData = pkt.TxData[:txL2Len+fastpkt.SizeofIPv4+fastpkt.SizeofICMP+rxPayloadLen]
	copy(pkt.TxData[txL2Len+fastpkt.SizeofIPv4+fastpkt.SizeofICMP:], pkt.RxData[rxL234Len:rxL234Len+rxPayloadLen])

	// Checksum
	txICMP.ComputeChecksum(rxPayloadLen)
	txIPv4.Len = netutil.Htons(uint16(fastpkt.SizeofIPv4 + fastpkt.SizeofICMP + rxPayloadLen))
	txIPv4.ComputeChecksum()

	return nil
}

func (h *SpoofHandle) handlePacketTCP(pkt *fastpkt.Packet) error {
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
	} else if rule.SpoofType == protos.SpoofType_TCPResetSYN && fastpkt.DataPtrTCP(pkt.RxData, int(pkt.L2Len+pkt.L3Len)).Flags.Has(fastpkt.TCPFlagSYN) {
		return h.handlePacketTCPReset(pkt)
	}
	return nil
}

func (h *SpoofHandle) handlePacketTCPReset(pkt *fastpkt.Packet) error {
	pkt.TxData = pkt.TxData[:fastpkt.SizeofEthernet]

	// L2 Ethernet
	txL2Len := fastpkt.SizeofEthernet
	rxEther := fastpkt.DataPtrEthernet(pkt.RxData, 0)
	txEther := fastpkt.DataPtrEthernet(pkt.TxData, 0)
	txEther.HwSource = rxEther.HwDest
	txEther.HwDest = rxEther.HwSource
	txEther.HwProto = rxEther.HwProto

	// L2 VLAN
	if rxEther.HwProto == unix.ETH_P_8021Q {
		rxVLAN := fastpkt.DataPtrVLAN(pkt.RxData, fastpkt.SizeofEthernet)
		pkt.TxData = pkt.TxData[:fastpkt.SizeofVLAN+fastpkt.SizeofVLAN]
		txVLAN := fastpkt.DataPtrVLAN(pkt.TxData, fastpkt.SizeofEthernet)
		txVLAN.ID = rxVLAN.ID
		txVLAN.EncapsulatedProto = rxVLAN.EncapsulatedProto
		txL2Len += fastpkt.SizeofVLAN
	}

	// L3
	rxIPv4 := fastpkt.DataPtrIPv4(pkt.RxData, txL2Len)
	pkt.TxData = pkt.TxData[:txL2Len+fastpkt.SizeofIPv4]

	txIPv4 := fastpkt.DataPtrIPv4(pkt.TxData, txL2Len)
	txIPv4.Protocol = rxIPv4.Protocol
	txIPv4.VerHdrLen = rxIPv4.VerHdrLen
	txIPv4.SrcIP = rxIPv4.DstIP
	txIPv4.DstIP = rxIPv4.SrcIP
	txIPv4.ID = rxIPv4.ID
	txIPv4.TTL = 78

	// L4
	pkt.TxData = pkt.TxData[:txL2Len+fastpkt.SizeofIPv4+fastpkt.SizeofTCP]

	rxTCP := fastpkt.DataPtrTCP(pkt.RxData, int(txL2Len+fastpkt.SizeofIPv4))
	txTCP := fastpkt.DataPtrTCP(pkt.TxData, int(txL2Len+fastpkt.SizeofIPv4))
	txTCP.SrcPort = rxTCP.DstPort
	txTCP.DstPort = rxTCP.SrcPort
	txTCP.AckSeq = netutil.Htonl(netutil.Ntohl(rxTCP.Seq) + 1)
	txTCP.DataOff = 90
	txTCP.Flags.Clear(fastpkt.TCPFlagsMask)
	txTCP.Flags.Set(fastpkt.TCPFlagRST)
	txTCP.Flags.Set(fastpkt.TCPFlagACK)

	// Checksum
	txTCP.ComputeChecksum(rxIPv4.PseudoChecksum(), 0)
	txIPv4.Len = netutil.Htons(uint16(fastpkt.SizeofIPv4 + fastpkt.SizeofTCP))
	txIPv4.ComputeChecksum()

	return nil
}

func (h *SpoofHandle) handlePacketUDP(*fastpkt.Packet) error {
	// TODO: add udp implement
	return nil
}
