package spoof

import (
	"encoding/json"
	"sync"

	"github.com/kentik/patricia"
	"github.com/kentik/patricia/generics_tree"
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
	ifaceName    string
	id           uint32
	mu           *sync.RWMutex
	v4RulesIDMap map[protos.SpoofRuleV4]uint32
	v4RetRules   []protos.SpoofRuleV4                      // reuse buffer for return matched rules
	v4DstIPTree  *generics_tree.TreeV4[protos.SpoofRuleV4] // search key is DstIP
}

func NewSpoofHandle(ifaceName string) (handle.RedirectHandle, error) {
	return &SpoofHandle{
		ifaceName:    ifaceName,
		mu:           &sync.RWMutex{},
		v4RulesIDMap: make(map[protos.SpoofRuleV4]uint32),
		v4RetRules:   make([]protos.SpoofRuleV4, 0, 64),
		v4DstIPTree:  generics_tree.NewTreeV4[protos.SpoofRuleV4](),
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
	resp := protos.SpoofResp{Rules: make([]protos.SpoofRule, 0, len(h.v4RulesIDMap))}

	h.mu.RLock()
	for rule, id := range h.v4RulesIDMap {
		resp.Rules = append(resp.Rules, protos.SpoofRule{
			ID:          id,
			SpoofRuleV4: rule,
		})
	}
	h.mu.RUnlock()

	return json.Marshal(resp)
}

func (h *SpoofHandle) handleOpListTypes(*protos.SpoofReq) ([]byte, error) {
	resp := protos.SpoofResp{Rules: []protos.SpoofRule{
		{SpoofRuleV4: protos.SpoofRuleV4{SpoofType: protos.SpoofType_ICMPEchoReply}},
		{SpoofRuleV4: protos.SpoofRuleV4{SpoofType: protos.SpoofType_TCPReset}},
		{SpoofRuleV4: protos.SpoofRuleV4{SpoofType: protos.SpoofType_TCPResetSYN}},
	}}
	return json.Marshal(resp)
}

func (h *SpoofHandle) handleOpAdd(req *protos.SpoofReq) ([]byte, error) {
	for _, rule := range req.Rules {
		l := logrus.WithField("rule", rule.String())

		h.mu.RLock()
		id, ok := h.v4RulesIDMap[rule.SpoofRuleV4]
		h.mu.RUnlock()
		if ok {
			l.WithField("id", id).Debug("Add duplicate spoof rule")
			continue
		}

		h.mu.Lock()
		h.id++
		h.v4RulesIDMap[rule.SpoofRuleV4] = h.id
		h.v4DstIPTree.Add(patricia.NewIPv4Address(rule.SpoofRuleV4.DstIP, uint(rule.SpoofRuleV4.DstIPPrefixLen)), rule.SpoofRuleV4, nil)
		h.mu.Unlock()

		l.WithField("id", h.id).Debug("Add spoof rule")
	}
	return []byte("{}"), nil
}

func (h *SpoofHandle) handleOpDel(req *protos.SpoofReq) ([]byte, error) {
	for _, rule := range req.Rules {
		l := logrus.WithField("rule", rule.String())

		h.mu.RLock()
		id, ok := h.v4RulesIDMap[rule.SpoofRuleV4]
		h.mu.RUnlock()
		if !ok {
			l.Debug("Delete no matched spoof rule")
			continue
		}
		l.WithField("id", id).Debug("Delete spoof rule")

		h.mu.Lock()
		delete(h.v4RulesIDMap, rule.SpoofRuleV4)
		h.v4DstIPTree.Delete(patricia.NewIPv4Address(rule.SpoofRuleV4.DstIP, uint(rule.SpoofRuleV4.DstIPPrefixLen)), func(_, _ protos.SpoofRuleV4) bool { return true }, rule.SpoofRuleV4)
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

func (h *SpoofHandle) handlePacketICMPv4(pkt *fastpkt.Packet) error {
	rxICMP := fastpkt.DataPtrICMP(pkt.RxData, int(pkt.L2Len+pkt.L3Len))
	if rxICMP.Type != ICMPv4TypeEchoRequest {
		return nil
	}

	h.mu.RLock()
	ok, rules := matchByDstIPKey(h.v4DstIPTree, pkt, h.v4RetRules[:0])
	h.mu.RUnlock()
	if !ok || len(rules) == 0 {
		return nil
	}

	found := false
	for _, rule := range rules {
		if rule.SpoofType == protos.SpoofType_ICMPEchoReply {
			if logrus.GetLevel() >= logrus.DebugLevel {
				logrus.WithField("rule", rule.String()).Debug("Matched rule")
			}
			found = true
			break
		}
	}
	if !found {
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
	txIPv4.SetHeaderLen(fastpkt.SizeofIPv4)
	txIPv4.Protocol = rxIPv4.Protocol
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
	h.mu.RLock()
	ok, rules := matchByDstIPKey(h.v4DstIPTree, pkt, h.v4RetRules[:0])
	h.mu.RUnlock()
	if !ok || len(rules) == 0 {
		return nil
	}

	if logrus.GetLevel() >= logrus.DebugLevel {
		logrus.WithField("rules_count", len(rules)).Debug("Matched rules")
		if logrus.GetLevel() >= logrus.TraceLevel {
			for _, rule := range rules {
				logrus.WithField("rule", rule.String()).Trace("Matched rule detail")
			}
		}
	}

	for _, rule := range rules {
		if rule.SpoofType == protos.SpoofType_TCPReset {
			return h.handlePacketTCPReset(pkt)
		} else if rule.SpoofType == protos.SpoofType_TCPResetSYN && fastpkt.DataPtrTCP(pkt.RxData, int(pkt.L2Len+pkt.L3Len)).Flags.Has(fastpkt.TCPFlagSYN) {
			return h.handlePacketTCPReset(pkt)
		}
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
	txIPv4.SetHeaderLen(fastpkt.SizeofIPv4)
	txIPv4.Protocol = rxIPv4.Protocol
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
	txTCP.Flags.Clear(fastpkt.TCPFlagsMask)
	txTCP.Flags.Set(fastpkt.TCPFlagRST)
	txTCP.Flags.Set(fastpkt.TCPFlagACK)
	txTCP.SetHeaderLen(fastpkt.SizeofTCP)

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

func IPv4PrefixToUint32(addr uint32, prefixLen uint) uint32 {
	return addr & (0xFFFFFFFF << (32 - prefixLen))
}

// matchByDstIPKey return true if matched dst ip
func matchByDstIPKey(trie *generics_tree.TreeV4[protos.SpoofRuleV4], pkt *fastpkt.Packet, ret []protos.SpoofRuleV4) (bool, []protos.SpoofRuleV4) {
	dstIP := patricia.NewIPv4Address(pkt.DstIP, 32)
	return trie.FindDeepestTagsWithFilterAppend(ret, dstIP, func(tag protos.SpoofRuleV4) bool {
		if tag.Proto != 0 && tag.Proto != pkt.L4Proto {
			return false
		}
		if tag.SrcPort != 0 && tag.SrcPort != pkt.SrcPort {
			return false
		}
		if tag.DstPort != 0 && tag.DstPort != pkt.DstPort {
			return false
		}
		return IPv4PrefixToUint32(tag.SrcIP, uint(tag.SrcIPPrefixLen)) == IPv4PrefixToUint32(pkt.SrcIP, uint(tag.SrcIPPrefixLen))
	})
}
