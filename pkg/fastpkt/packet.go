package fastpkt

import (
	"errors"
	"unsafe"

	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/netutil"
	"golang.org/x/sys/unix"
)

const (
	SizeofEthernet = int(unsafe.Sizeof(Ethernet{})) // sizeof(struct ethhdr)
	SizeofVLAN     = int(unsafe.Sizeof(VLAN{}))     // sizeof(struct vlan_hdr)
	SizeofIPv4     = int(unsafe.Sizeof(IPv4{}))     // sizeof(struct iphdr)
	SizeofIPv6     = int(unsafe.Sizeof(IPv6{}))     // sizeof(struct ipv6hdr)
	SizeofTCP      = int(unsafe.Sizeof(TCP{}))      // sizeof(struct tcphdr)
	SizeofUDP      = int(unsafe.Sizeof(UDP{}))      // sizeof(struct udphdr)
	SizeofICMP     = int(unsafe.Sizeof(ICMP{}))     // sizeof(struct icmphdr)
)

var (
	ErrPacketTooShort            = errors.New("packet too short")
	ErrPacketInvalidEthernetType = errors.New("invalid ethernet type")
	ErrPacketInvalidProtocol     = errors.New("invalid protocol")
)

type Packet struct {
	L3Proto uint16
	L4Proto uint16

	// L3
	SrcIP uint32
	DstIP uint32

	// L4
	SrcPort uint16
	DstPort uint16

	L2Len uint8
	L3Len uint8
	L4Len uint8

	RxData []byte // Raw data received from the network (read only)
	TxData []byte // Raw data to be sent to the network
}

func (pkt *Packet) Clear() {
	pkt.L3Proto = 0
	pkt.L4Proto = 0
	pkt.SrcIP = 0
	pkt.DstIP = 0
	pkt.SrcPort = 0
	pkt.DstPort = 0
	pkt.L2Len = 0
	pkt.L3Len = 0
	pkt.L4Len = 0
	pkt.RxData = nil
	pkt.TxData = nil
}

func (pkt *Packet) DecodeFromData(data []byte) error {
	if len(data) < 14 {
		return ErrPacketTooShort
	}
	pkt.RxData = data

	eth := (*Ethernet)(unsafe.Pointer(&data[0]))
	ethType := netutil.Ntohs(eth.HwProto)
	off := SizeofEthernet
	pkt.L2Len = uint8(SizeofEthernet)

	if ethType == unix.ETH_P_8021Q {
		if len(data[off:]) < SizeofVLAN {
			return ErrPacketTooShort
		}
		vlan := (*VLAN)(unsafe.Pointer(&data[off]))
		ethType = netutil.Ntohs(vlan.EncapsulatedProto)
		off += SizeofVLAN
		pkt.L2Len += uint8(SizeofVLAN)
	}

	switch ethType {
	case unix.ETH_P_IP:
		return pkt.DecodePacketIPv4(data[off:])
	case unix.ETH_P_IPV6:
		return pkt.DecodePacketIPv6(data[off:])
	default:
		return ErrPacketInvalidEthernetType
	}
}

func (pkt *Packet) DecodePacketIPv4(data []byte) error {
	if len(data) < 20 {
		return ErrPacketTooShort
	}

	ip := (*IPv4)(unsafe.Pointer(&data[0]))
	off := ip.HeaderLen()
	pkt.L3Proto = unix.ETH_P_IP
	pkt.SrcIP = netutil.Ntohl(ip.SrcIP)
	pkt.DstIP = netutil.Ntohl(ip.DstIP)
	pkt.L3Len = uint8(off)

	switch ip.Protocol {
	case unix.IPPROTO_TCP:
		return pkt.DecodePacketTCP(data[off:])
	case unix.IPPROTO_UDP:
		return pkt.DecodePacketUDP(data[off:])
	case unix.IPPROTO_ICMP:
		return pkt.DecodePacketICMP(data[off:])
	default:
		return ErrPacketInvalidProtocol
	}
}

// TODO: implement
func (pkt *Packet) DecodePacketIPv6([]byte) error {
	return protos.ErrNotImpl
}

func (pkt *Packet) DecodePacketTCP(data []byte) error {
	if len(data) < 20 {
		return ErrPacketTooShort
	}

	tcp := (*TCP)(unsafe.Pointer(&data[0]))
	pkt.L4Proto = unix.IPPROTO_TCP
	pkt.SrcPort = netutil.Ntohs(tcp.SrcPort)
	pkt.DstPort = netutil.Ntohs(tcp.DstPort)
	pkt.L4Len = uint8(tcp.HeaderLen())

	return nil
}

func (pkt *Packet) DecodePacketUDP(data []byte) error {
	if len(data) < 8 {
		return ErrPacketTooShort
	}

	udp := (*UDP)(unsafe.Pointer(&data[0]))
	pkt.L4Proto = unix.IPPROTO_UDP
	pkt.SrcPort = netutil.Ntohs(udp.SrcPort)
	pkt.DstPort = netutil.Ntohs(udp.DstPort)
	pkt.L4Len = uint8(SizeofUDP)
	return nil
}

func (pkt *Packet) DecodePacketICMP(data []byte) error {
	if len(data) < 8 {
		return ErrPacketTooShort
	}

	pkt.L4Proto = unix.IPPROTO_ICMP
	pkt.SrcPort = 0
	pkt.DstPort = 0
	pkt.L4Len = uint8(SizeofICMP)
	return nil
}

func NewPacket(data []byte) (*Packet, error) {
	pkt := &Packet{}
	return pkt, pkt.DecodeFromData(data)
}
