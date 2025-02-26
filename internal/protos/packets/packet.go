package packets

import (
	"errors"
	"net"
	"unsafe"

	"github.com/zxhio/xdpass/internal/protos"
	"golang.org/x/sys/unix"
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

	// TCP
	Flags TCPFlags

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
	pkt.Flags = 0
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

	eth := (*EthernetHeader)(unsafe.Pointer(&data[0]))
	ethType := Ntohs(eth.EthernetType)
	off := SizeofEthernetHeader
	pkt.L2Len = uint8(SizeofEthernetHeader)

	if ethType == unix.ETH_P_8021Q {
		if len(data[off:]) < SizeofVLANHeader {
			return ErrPacketTooShort
		}
		vlan := (*VLANHeader)(unsafe.Pointer(&data[off]))
		ethType = Ntohs(vlan.EncapsulatedProto)
		off += SizeofVLANHeader
		pkt.L2Len += uint8(SizeofVLANHeader)
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

	ip := (*IPv4Header)(unsafe.Pointer(&data[0]))
	off := int(ip.VerHdrLen&0x0F) * 4
	pkt.L3Proto = unix.ETH_P_IP
	pkt.SrcIP = Ntohl(ip.SrcIP)
	pkt.DstIP = Ntohl(ip.DstIP)
	pkt.L3Len = uint8(off)

	switch ip.Proto {
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

	tcp := (*TCPHeader)(unsafe.Pointer(&data[0]))
	pkt.L4Proto = unix.IPPROTO_TCP
	pkt.SrcPort = Ntohs(tcp.SrcPort)
	pkt.DstPort = Ntohs(tcp.DstPort)
	pkt.Flags = tcp.Flags
	pkt.L4Len = uint8((tcp.DataOff >> 4) * 4)

	return nil
}

func (pkt *Packet) DecodePacketUDP(data []byte) error {
	if len(data) < 8 {
		return ErrPacketTooShort
	}

	udp := (*UDPHeader)(unsafe.Pointer(&data[0]))
	pkt.L4Proto = unix.IPPROTO_UDP
	pkt.SrcPort = Ntohs(udp.SrcPort)
	pkt.DstPort = Ntohs(udp.DstPort)
	pkt.L4Len = uint8(SizeofUDPHeader)
	return nil
}

func (pkt *Packet) DecodePacketICMP(data []byte) error {
	if len(data) < 8 {
		return ErrPacketTooShort
	}

	pkt.L4Proto = unix.IPPROTO_ICMP
	pkt.SrcPort = 0
	pkt.DstPort = 0
	pkt.L4Len = uint8(SizeofICMPHeader)
	return nil
}

// GetRxEthernetHeader must be called after DecodeFromData
func (pkt *Packet) GetRxEthernetHeader() *EthernetHeader {
	return GetPtrWithType[EthernetHeader](pkt.RxData, 0)
}

// GetRxVLANHeader must be called after DecodeFromData
func (pkt *Packet) GetRxVLANHeader() *VLANHeader {
	if pkt.L2Len < uint8(SizeofEthernetHeader+SizeofVLANHeader) {
		return nil
	}
	return GetPtrWithType[VLANHeader](pkt.RxData, SizeofEthernetHeader)
}

// GetRxIPv4Header must be called after DecodeFromData
func (pkt *Packet) GetRxIPv4Header() *IPv4Header {
	return GetPtrWithType[IPv4Header](pkt.RxData, int(pkt.L2Len))
}

// GetRxIPv6Header must be called after DecodeFromData
func (pkt *Packet) GetRxIPv6Header() *IPv6Header {
	return GetPtrWithType[IPv6Header](pkt.RxData, int(pkt.L2Len))
}

// GetRxTCPHeader must be called after DecodeFromData
func (pkt *Packet) GetRxTCPHeader() *TCPHeader {
	return GetPtrWithType[TCPHeader](pkt.RxData, int(pkt.L2Len+pkt.L3Len))
}

// GetRxUDPHeader must be called after DecodeFromData
func (pkt *Packet) GetRxUDPHeader() *UDPHeader {
	return GetPtrWithType[UDPHeader](pkt.RxData, int(pkt.L2Len+pkt.L3Len))
}

// GetRxICMPv4Header must be called after DecodeFromData
func (pkt *Packet) GetRxICMPv4Header() *ICMPHeader {
	return GetPtrWithType[ICMPHeader](pkt.RxData, int(pkt.L2Len+pkt.L3Len))
}

func GetPtrWithType[T any](data []byte, off int) *T {
	return (*T)(unsafe.Pointer(&data[off]))
}

func NewPacket(data []byte) (*Packet, error) {
	pkt := &Packet{}
	return pkt, pkt.DecodeFromData(data)
}

func Ntohs(v uint16) uint16 { return (v >> 8) | (v << 8) }
func Ntohl(v uint32) uint32 { return (v>>24)&0xff | (v>>8)&0xff00 | (v<<8)&0xff0000 | (v << 24) }
func Htons(v uint16) uint16 { return (v >> 8) | (v << 8) }
func Htonl(v uint32) uint32 { return (v>>24)&0xff | (v>>8)&0xff00 | (v<<8)&0xff0000 | (v << 24) }

func IPv4FromUint32(v uint32) net.IP {
	return net.IPv4(byte(v&0xff000000>>24), byte(v&0xff0000>>16), byte(v&0xff00>>8), byte(v&0xff))
}

func IPv4ToUint32(ip [4]byte) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func (ip *IPv4Header) PseudoHeaderChecksum() uint32 {
	saddr := (*[4]byte)(unsafe.Pointer(&ip.SrcIP))
	daddr := (*[4]byte)(unsafe.Pointer(&ip.DstIP))

	csum := uint32((saddr[0] + saddr[2])) << 8
	csum += uint32(saddr[1] + saddr[3])
	csum += uint32((daddr[0] + daddr[2])) << 8
	csum += uint32(daddr[1] + daddr[3])
	return csum
}
