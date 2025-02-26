package packets

import "unsafe"

// All header is little endian

const (
	SizeofEthernetHeader = int(unsafe.Sizeof(EthernetHeader{}))
	SizeofVLANHeader     = int(unsafe.Sizeof(VLANHeader{}))
	SizeofIPv4Header     = int(unsafe.Sizeof(IPv4Header{}))
	SizeofIPv6Header     = int(unsafe.Sizeof(IPv6Header{}))
	SizeofTCPHeader      = int(unsafe.Sizeof(TCPHeader{}))
	SizeofUDPHeader      = int(unsafe.Sizeof(UDPHeader{}))
	SizeofICMPHeader     = int(unsafe.Sizeof(ICMPHeader{}))
)

// <linux/if_ether.h>
//
//	struct ethhdr {
//	    unsigned char h_dest[6];
//	    unsigned char h_source[6];
//	    __be16 h_proto;
//	};
type EthernetHeader struct {
	DestMAC      [6]byte
	SrcMAC       [6]byte
	EthernetType uint16
}

// <linux/if_vlan.h>
//
//	struct vlan_hdr {
//	    __be16 h_vlan_TCI;
//	    __be16 h_vlan_encapsulated_proto;
//	};
type VLANHeader struct {
	VLANID            uint16
	EncapsulatedProto uint16
}

// <linux/ip.h>
type IPv4Header struct {
	VerHdrLen uint8  // 4 bits version, 4 bits header length
	TOS       uint8  // type of service
	Len       uint16 // total length
	ID        uint16 // identification
	FragOff   uint16 // fragment offset
	TTL       uint8  // time to live
	Proto     uint8  // protocol
	Checksum  uint16 // checksum
	SrcIP     uint32 // source ip
	DstIP     uint32 // destination ip
}

// <linux/ipv6.h>
type IPv6Header struct {
}

// <linux/tcp.h>
type TCPHeader struct {
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	AckSeq  uint32
	DataOff uint8    // 4 bits reserved, 4 bits header length
	Flags   TCPFlags // fin, syn, rst, psh, ack, urg, ece, cwr
	Window  uint16
	Check   uint16
	UrgPtr  uint16
}

// <linux/udp.h>
type UDPHeader struct {
	SrcPort uint16
	DstPort uint16
	Len     uint16
	Check   uint16
}

// <linux/icmp.h>
type ICMPHeader struct {
	Type     uint8
	Code     uint8
	Checksum uint16

	// 4 bytes union {

	// echo struct
	ID  uint16
	Seq uint16

	// gateway
	// Gateway uint32

	// frag struct
	//  Unused uint16
	//  MTU    uint16

	// reserved [4]byte

	// end of union
	// }
}

type TCPFlags uint8

const (
	TCPFlagFIN TCPFlags = 1 << iota
	TCPFlagSYN
	TCPFlagRST
	TCPFlagPSH
	TCPFlagACK
	TCPFlagURG
	TCPFlagECE
	TCPFlagCWR

	TCPFlagsMask = TCPFlagFIN | TCPFlagSYN | TCPFlagRST | TCPFlagPSH | TCPFlagACK | TCPFlagURG | TCPFlagECE | TCPFlagCWR
)

func (flags *TCPFlags) Set(flag TCPFlags) {
	*flags |= flag
}

func (flags *TCPFlags) Has(flag TCPFlags) bool {
	return *flags&flag != 0
}

func (flags *TCPFlags) Clear(flag TCPFlags) {
	*flags &= ^flag
}
