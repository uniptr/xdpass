package fastpkt

import (
	"unsafe"

	"github.com/zxhio/xdpass/pkg/netutil"
)

// <linux/ip.h>
//
// struct iphdr {
// #if defined(__LITTLE_ENDIAN_BITFIELD)
//     unsigned int ihl : 4, version : 4;
// #elif defined(__BIG_ENDIAN_BITFIELD)
//     unsigned int version : 4, ihl : 4;
// #else
// #error "Please fix <asm/byteorder.h>"
// #endif
//     __u8 tos;        // Type of Service
//     __be16 tot_len;  // Total Length
//     __be16 id;       // Identification
//     __be16 frag_off; // Fragment Offset and Flags
//     __u8 ttl;        // Time to Live
//     __u8 protocol;   // Protocol (TCP, UDP, etc.)
//     __u16 check;     // Header Checksum
//     __be32 saddr;    // Source IP Address
//     __be32 daddr;    // Destination IP Address
// };

type IPv4 struct {
	VerHdrLen uint8  // 4 bits version, 4 bits header length
	TOS       uint8  // type of service
	Len       uint16 // total length
	ID        uint16 // identification
	FragOff   uint16 // fragment offset
	TTL       uint8  // time to live
	Protocol  uint8  // protocol
	Checksum  uint16 // checksum
	SrcIP     uint32 // source ip
	DstIP     uint32 // destination ip
}

func (ip *IPv4) HeaderLen() int { return int((ip.VerHdrLen & 0x0F) * 4) }

// ComputeChecksum must be called after the header is filled
func (ip *IPv4) ComputeChecksum() uint16 {
	off := ip.HeaderLen()
	data := unsafe.Slice((*byte)(unsafe.Pointer(ip)), off)

	ip.Checksum = 0
	ip.Checksum = netutil.Htons(checksum(data[:off]))
	return ip.Checksum
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

// PseudoChecksum is the checksum of the pseudo header
func (ip *IPv4) PseudoChecksum() uint32 {
	saddr := (*[4]byte)(unsafe.Pointer(&ip.SrcIP))
	daddr := (*[4]byte)(unsafe.Pointer(&ip.DstIP))

	csum := uint32((saddr[0] + saddr[2])) << 8
	csum += uint32(saddr[1] + saddr[3])
	csum += uint32((daddr[0] + daddr[2])) << 8
	csum += uint32(daddr[1] + daddr[3])
	return csum
}
