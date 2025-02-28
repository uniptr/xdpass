package fastpkt

import (
	"unsafe"

	"github.com/zxhio/xdpass/pkg/netutil"
)

// <linux/icmp.h>
//
// struct icmphdr {
//     __u8 type;
//     __u8 code;
//     __sum16 checksum;
//     union {
//         struct {
//             __be16 id;
//             __be16 sequence;
//         } echo;
//         __be32 gateway;
//         struct {
//             __be16 mtu;
//             __u8 void;
//         } frag;
//     };
// };

type ICMP struct {
	Type     uint8
	Code     uint8
	Checksum uint16

	// Echo
	ID  uint16
	Seq uint16
}

func (icmp *ICMP) ComputeChecksum(payloadLen uint16) uint16 {
	data := unsafe.Slice((*byte)(unsafe.Pointer(icmp)), SizeofICMP+int(payloadLen))
	icmp.Checksum = 0
	icmp.Checksum = netutil.Htons(tcpipChecksum(data, 0))
	return icmp.Checksum
}
