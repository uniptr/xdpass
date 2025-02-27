package fastpkt

import (
	"unsafe"

	"github.com/zxhio/xdpass/pkg/netutil"
	"golang.org/x/sys/unix"
)

// <linux/udp.h>
//
// struct udphdr {
//     __be16 source;
//     __be16 dest;
//     __be16 len;
//     __sum16 check;
// };

type UDP struct {
	SrcPort uint16
	DstPort uint16
	Length  uint16
	Check   uint16
}

func (udp *UDP) ComputeChecksum(ipPseudoChecksum uint32, payloadLen uint16) uint16 {
	udpAndPayloadLen := udp.Length + payloadLen
	data := unsafe.Slice((*byte)(unsafe.Pointer(udp)), udpAndPayloadLen)

	ipPseudoChecksum += unix.IPPROTO_UDP
	ipPseudoChecksum += uint32(udpAndPayloadLen) & 0xffff
	ipPseudoChecksum += uint32(udpAndPayloadLen) >> 16

	udp.Check = 0
	udp.Check = netutil.Htons(tcpipChecksum(data, ipPseudoChecksum))
	return udp.Check
}
