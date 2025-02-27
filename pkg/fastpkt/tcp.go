package fastpkt

import (
	"unsafe"

	"github.com/zxhio/xdpass/pkg/netutil"
	"golang.org/x/sys/unix"
)

// <linux/tcp.h>
//
// struct tcphdr {
// 	__be16	source;
// 	__be16	dest;
// 	__be32	seq;
// 	__be32	ack_seq;
// #if defined(__LITTLE_ENDIAN_BITFIELD)
// 	__u16	res1:4,
// 		doff:4,
// 		fin:1,
// 		syn:1,
// 		rst:1,
// 		psh:1,
// 		ack:1,
// 		urg:1,
// 		ece:1,
// 		cwr:1;
// #elif defined(__BIG_ENDIAN_BITFIELD)
// 	__u16	doff:4,
// 		res1:4,
// 		cwr:1,
// 		ece:1,
// 		urg:1,
// 		ack:1,
// 		psh:1,
// 		rst:1,
// 		syn:1,
// 		fin:1;
// #else
// #error	"Adjust your <asm/byteorder.h> defines"
// #endif
// 	__be16	window;
// 	__sum16	check;
// 	__be16	urg_ptr;
// };

type TCP struct {
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

func (tcp *TCP) HeaderLen() int {
	return int((tcp.DataOff&0xf0)>>4) * 4
}

func (tcp *TCP) SetHeaderLen(headerLen int) {
	tcp.DataOff = (uint8(headerLen/4) << 4) | (tcp.DataOff & 0x0f)
}

func (tcp *TCP) ComputeChecksum(ipPseudoChecksum uint32, payloadLen int) uint16 {
	tcpAndPayloadLen := tcp.HeaderLen() + payloadLen
	data := unsafe.Slice((*byte)(unsafe.Pointer(tcp)), tcpAndPayloadLen)

	ipPseudoChecksum += unix.IPPROTO_TCP
	ipPseudoChecksum += uint32(tcpAndPayloadLen) & 0xffff
	ipPseudoChecksum += uint32(tcpAndPayloadLen) >> 16
	tcp.Check = 0
	tcp.Check = netutil.Htons(tcpipChecksum(data, ipPseudoChecksum))
	return tcp.Check
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

func (flags *TCPFlags) Set(flag TCPFlags)      { *flags |= flag }
func (flags *TCPFlags) Clear(flag TCPFlags)    { *flags &= ^flag }
func (flags *TCPFlags) Has(flag TCPFlags) bool { return *flags&flag != 0 }
