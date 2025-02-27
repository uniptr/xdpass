package netutil

import (
	"net"
)

func Ntohs(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

func Ntohl(v uint32) uint32 {
	return (v>>24)&0xff | (v>>8)&0xff00 | (v<<8)&0xff0000 | (v << 24)
}

func Htons(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

func Htonl(v uint32) uint32 {
	return (v>>24)&0xff | (v>>8)&0xff00 | (v<<8)&0xff0000 | (v << 24)
}

func Uint32ToIPv4(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func IPv4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
