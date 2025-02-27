package fastpkt

import (
	"unsafe"
)

// DataPtr is a helper function to cast a data type to a pointer
func DataPtr[T any](data []byte, off int) *T {
	return (*T)(unsafe.Pointer(&data[off]))
}

// DataPtrEthernet is a helper function to cast an Ethernet header to a pointer
func DataPtrEthernet(data []byte, off int) *Ethernet {
	return DataPtr[Ethernet](data, off)
}

// DataPtrVLAN is a helper function to cast a VLAN header to a pointer
func DataPtrVLAN(data []byte, off int) *VLAN {
	return DataPtr[VLAN](data, off)
}

// DataPtrIPv4 is a helper function to cast an IPv4 header to a pointer
func DataPtrIPv4(data []byte, off int) *IPv4 {
	return DataPtr[IPv4](data, off)
}

// DataPtrIPv6 is a helper function to cast an IPv6 header to a pointer
func DataPtrIPv6(data []byte, off int) *IPv6 {
	return DataPtr[IPv6](data, off)
}

// DataPtrTCP is a helper function to cast a TCP header to a pointer
func DataPtrTCP(data []byte, off int) *TCP {
	return DataPtr[TCP](data, off)
}

// DataPtrUDP is a helper function to cast a UDP header to a pointer
func DataPtrUDP(data []byte, off int) *UDP {
	return DataPtr[UDP](data, off)
}

// DataPtrICMP is a helper function to cast an ICMP header to a pointer
func DataPtrICMP(data []byte, off int) *ICMP {
	return DataPtr[ICMP](data, off)
}
