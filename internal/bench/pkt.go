package bench

import (
	"encoding/hex"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type layerOptEthernet struct {
	SrcMACStr string
	DstMACStr string
	VlanId    uint16
}

type layerOptIPv4 struct {
	SrcIPStr string
	DstIPStr string
}

type layerOptICMPv4 struct {
	Id  uint16
	Seq uint16
}

type layerOptTCP struct {
	SYN        bool
	ACK        bool
	PSH        bool
	RST        bool
	FIN        bool
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Payload    string
	PayloadHex string
}

type layerOptUDP struct {
	SrcPort     uint16
	DstPort     uint16
	Payload     string
	PayloadHex  string
	PayloadHex2 []byte
}

type layerOpt struct {
	layerOptEthernet
	layerOptIPv4
	icmp4 layerOptICMPv4
	tcp   layerOptTCP
	udp   layerOptUDP
}

type l4DMaker interface {
	MakeLayer(*layerOpt, *layers.IPv4) gopacket.SerializableLayer
	MakePayload(*layerOpt) (gopacket.Payload, error)
}

type l4MakerICMPv4 struct{}

func (l4MakerICMPv4) MakeLayer(opt *layerOpt, ipv4 *layers.IPv4) gopacket.SerializableLayer {
	ipv4.Protocol = layers.IPProtocolICMPv4
	return &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       valueOr(opt.icmp4.Id, 12345),
		Seq:      valueOr(opt.icmp4.Seq, 12345),
	}
}

func (l4MakerICMPv4) MakePayload(_ *layerOpt) (gopacket.Payload, error) {
	return gopacket.Payload{
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	}, nil
}

type l4MakerTCP struct{}

func (l4MakerTCP) MakeLayer(opt *layerOpt, ipv4 *layers.IPv4) gopacket.SerializableLayer {
	ipv4.Protocol = layers.IPProtocolTCP
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(valueOr(opt.tcp.SrcPort, 54321)),
		DstPort: layers.TCPPort(valueOr(opt.tcp.SrcPort, 54321)),
		Seq:     valueOr(opt.tcp.Seq, 12345),
		SYN:     opt.tcp.SYN,
		ACK:     opt.tcp.ACK,
		PSH:     opt.tcp.PSH,
		RST:     opt.tcp.RST,
		FIN:     opt.tcp.FIN,
	}
	tcp.SetNetworkLayerForChecksum(ipv4)
	return tcp
}

func (l4MakerTCP) MakePayload(opt *layerOpt) (gopacket.Payload, error) {
	if len(opt.tcp.Payload) == 0 && len(opt.tcp.PayloadHex) != 0 {
		data, err := hex.DecodeString(opt.tcp.PayloadHex)
		if err != nil {
			return nil, errors.Wrap(err, "hex.Decode")
		}
		return gopacket.Payload(data[:min(len(data), 1400)]), nil
	}
	return gopacket.Payload(opt.tcp.Payload[:min(len(opt.tcp.Payload), 1400)]), nil
}

type l4MakerUDP struct{}

func (l4MakerUDP) MakeLayer(opt *layerOpt, ipv4 *layers.IPv4) gopacket.SerializableLayer {
	ipv4.Protocol = layers.IPProtocolUDP
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(valueOr(opt.udp.SrcPort, 54321)),
		DstPort: layers.UDPPort(valueOr(opt.udp.SrcPort, 54321)),
	}
	udp.SetNetworkLayerForChecksum(ipv4)
	return udp
}

func (l4MakerUDP) MakePayload(opt *layerOpt) (gopacket.Payload, error) {
	if len(opt.udp.Payload) == 0 && len(opt.udp.PayloadHex) != 0 {
		data, err := hex.DecodeString(opt.udp.PayloadHex)
		if err != nil {
			return nil, errors.Wrap(err, "hex.Decode")
		}
		return gopacket.Payload(data[:min(len(data), 1400)]), nil
	}
	return gopacket.Payload(opt.udp.Payload[:min(len(opt.udp.Payload), 1400)]), nil
}

func makePacketData(ifaceName string, opt *layerOpt, l4Maker l4DMaker) ([]byte, error) {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, errors.Wrap(err, "netlink.LinkByName")
	}
	logrus.WithFields(logrus.Fields{"name": link.Attrs().Name, "index": link.Attrs().Index, "hwaddr": link.Attrs().HardwareAddr}).Debug("Found link")

	srcIP, dstIP, err := getIPPair(link, &opt.layerOptIPv4)
	if err != nil {
		return nil, err
	}
	logrus.WithFields(logrus.Fields{"src_ip": srcIP, "dst_ip": dstIP}).Debug("Found ip address")

	srcMAC, dstMAC, err := getMACPair(link, &opt.layerOptEthernet, dstIP)
	if err != nil {
		return nil, err
	}
	logrus.WithFields(logrus.Fields{"src_mac": srcMAC, "dst_mac": dstMAC}).Debug("Found mac address")

	var packetLayers []gopacket.SerializableLayer
	if opt.VlanId != 0 {
		packetLayers = append(packetLayers,
			&layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeDot1Q},
			&layers.Dot1Q{VLANIdentifier: opt.VlanId, Type: layers.EthernetTypeIPv4},
		)
	} else {
		packetLayers = append(packetLayers, &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4})
	}

	ipv4 := layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: srcIP, DstIP: dstIP}
	l4 := l4Maker.MakeLayer(opt, &ipv4)
	payload, err := l4Maker.MakePayload(opt)
	if err != nil {
		return nil, err
	}
	packetLayers = append(packetLayers, &ipv4, l4, payload)

	b := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, packetLayers...)
	if err != nil {
		return nil, errors.Wrap(err, "gopacket.SerializeLayers")
	}
	return b.Bytes(), nil
}

func getIPPair(link netlink.Link, opt *layerOptIPv4) (net.IP, net.IP, error) {
	var srcIP net.IP
	if opt.SrcIPStr != "" {
		srcIP = net.ParseIP(opt.SrcIPStr)
	} else {
		list, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return nil, nil, errors.Wrap(err, "netlink.AddrList")
		}
		if len(list) == 0 {
			return nil, nil, errors.Errorf("link no such ipv4 address")
		}
		srcIP = list[0].IP
	}
	if srcIP == nil {
		return nil, nil, errors.Errorf("invalid src ip: %s", opt.SrcIPStr)
	}

	dstIP := net.ParseIP(opt.DstIPStr)
	if dstIP == nil {
		return nil, nil, errors.Errorf("invalid dst ip: %s", dstIP)
	}
	return srcIP, dstIP, nil
}

func getMACPair(link netlink.Link, opt *layerOptEthernet, dstIP net.IP) (net.HardwareAddr, net.HardwareAddr, error) {
	var (
		srcMAC net.HardwareAddr
		err    error
	)

	if opt.SrcMACStr != "" {
		srcMAC, err = net.ParseMAC(opt.SrcMACStr)
		if err != nil {
			return nil, nil, errors.Wrap(err, "net.ParseMAC")
		}
	} else {
		srcMAC = link.Attrs().HardwareAddr
		if srcMAC == nil {
			srcMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}
		}
	}

	dstMAC, err := getDstMAC(link, opt.DstMACStr, dstIP)
	if err != nil {
		return nil, nil, err
	}
	return srcMAC, dstMAC, nil
}

func getDstMAC(link netlink.Link, dstMacStr string, dstIP net.IP) (net.HardwareAddr, error) {
	if dstMacStr != "" {
		mac, err := net.ParseMAC(dstMacStr)
		return mac, errors.Wrap(err, "net.ParseMAC")
	}

	// Find in host link
	list, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, errors.Wrap(err, "netlink.AddrList")
	}
	for _, addr := range list {
		if addr.IP.Equal(dstIP) {
			if link.Attrs().HardwareAddr == nil {
				return net.HardwareAddr{0, 0, 0, 0, 0, 0}, nil
			}
			return link.Attrs().HardwareAddr, nil
		}
	}

	// Find in same subnet by neigh
	neighList, err := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
	if err != nil {
		return nil, errors.Wrap(err, "netlink.NeighList")
	}
	for _, neigh := range neighList {
		if neigh.IP.Equal(dstIP) {
			return neigh.HardwareAddr, nil
		}
	}

	// Find in diff subnet by gatway
	routeList, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, errors.Wrap(err, "netlink.RouteList")
	}
	for _, neigh := range neighList {
		for _, route := range routeList {
			if neigh.IP.Equal(route.Gw) {
				return neigh.HardwareAddr, nil
			}
		}
	}

	return nil, errors.Errorf("no such dst mac for dst ip %s", dstIP)
}

func valueOr[T comparable](v T, def T) T {
	var vv T
	if vv == v {
		return def
	}
	return v
}
