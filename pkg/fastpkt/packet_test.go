package fastpkt

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/zxhio/xdpass/pkg/netutil"
	"golang.org/x/sys/unix"
)

var (
	testLayerEth = layers.Ethernet{
		DstMAC:       net.HardwareAddr{22, 70, 177, 58, 175, 3},
		SrcMAC:       net.HardwareAddr{86, 102, 96, 15, 235, 58},
		EthernetType: layers.EthernetTypeIPv4,
	}

	testLayerIPv4 = layers.IPv4{
		Version: 4,
		SrcIP:   net.IPv4(172, 16, 23, 2),
		DstIP:   net.IPv4(172, 16, 23, 1),
	}
)

func serialize(layers ...gopacket.SerializableLayer) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts, layers...)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func serializeAndDecode(layers ...gopacket.SerializableLayer) (*Packet, error) {
	buf, err := serialize(layers...)
	if err != nil {
		return nil, err
	}
	return NewPacket(buf)
}

func TestDecodePacketInvalid(t *testing.T) {
	_, err := NewPacket([]byte{1, 2, 3})
	assert.Error(t, err)
}

func TestDecodePacketVLAN(t *testing.T) {
	testLayerEth.EthernetType = layers.EthernetTypeDot1Q
	vlan := layers.Dot1Q{VLANIdentifier: 10, Type: layers.EthernetTypeIPv4}
	testLayerIPv4.Protocol = layers.IPProtocolICMPv4
	icmp := layers.ICMPv4{TypeCode: layers.ICMPv4TypeEchoRequest}

	pkt, err := serializeAndDecode(&testLayerEth, &vlan, &testLayerIPv4, &icmp)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, uint16(unix.ETH_P_IP), pkt.L3Proto)
	assert.Equal(t, uint16(unix.IPPROTO_ICMP), pkt.L4Proto)
	assert.Equal(t, true, netutil.Uint32ToIPv4(pkt.SrcIP).Equal(testLayerIPv4.SrcIP.To4()))
	assert.Equal(t, true, netutil.Uint32ToIPv4(pkt.DstIP).Equal(testLayerIPv4.DstIP.To4()))
	assert.Equal(t, uint16(0), pkt.SrcPort)
	assert.Equal(t, uint16(0), pkt.DstPort)
	assert.Equal(t, uint8(SizeofEthernet+SizeofVLAN), pkt.L2Len)
	assert.Equal(t, uint8(SizeofIPv4), pkt.L3Len)
	assert.Equal(t, uint8(SizeofICMP), pkt.L4Len)
}

func TestDecodePacketTCP(t *testing.T) {
	testLayerEth.EthernetType = layers.EthernetTypeIPv4
	testLayerIPv4.Protocol = layers.IPProtocolTCP
	tcp := layers.TCP{SrcPort: 54213, DstPort: 80}
	tcp.Options = append(tcp.Options, layers.TCPOption{
		OptionType: layers.TCPOptionKindMSS,
		OptionData: []byte{5, 0, 0, 0},
	})
	tcp.SetNetworkLayerForChecksum(&testLayerIPv4)

	pkt, err := serializeAndDecode(&testLayerEth, &testLayerIPv4, &tcp)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, uint16(unix.ETH_P_IP), pkt.L3Proto)
	assert.Equal(t, uint16(unix.IPPROTO_TCP), pkt.L4Proto)
	assert.Equal(t, uint16(54213), pkt.SrcPort)
	assert.Equal(t, uint16(80), pkt.DstPort)
	assert.Equal(t, uint8(SizeofTCP+8), pkt.L4Len)
}

func TestDecodePacketUDP(t *testing.T) {
	testLayerEth.EthernetType = layers.EthernetTypeIPv4
	testLayerIPv4.Protocol = layers.IPProtocolUDP
	udp := layers.UDP{SrcPort: 12345, DstPort: 8080}
	udp.SetNetworkLayerForChecksum(&testLayerIPv4)

	pkt, err := serializeAndDecode(&testLayerEth, &testLayerIPv4, &udp)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint16(unix.ETH_P_IP), pkt.L3Proto)
	assert.Equal(t, uint16(unix.IPPROTO_UDP), pkt.L4Proto)
	assert.Equal(t, uint16(12345), pkt.SrcPort)
	assert.Equal(t, uint16(8080), pkt.DstPort)
	assert.Equal(t, uint8(SizeofUDP), pkt.L4Len)
}

func TestDecodePacketICMP(t *testing.T) {
	testLayerEth.EthernetType = layers.EthernetTypeIPv4
	testLayerIPv4.Protocol = layers.IPProtocolICMPv4
	icmp := layers.ICMPv4{TypeCode: layers.ICMPv4TypeEchoRequest}

	pkt, err := serializeAndDecode(&testLayerEth, &testLayerIPv4, &icmp)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint16(unix.ETH_P_IP), pkt.L3Proto)
	assert.Equal(t, uint16(unix.IPPROTO_ICMP), pkt.L4Proto)
	assert.Equal(t, uint16(0), pkt.SrcPort)
	assert.Equal(t, uint16(0), pkt.DstPort)
	assert.Equal(t, uint8(SizeofICMP), pkt.L4Len)
}

func BenchmarkDecodePacket(b *testing.B) {
	testLayerEth.EthernetType = layers.EthernetTypeIPv4
	testLayerIPv4.Protocol = layers.IPProtocolTCP
	tcp := layers.TCP{SrcPort: 54213, DstPort: 80}
	tcp.SetNetworkLayerForChecksum(&testLayerIPv4)

	data, err := serialize(&testLayerEth, &testLayerIPv4, &tcp)
	if err != nil {
		b.Fatal(err)
	}

	pkt := &Packet{}
	err = pkt.DecodeFromData(data)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt.DecodeFromData(data)
	}
}

func BenchmarkDecodePacketByGoPacket(b *testing.B) {
	testLayerIPv4.Protocol = layers.IPProtocolTCP
	tcp := layers.TCP{SrcPort: 54213, DstPort: 80}
	tcp.SetNetworkLayerForChecksum(&testLayerIPv4)

	data, err := serialize(&testLayerEth, &testLayerIPv4, &tcp)
	if err != nil {
		b.Fatal(err)
	}

	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if pkt.ErrorLayer() != nil {
		b.Fatal(pkt.ErrorLayer())
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	}
}
