package fastpkt

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/zxhio/xdpass/pkg/netutil"
)

func setBaseLayersForUDP() {
	testLayerEth.EthernetType = layers.EthernetTypeIPv4
	testLayerIPv4.Protocol = layers.IPProtocolUDP
}

func TestUDPChecksum(t *testing.T) {
	setBaseLayersForUDP()

	testCases := []struct {
		payload []byte
	}{
		{},
		{payload: []byte{0x01, 0x02, 0x03, 0x04}},
		{payload: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{payload: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a}},
	}

	for _, testCase := range testCases {
		layerUDP := layers.UDP{SrcPort: 4096, DstPort: 65535}
		layerUDP.SetNetworkLayerForChecksum(&testLayerIPv4)

		buf, err := serialize(&testLayerIPv4, &layerUDP, gopacket.Payload(testCase.payload))
		if err != nil {
			t.Fatalf("serialize: %v", err)
		}

		ipPseudoChecksum := DataPtrIPv4(buf, 0).PseudoChecksum()
		checksum := netutil.Htons(DataPtrUDP(buf, 20).ComputeChecksum(ipPseudoChecksum, uint16(len(testCase.payload))))

		pkt := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.Default)
		assert.Equal(t, pkt.Layers()[1].(*layers.UDP).Checksum, checksum)
	}
}
