package spoof

import (
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"testing"

	"github.com/kentik/patricia"
	"github.com/kentik/patricia/generics_tree"
	"github.com/stretchr/testify/assert"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netutil"
	"golang.org/x/sys/unix"
)

func randomRulesV4(prefixLen uint) protos.SpoofRuleV4 {
	srcIP := rand.Uint32()
	dstIP := srcIP + (rand.Uint32() % (1 << (32 - prefixLen)))
	return protos.SpoofRuleV4{
		SrcIP:          srcIP,
		DstIP:          dstIP,
		SrcIPPrefixLen: uint8(prefixLen),
		DstIPPrefixLen: uint8(prefixLen),
		SrcPort:        uint16(rand.Uint32() % (1 << 16)),
		DstPort:        uint16(rand.Uint32() % (1 << 16)),
		Proto:          uint16(unix.IPPROTO_TCP),
	}
}

func TestAddrWithPrefix(t *testing.T) {
	testCases := []struct {
		ip        string
		prefixlen int
		expect    string
	}{
		{
			ip:        "192.168.1.1",
			prefixlen: 32,
			expect:    "192.168.1.1",
		},
		{
			ip:        "192.168.1.1",
			prefixlen: 24,
			expect:    "192.168.1.0",
		},
		{
			ip:        "192.168.1.1",
			prefixlen: 16,
			expect:    "192.168.0.0",
		},
	}

	for _, testCase := range testCases {
		uint32IP := IPv4PrefixToUint32(netutil.IPv4ToUint32(net.ParseIP(testCase.ip).To4()), uint(testCase.prefixlen))
		assert.Equal(t, testCase.expect, netutil.Uint32ToIPv4(uint32IP).String())
	}
}

var testPacketTCP = fastpkt.Packet{
	SrcIP:   netutil.IPv4ToUint32(net.IPv4(172, 16, 23, 2)),
	DstIP:   netutil.IPv4ToUint32(net.IPv4(172, 16, 23, 1)),
	SrcPort: 12345,
	DstPort: 80,
	L4Proto: unix.IPPROTO_TCP,
}

var testFullRuleV4 = protos.SpoofRuleV4{
	SrcIP:          testPacketTCP.SrcIP,
	DstIP:          testPacketTCP.DstIP,
	SrcIPPrefixLen: 32,
	DstIPPrefixLen: 32,
	Proto:          uint16(testPacketTCP.L4Proto),
	SrcPort:        testPacketTCP.SrcPort,
	DstPort:        testPacketTCP.DstPort,
}

func TestMatch(t *testing.T) {
	testCases := []struct {
		name         string
		ignoreFnList []func(d *protos.SpoofRuleV4)
	}{
		{
			name:         "Full",
			ignoreFnList: []func(d *protos.SpoofRuleV4){},
		},
		{
			name: "PartialIgnore1",
			ignoreFnList: []func(d *protos.SpoofRuleV4){
				func(d *protos.SpoofRuleV4) { d.Proto = 0 },
			},
		},
		{
			name: "PartialIgnore2",
			ignoreFnList: []func(d *protos.SpoofRuleV4){
				func(d *protos.SpoofRuleV4) { d.Proto = 0 },
				func(d *protos.SpoofRuleV4) { d.SrcPort = 0 },
			},
		},
		{
			name: "PartialIgnore3",
			ignoreFnList: []func(d *protos.SpoofRuleV4){
				func(d *protos.SpoofRuleV4) { d.Proto = 0 },
				func(d *protos.SpoofRuleV4) { d.SrcPort = 0 },
				func(d *protos.SpoofRuleV4) { d.DstPort = 0 },
			},
		},
		{
			name: "PartialIgnore4",
			ignoreFnList: []func(d *protos.SpoofRuleV4){
				func(d *protos.SpoofRuleV4) { d.Proto = 0 },
				func(d *protos.SpoofRuleV4) { d.SrcPort = 0 },
				func(d *protos.SpoofRuleV4) { d.DstPort = 0 },
				func(d *protos.SpoofRuleV4) { d.SrcIPPrefixLen = 0 },
			},
		},
		{
			name: "PartialIgnoreAll",
			ignoreFnList: []func(d *protos.SpoofRuleV4){
				func(d *protos.SpoofRuleV4) { d.Proto = 0 },
				func(d *protos.SpoofRuleV4) { d.SrcPort = 0 },
				func(d *protos.SpoofRuleV4) { d.DstPort = 0 },
				func(d *protos.SpoofRuleV4) { d.SrcIPPrefixLen = 0 },
				func(d *protos.SpoofRuleV4) { d.DstIPPrefixLen = 0 },
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			d := testFullRuleV4
			for _, ignoreFn := range testCase.ignoreFnList {
				ignoreFn(&d)
			}

			tree := generics_tree.NewTreeV4[protos.SpoofRuleV4]()
			tree.Add(patricia.NewIPv4Address(testPacketTCP.DstIP, 32), d, nil)
			ok, ret := matchByDstIPKey(tree, &testPacketTCP, []protos.SpoofRuleV4{})
			assert.True(t, ok)
			assert.Equal(t, d, ret[0])
		})
	}
}

func TestNotMatch(t *testing.T) {
	testCases := []struct {
		name            string
		matchedDstIP    bool
		packetModFnList []func(d *fastpkt.Packet)
	}{
		{
			name:         "NotMatchArgs1",
			matchedDstIP: true,
			packetModFnList: []func(d *fastpkt.Packet){
				func(d *fastpkt.Packet) { d.L4Proto = d.L4Proto + 1 },
			},
		},
		{
			name:         "NotMatchArgs2",
			matchedDstIP: true,
			packetModFnList: []func(d *fastpkt.Packet){
				func(d *fastpkt.Packet) { d.L4Proto = d.L4Proto + 1 },
				func(d *fastpkt.Packet) { d.SrcPort = d.SrcPort + 1 },
			},
		},
		{
			name:         "NotMatchArgs3",
			matchedDstIP: true,
			packetModFnList: []func(d *fastpkt.Packet){
				func(d *fastpkt.Packet) { d.L4Proto = d.L4Proto + 1 },
				func(d *fastpkt.Packet) { d.SrcPort = d.SrcPort + 1 },
				func(d *fastpkt.Packet) { d.DstPort = d.DstPort + 1 },
			},
		},
		{
			name:         "NotMatchArgs4",
			matchedDstIP: true,
			packetModFnList: []func(d *fastpkt.Packet){
				func(d *fastpkt.Packet) { d.L4Proto = d.L4Proto + 1 },
				func(d *fastpkt.Packet) { d.SrcPort = d.SrcPort + 1 },
				func(d *fastpkt.Packet) { d.DstPort = d.DstPort + 1 },
				func(d *fastpkt.Packet) { d.SrcIP = d.SrcIP + 1 },
			},
		},
		{
			name:         "NotMatchArgsAll",
			matchedDstIP: false,
			packetModFnList: []func(d *fastpkt.Packet){
				func(d *fastpkt.Packet) { d.L4Proto = d.L4Proto + 1 },
				func(d *fastpkt.Packet) { d.SrcPort = d.SrcPort + 1 },
				func(d *fastpkt.Packet) { d.DstPort = d.DstPort + 1 },
				func(d *fastpkt.Packet) { d.SrcIP = d.SrcIP + 1 },
				func(d *fastpkt.Packet) { d.DstIP = d.DstIP + 1 },
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			pkt := testPacketTCP
			for _, modFn := range testCase.packetModFnList {
				modFn(&pkt)
			}

			tree := generics_tree.NewTreeV4[protos.SpoofRuleV4]()
			tree.Add(patricia.NewIPv4Address(testPacketTCP.DstIP, 32), testFullRuleV4, nil)
			ok, ret := matchByDstIPKey(tree, &pkt, []protos.SpoofRuleV4{})
			assert.Equal(t, testCase.matchedDstIP, ok)
			assert.Equal(t, 0, len(ret))
		})
	}
}

func BenchmarkRule(b *testing.B) {
	bench := func(b *testing.B, prefixLen uint, randomN int, reuseBuf bool, withLock bool) {
		tree := generics_tree.NewTreeV4[protos.SpoofRuleV4]()

		var rules []protos.SpoofRuleV4
		for i := 0; i < randomN; i++ {
			rules = append(rules, randomRulesV4(prefixLen))
		}

		// Random rules
		for _, rule := range rules {
			tree.Add(patricia.NewIPv4Address(rule.SrcIP, prefixLen), rule, nil)
		}

		// Matched rules
		tree.Add(patricia.NewIPv4Address(testFullRuleV4.DstIP, 32), testFullRuleV4, nil)

		buf := []protos.SpoofRuleV4{}
		if reuseBuf {
			buf = make([]protos.SpoofRuleV4, 0, max(1024, randomN/100))
		}

		lock := func() {}
		unlock := func() {}

		mu := sync.RWMutex{}
		if withLock {
			lock = func() { mu.RLock() }
			unlock = func() { mu.RUnlock() }
		}

		for i := 0; i < b.N; i++ {
			if reuseBuf {
				buf = buf[:0]
			}
			lock()
			matchByDstIPKey(tree, &testPacketTCP, buf)
			unlock()
		}
	}

	benchCases := []struct {
		prefixLen int
		randomN   int
		buffered  bool
		withLock  bool
	}{
		{prefixLen: 24, randomN: 1000},
		{prefixLen: 24, randomN: 1000, buffered: true},
		{prefixLen: 24, randomN: 1000, buffered: true, withLock: true},
		{prefixLen: 24, randomN: 10000},
		{prefixLen: 24, randomN: 10000, buffered: true},
		{prefixLen: 24, randomN: 10000, buffered: true, withLock: true},
		{prefixLen: 24, randomN: 100000},
		{prefixLen: 24, randomN: 100000, buffered: true},
		{prefixLen: 24, randomN: 100000, buffered: true, withLock: true},
		{prefixLen: 24, randomN: 1000000},
		{prefixLen: 24, randomN: 1000000, buffered: true},
		{prefixLen: 24, randomN: 1000000, buffered: true, withLock: true},

		{prefixLen: 16, randomN: 1000, buffered: true},
		{prefixLen: 16, randomN: 1000, buffered: true, withLock: true},
		{prefixLen: 16, randomN: 10000, buffered: true},
		{prefixLen: 16, randomN: 10000, buffered: true, withLock: true},
		{prefixLen: 16, randomN: 100000, buffered: true},
		{prefixLen: 16, randomN: 100000, buffered: true, withLock: true},
		{prefixLen: 16, randomN: 1000000, buffered: true},
		{prefixLen: 16, randomN: 1000000, buffered: true, withLock: true},
	}

	for _, benchCase := range benchCases {
		b.Run(fmt.Sprintf("N=%d_Buf=%t_PrefixLen=%d_WithLock=%t", benchCase.randomN, benchCase.buffered, benchCase.prefixLen, benchCase.withLock), func(b *testing.B) {
			bench(b, uint(benchCase.prefixLen), benchCase.randomN, benchCase.buffered, benchCase.withLock)
		})
	}
}
