package xdpprog

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/kentik/patricia"
)

type FirewallMode uint32

const (
	FirewallModeWhitelist FirewallMode = iota
	FirewallModeBlocklist
)

type Objects struct {
	xdpprogObjects
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdpprog xdp.c -- -I../headers

func LoadObjects(opts *ebpf.CollectionOptions) (*Objects, error) {
	var objs Objects
	return &objs, loadXdpprogObjects(&objs.xdpprogObjects, nil)
}

type IPLpmKey xdpprogIpLpmKey

func (key *IPLpmKey) Set(s string) error {
	k, err := MakeIPLpmKeyFromStr(s)
	if err != nil {
		return err
	}
	*key = *k
	return nil
}

func (key *IPLpmKey) Type() string {
	return "IP[/PrefixLen]"
}

func (key IPLpmKey) IsIPv4() bool {
	for i := 4; i < len(key.Data); i++ {
		if key.Data[i] != 0 {
			return false
		}
	}
	return true
}

func (key IPLpmKey) String() string {
	var ipNet net.IPNet
	if key.IsIPv4() {
		ipNet = net.IPNet{IP: key.Data[:4], Mask: net.CIDRMask(int(key.PrefixLen), 32)}
	} else {
		ipNet = net.IPNet{IP: key.Data[:], Mask: net.CIDRMask(int(key.PrefixLen), 128)}
	}
	return ipNet.String()
}

func (key IPLpmKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(key.String())
}

func (key *IPLpmKey) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	return key.Set(s)
}

func (key *IPLpmKey) To4() patricia.IPv4Address {
	return patricia.NewIPv4Address(binary.BigEndian.Uint32(key.Data[:4]), uint(key.PrefixLen))
}

func (key *IPLpmKey) To6() patricia.IPv6Address {
	return patricia.NewIPv6Address(key.Data[:], uint(key.PrefixLen))
}

func MakeIPLpmKeyFromIP(ip net.IP) *IPLpmKey {
	var key IPLpmKey
	ip4 := ip.To4()
	if len(ip4) == net.IPv4len {
		key.PrefixLen = 32
		copy(key.Data[:net.IPv4len], ip4)
	} else {
		key.PrefixLen = 128
		copy(key.Data[:net.IPv6len], ip)
	}
	return &key
}

func MakeIPLpmKeyFromStr(s string) (*IPLpmKey, error) {
	if strings.IndexByte(s, '/') == -1 {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, errors.New("invalid ip")
		}
		return MakeIPLpmKeyFromIP(ip), nil
	}

	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	ones, _ := ipnet.Mask.Size()

	key := MakeIPLpmKeyFromIP(ipnet.IP)
	key.PrefixLen = uint32(ones)

	return key, nil
}
