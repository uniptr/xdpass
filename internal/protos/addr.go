package protos

import (
	"encoding/json"
	"net/netip"
)

type AddrPort netip.AddrPort

func (p AddrPort) String() string {
	if netip.AddrPort(p).Compare(netip.AddrPort{}) == 0 {
		return ""
	}
	return netip.AddrPort(p).String()
}

func (p AddrPort) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

func (p *AddrPort) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	return p.Set(s)
}

func (p *AddrPort) Set(s string) error {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return err
	}
	*p = AddrPort(addr)
	return nil
}

func (p *AddrPort) Type() string {
	return "AddrPort"
}
