package protos

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/zxhio/xdpass/pkg/netutil"
)

type RedirectType int

const (
	RedirectTypeDump RedirectType = iota + 1
	RedirectTypeRemote
	RedirectTypeSpoof
	RedirectTypeTuntap
)

const (
	redirectTypeStrDump   = "dump"
	redirectTypeStrRemote = "remote"
	redirectTypeStrSpoof  = "spoof"
	redirectTypeStrTuntap = "tuntap"
)

var redirectTypeStrLookup = map[RedirectType]string{
	RedirectTypeDump:   redirectTypeStrDump,
	RedirectTypeRemote: redirectTypeStrRemote,
	RedirectTypeSpoof:  redirectTypeStrSpoof,
	RedirectTypeTuntap: redirectTypeStrTuntap,
}

var redirectTypeLookup = map[string]RedirectType{
	redirectTypeStrDump:   RedirectTypeDump,
	redirectTypeStrRemote: RedirectTypeRemote,
	redirectTypeStrSpoof:  RedirectTypeSpoof,
	redirectTypeStrTuntap: RedirectTypeTuntap,
}

func (t RedirectType) String() string {
	return redirectTypeStrLookup[t]
}

func (t *RedirectType) Set(s string) error {
	v, ok := redirectTypeLookup[s]
	if !ok {
		return fmt.Errorf("invalid redirect type: %s", s)
	}
	*t = v
	return nil
}

func (t RedirectType) MarshalJSON() ([]byte, error) {
	s, ok := redirectTypeStrLookup[t]
	if !ok {
		return nil, fmt.Errorf("invalid redirect type %d", t)
	}
	return json.Marshal(s)
}

func (t *RedirectType) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	return t.Set(s)
}

type RedirectReq struct {
	RedirectType RedirectType    `json:"redirect_type"`
	RedirectData json.RawMessage `json:"redirect_data"`
}

type DumpReq struct {
	Interface string `json:"interface,omitempty"`
}

// Remote
// TODO: add req/resp

// Spoof

type SpoofType uint16

const (
	SpoofTypeNone SpoofType = iota
	SpoofTypeICMPEchoReply
	SpoofTypeTCPReset
	SpoofTypeTCPResetSYN
)

const (
	spoofTypeStrNone          = "none"
	spoofTypeStrICMPEchoReply = "icmp-echo-reply"
	spoofTypeStrTCPReset      = "tcp-reset"
	spoofTypeStrTCPResetSYN   = "tcp-reset-syn"
)

var spoofTypeLookup = map[string]SpoofType{
	spoofTypeStrNone:          SpoofTypeNone,
	spoofTypeStrICMPEchoReply: SpoofTypeICMPEchoReply,
	spoofTypeStrTCPReset:      SpoofTypeTCPReset,
	spoofTypeStrTCPResetSYN:   SpoofTypeTCPResetSYN,
}

var spoofTypeStrLookup = map[SpoofType]string{
	SpoofTypeNone:          spoofTypeStrNone,
	SpoofTypeICMPEchoReply: spoofTypeStrICMPEchoReply,
	SpoofTypeTCPReset:      spoofTypeStrTCPReset,
	SpoofTypeTCPResetSYN:   spoofTypeStrTCPResetSYN,
}

func (t SpoofType) String() string { return spoofTypeStrLookup[t] }

func (t *SpoofType) Set(s string) error {
	v, ok := spoofTypeLookup[s]
	if !ok {
		return fmt.Errorf("invalid spoof type: %s", s)
	}
	*t = v
	return nil
}

func (t *SpoofType) Type() string {
	return "SpoofType"
}

func (t SpoofType) MarshalJSON() ([]byte, error) {
	s, ok := spoofTypeStrLookup[t]
	if !ok {
		return nil, fmt.Errorf("invalid spoof type: %d", t)
	}
	return json.Marshal(s)
}

func (t *SpoofType) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	return t.Set(s)
}

type SpoofRule struct {
	ID uint32 `json:"id,omitempty"`
	SpoofRuleV4
}

type SpoofRuleSlice []SpoofRule

func (s SpoofRuleSlice) Len() int           { return len(s) }
func (s SpoofRuleSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s SpoofRuleSlice) Less(i, j int) bool { return s[i].ID < s[j].ID }

type SpoofRuleV4 struct {
	SrcIP          uint32    `json:"src_ip,omitempty"`
	DstIP          uint32    `json:"dst_ip,omitempty"`
	SrcIPPrefixLen uint8     `json:"src_ip_prefix_len,omitempty"`
	DstIPPrefixLen uint8     `json:"dst_ip_prefix_len,omitempty"`
	SrcPort        uint16    `json:"src_port,omitempty"`
	DstPort        uint16    `json:"dst_port,omitempty"`
	Proto          uint16    `json:"proto,omitempty"`
	SpoofType      SpoofType `json:"spoof_type"`
}

func (d *SpoofRuleV4) String() string {
	srcIP := net.IPNet{IP: netutil.Uint32ToIPv4(d.SrcIP), Mask: net.CIDRMask(int(d.SrcIPPrefixLen), 32)}
	dstIP := net.IPNet{IP: netutil.Uint32ToIPv4(d.DstIP), Mask: net.CIDRMask(int(d.DstIPPrefixLen), 32)}
	return fmt.Sprintf("%s(0x%0x,%s:%d,%s:%d)", d.SpoofType.String(), d.Proto, srcIP.String(), d.SrcPort, dstIP.String(), d.DstPort)
}

type SpoofReq struct {
	Operation Operation   `json:"operation"`
	Interface string      `json:"interface,omitempty"`
	Rules     []SpoofRule `json:"rules,omitempty"`
}

type SpoofResp struct {
	Interfaces     []SpoofInterfaceRule `json:"interfaces,omitempty"`
	SupportedTypes []SpoofType          `json:"supported_types,omitempty"`
}

type SpoofInterfaceRule struct {
	Interface string      `json:"interface"`
	Rules     []SpoofRule `json:"rules"`
}

// Tun

type TuntapReq struct {
	Operation Operation      `json:"operation"`
	Interface string         `json:"interface,omitempty"`
	Devices   []TuntapDevice `json:"devices,omitempty"`
}

type TuntapDevice struct {
	Name string             `json:"name"`
	Mode netlink.TuntapMode `json:"mode,omitempty"`
}

type TuntapResp struct {
	Interfaces []TuntapInterfaceDevices `json:"interfaces,omitempty"`
}

type TuntapInterfaceDevices struct {
	Interface string         `json:"interface"`
	Devices   []TuntapDevice `json:"devices"`
}
