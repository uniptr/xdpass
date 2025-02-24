package protos

import (
	"encoding/json"
	"fmt"

	"github.com/zxhio/xdpass/pkg/xdpprog"
)

type RedirectType int

const (
	RedirectType_Dump RedirectType = iota + 1
	RedirectType_Remote
	RedirectType_Spoof
	RedirectType_Tap
)

const (
	RedirectTypeStr_Dump   = "dump"
	RedirectTypeStr_Remote = "remote"
	RedirectTypeStr_Spoof  = "spoof"
	RedirectTypeStr_Tap    = "tap"
)

var redirectTypeStrLookup = map[RedirectType]string{
	RedirectType_Dump:   RedirectTypeStr_Dump,
	RedirectType_Remote: RedirectTypeStr_Remote,
	RedirectType_Spoof:  RedirectTypeStr_Spoof,
	RedirectType_Tap:    RedirectTypeStr_Tap,
}

var redirectTypeLookup = map[string]RedirectType{
	RedirectTypeStr_Dump:   RedirectType_Dump,
	RedirectTypeStr_Remote: RedirectType_Remote,
	RedirectTypeStr_Spoof:  RedirectType_Spoof,
	RedirectTypeStr_Tap:    RedirectType_Tap,
}

func (t RedirectType) String() string {
	return redirectTypeStrLookup[t]
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

	v, ok := redirectTypeLookup[s]
	if !ok {
		return fmt.Errorf("invalid redirect type string")
	}
	*t = v
	return nil
}

type RedirectReq struct {
	RedirectType RedirectType    `json:"redirect_type"`
	RedirectData json.RawMessage `json:"redirect_data"`
}

// Dump
// TODO: add req/resp

// Remote
// TODO: add req/resp

// Spoof

type SpoofType uint16

const (
	SpoofType_None SpoofType = iota
	SpoofType_ICMPEchoReply
	SpoofType_TCPReset
	SpoofType_TCPResetSYN
)

const (
	SpoofTypeStr_None          = "none"
	SpoofTypeStr_ICMPEchoReply = "icmp-echo-reply"
	SpoofTypeStr_TCPReset      = "tcp-reset"
	SpoofTypeStr_TCPResetSYN   = "tcp-reset-syn"
)

var spoofTypeLookup = map[string]SpoofType{
	SpoofTypeStr_None:          SpoofType_None,
	SpoofTypeStr_ICMPEchoReply: SpoofType_ICMPEchoReply,
	SpoofTypeStr_TCPReset:      SpoofType_TCPReset,
}

var spoofTypeStrLookup = map[SpoofType]string{
	SpoofType_None:          SpoofTypeStr_None,
	SpoofType_ICMPEchoReply: SpoofTypeStr_ICMPEchoReply,
	SpoofType_TCPReset:      SpoofTypeStr_TCPReset,
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

type SpoofOperation int

const (
	SpoofOperation_Nop SpoofOperation = iota
	SpoofOperation_List
	SpoofOperation_ListTypes
	SpoofOperation_Add
	SpoofOperation_Del
)

func (o SpoofOperation) String() string {
	switch o {
	case SpoofOperation_Nop:
		return "nop"
	case SpoofOperation_List:
		return "list"
	case SpoofOperation_ListTypes:
		return "list-types"
	case SpoofOperation_Add:
		return "add"
	case SpoofOperation_Del:
		return "del"
	}
	return "unknown"
}

type SpoofRule struct {
	ID           uint32           `json:"id,omitempty"`
	SrcIPAddrLPM xdpprog.IPLpmKey `json:"src_ip_lpm"`
	DstIPAddrLPM xdpprog.IPLpmKey `json:"dst_ip_lpm"`
	SrcPort      uint16           `json:"src_port,omitempty"`
	DstPort      uint16           `json:"dst_port,omitempty"`
	Proto        uint16           `json:"proto,omitempty"`
	SpoofType    SpoofType        `json:"spoof_type"`
}

type SpoofReq struct {
	Operation SpoofOperation `json:"operation"`
	Rules     []SpoofRule    `json:"rules,omitempty"`
}

type SpoofResp struct {
	Rules []SpoofRule `json:"rules,omitempty"`
}
