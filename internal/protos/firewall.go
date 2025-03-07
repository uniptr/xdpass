package protos

import (
	"github.com/zxhio/xdpass/pkg/xdpprog"
)

type FirewallReq struct {
	Operation Operation          `json:"operation"`
	Interface string             `json:"interface"`
	Keys      []xdpprog.IPLpmKey `json:"keys,omitempty"`
}

type FirewallResp struct {
	Interfaces []FirewallIPKeys `json:"interfaces,omitempty"`
}

type FirewallIPKeys struct {
	Interface string             `json:"interface"`
	Keys      []xdpprog.IPLpmKey `json:"keys,omitempty"`
}
