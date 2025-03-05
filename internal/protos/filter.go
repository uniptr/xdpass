package protos

import (
	"github.com/zxhio/xdpass/pkg/xdpprog"
)

type FilterReq struct {
	Operation Operation          `json:"operation"`
	Interface string             `json:"interface"`
	Keys      []xdpprog.IPLpmKey `json:"keys,omitempty"`
}

type FilterResp struct {
	Interfaces []FilterIPKeys `json:"interfaces,omitempty"`
}

type FilterIPKeys struct {
	Interface string             `json:"interface"`
	Keys      []xdpprog.IPLpmKey `json:"keys,omitempty"`
}
