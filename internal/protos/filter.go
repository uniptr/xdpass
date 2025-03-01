package protos

import (
	"github.com/zxhio/xdpass/pkg/xdpprog"
)

type FilterReq struct {
	Operation Operation    `json:"operation"`
	Rules     []FilterRule `json:"rules,omitempty"`
}

type FilterResp struct {
	Rules []FilterRule `json:"rules"`
}

type FilterRule struct {
	Interface string             `json:"interface"`
	Keys      []xdpprog.IPLpmKey `json:"keys,omitempty"`
}
