package protos

import (
	"github.com/zxhio/xdpass/pkg/xdpprog"
)

type FilterOperation int

const (
	FilterOperation_Nop FilterOperation = iota
	FilterOperation_List
	FilterOperation_Add
	FilterOperation_Del
)

func (f FilterOperation) String() string {
	switch f {
	case FilterOperation_Nop:
		return "nop"
	case FilterOperation_List:
		return "list"
	case FilterOperation_Add:
		return "add"
	case FilterOperation_Del:
		return "del"
	}
	return "unknown"
}

type FilterReq struct {
	Operation FilterOperation `json:"operation"`
	Rules     []FilterRule    `json:"rules,omitempty"`
}

type FilterResp struct {
	Rules []FilterRule `json:"rules"`
}

type FilterRule struct {
	Interface string             `json:"interface"`
	Keys      []xdpprog.IPLpmKey `json:"keys,omitempty"`
}
