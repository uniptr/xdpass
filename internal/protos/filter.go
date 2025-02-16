package protos

import (
	"github.com/zxhio/xdpass/pkg/xdpprog"
)

type FilterReq struct {
	Interface string             `json:"interface"`
	AddKeys   []xdpprog.IPLpmKey `json:"add_keys,omitempty"`
	DelKeys   []xdpprog.IPLpmKey `json:"del_keys,omitempty"`
	Show      bool               `json:"show,omitempty"`
}

type FilterResp struct {
	InterfacesKeys []FilterInterfaceKeys `json:"interfaces_keys"`
}

type FilterInterfaceKeys struct {
	Interface string             `json:"interface"`
	Keys      []xdpprog.IPLpmKey `json:"keys,omitempty"`
}
