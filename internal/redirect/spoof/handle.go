package spoof

import (
	"encoding/json"
	"net/netip"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/handle"
)

type addrKey struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
}

type SpoofHandle struct {
	// TODO: Add interface
	rules map[addrKey]protos.SpoofRule
}

func NewSpoofHandle() (handle.RedirectHandle, error) {
	return &SpoofHandle{
		rules: make(map[addrKey]protos.SpoofRule),
	}, nil
}

func (SpoofHandle) RedirectType() protos.RedirectType {
	return protos.RedirectType_Spoof
}

func (h *SpoofHandle) Close() error {
	return nil
}

func (SpoofHandle) HandlePacketData(data []byte) {
}

func (h *SpoofHandle) HandleReqData(data []byte) ([]byte, error) {
	var req protos.SpoofReq
	err := json.Unmarshal(data, &req)
	if err != nil {
		return nil, err
	}

	logrus.WithField("op", req.Operation).Debug("Handle spoof req")

	switch req.Operation {
	case protos.SpoofOperation_Nop:
		return []byte("{}"), nil
	case protos.SpoofOperation_List:
		return h.handleOpList(&req)
	case protos.SpoofOperation_ListTypes:
		return h.handleOpListTypes(&req)
	case protos.SpoofOperation_Add:
		return h.handleOpAdd(&req)
	case protos.SpoofOperation_Del:
		return h.handleOpDel(&req)
	}

	return nil, protos.ErrNotImpl
}

func (h *SpoofHandle) handleOpList(*protos.SpoofReq) ([]byte, error) {
	var resp protos.SpoofResp
	for _, rule := range h.rules {
		resp.Rules = append(resp.Rules, rule)
	}
	return json.Marshal(resp)
}

func (h *SpoofHandle) handleOpListTypes(*protos.SpoofReq) ([]byte, error) {
	resp := protos.SpoofResp{Rules: []protos.SpoofRule{{
		SpoofType: protos.SpoofType_ICMPEchoReply,
	}}}
	return json.Marshal(resp)
}

func (h *SpoofHandle) handleOpAdd(req *protos.SpoofReq) ([]byte, error) {
	for _, rule := range req.Rules {
		src, err := netip.ParseAddrPort(rule.Source)
		if err != nil {
			return nil, errors.Wrap(err, rule.Source)
		}
		dst, err := netip.ParseAddrPort(rule.Destination)
		if err != nil {
			return nil, errors.Wrap(err, rule.Destination)
		}
		h.rules[addrKey{Source: src, Destination: dst}] = rule
	}
	return []byte("{}"), nil
}

func (h *SpoofHandle) handleOpDel(req *protos.SpoofReq) ([]byte, error) {
	for _, rule := range req.Rules {
		src, err := netip.ParseAddrPort(rule.Source)
		if err != nil {
			return nil, errors.Wrap(err, rule.Source)
		}
		dst, err := netip.ParseAddrPort(rule.Destination)
		if err != nil {
			return nil, errors.Wrap(err, rule.Destination)
		}
		delete(h.rules, addrKey{Source: src, Destination: dst})
	}
	return []byte("{}"), nil
}
