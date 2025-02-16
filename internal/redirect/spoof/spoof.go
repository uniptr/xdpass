package spoof

import (
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/handle"
)

func init() {
	handle.RegisterMaker(SpoofHandle{}.RedirectType(), NewSpoofHandle)
}

type SpoofHandle struct{}

func (SpoofHandle) RedirectType() protos.RedirectType {
	return protos.RedirectType_Spoof
}

func (h *SpoofHandle) HandleReqData(data []byte) ([]byte, error) {
	return nil, handle.ErrNotImpl
}

func NewSpoofHandle() (handle.RedirectHandle, error) {
	return nil, handle.ErrNotImpl
}
