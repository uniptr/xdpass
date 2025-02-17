package tap

import (
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/handle"
)

type TapHandle struct{}

func NewTapHandle() (handle.RedirectHandle, error) {
	return nil, protos.ErrNotImpl
}

func (TapHandle) RedirectType() protos.RedirectType {
	return protos.RedirectType_Tap
}

func (h *TapHandle) Close() error {
	return nil
}

func (h *TapHandle) HandleReqData(data []byte) ([]byte, error) {
	return nil, protos.ErrNotImpl
}

func (h *TapHandle) HandlePacketData(data []byte) {
}
