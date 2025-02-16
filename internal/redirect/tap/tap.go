package tap

import (
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/handle"
)

func init() {
	handle.RegisterMaker(TapHandle{}.RedirectType(), NewTap)
}

type TapHandle struct{}

func (TapHandle) RedirectType() protos.RedirectType {
	return protos.RedirectType_Tap
}

func (h *TapHandle) HandleReqData(data []byte) ([]byte, error) {
	return nil, handle.ErrNotImpl
}

func NewTap() (handle.RedirectHandle, error) {
	return nil, handle.ErrNotImpl
}
