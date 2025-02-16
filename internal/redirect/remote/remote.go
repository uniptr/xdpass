package remote

import (
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/handle"
)

func init() {
	handle.RegisterMaker(RemoteHandle{}.RedirectType(), NewRemoteHandle)
}

type RemoteHandle struct{}

func (RemoteHandle) RedirectType() protos.RedirectType {
	return protos.RedirectType_Remote
}

func (h *RemoteHandle) HandleReqData([]byte) ([]byte, error) {
	return nil, handle.ErrNotImpl
}

func NewRemoteHandle() (handle.RedirectHandle, error) {
	return nil, handle.ErrNotImpl
}
