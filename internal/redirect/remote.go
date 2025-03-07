package redirect

import (
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/fastpkt"
)

type RemoteHandle struct{}

func NewRemoteHandle() (RedirectHandle, error) {
	return nil, protos.ErrNotImpl
}

func (RemoteHandle) RedirectType() protos.RedirectType {
	return protos.RedirectTypeRemote
}

func (h *RemoteHandle) Close() error {
	return nil
}

func (h *RemoteHandle) HandleReqData([]byte) ([]byte, error) {
	return nil, protos.ErrNotImpl
}

func (h *RemoteHandle) HandlePacket(pkt *fastpkt.Packet) {
}
