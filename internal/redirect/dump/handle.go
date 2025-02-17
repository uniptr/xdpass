package dump

import (
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/handle"
)

type DumpHandle struct{}

func NewDumpHandle() (handle.RedirectHandle, error) {
	return nil, protos.ErrNotImpl
}

func (DumpHandle) RedirectType() protos.RedirectType {
	return protos.RedirectType_Dump
}

func (h *DumpHandle) Close() error {
	return nil
}

func (h *DumpHandle) HandleReqData([]byte) ([]byte, error) {
	return nil, protos.ErrNotImpl
}

func (h *DumpHandle) HandlePacketData(data []byte) {
}
