package dump

import (
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/handle"
)

func init() {
	handle.RegisterMaker(DumpHandle{}.RedirectType(), NewDumpHandle)
}

type DumpHandle struct{}

func NewDumpHandle() (handle.RedirectHandle, error) {
	return &DumpHandle{}, nil
}

func (DumpHandle) RedirectType() protos.RedirectType {
	return protos.RedirectType_Dump
}

func (h *DumpHandle) HandleReqData([]byte) ([]byte, error) {
	return nil, handle.ErrNotImpl
}
