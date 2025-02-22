package handle

import (
	"github.com/zxhio/xdpass/internal/protos"
)

type PacketData struct {
	Data []byte
	Len  int
}

type RedirectHandle interface {
	RedirectType() protos.RedirectType
	HandleReqData([]byte) ([]byte, error)
	HandlePacketData(*PacketData)
	Close() error
}
