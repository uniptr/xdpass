package handle

import (
	"github.com/zxhio/xdpass/internal/protos"
)

type RedirectHandle interface {
	RedirectType() protos.RedirectType
	HandleReqData([]byte) ([]byte, error)
	HandlePacketData([]byte)
	Close() error
}
