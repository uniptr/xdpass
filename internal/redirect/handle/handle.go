package handle

import (
	"errors"

	"github.com/zxhio/xdpass/internal/protos"
)

var (
	ErrNotImpl = errors.New("not implement")
)

type RedirectHandle interface {
	RedirectType() protos.RedirectType
	HandleReqData([]byte) ([]byte, error)
}

type HandleMaker func() (RedirectHandle, error)

var makers map[protos.RedirectType]HandleMaker

func RegisterMaker(typ protos.RedirectType, maker HandleMaker) {
	makers[typ] = maker
}

func GetMaker(typ protos.RedirectType) (HandleMaker, bool) {
	maker, ok := makers[typ]
	return maker, ok
}
