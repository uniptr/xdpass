package handle

import (
	"encoding/json"

	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
)

type PacketData struct {
	Data []byte
	Len  int
}

type RedirectHandle interface {
	RedirectType() protos.RedirectType
	HandleReqData(client *commands.MessageClient, req []byte) error
	HandlePacketData(*PacketData)
	Close() error
}

func ResponseRedirectValue[T any](client *commands.MessageClient, v *T) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}
	resp := protos.MessageResp{Data: raw, ErrorCode: 0}
	return commands.Response(client, &resp)
}

func ResponseRedirectData(client *commands.MessageClient, data []byte) error {
	resp := protos.MessageResp{Data: data, ErrorCode: 0}
	return commands.Response(client, &resp)
}
