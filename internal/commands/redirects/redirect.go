package redirects

import (
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
)

func ResponseRedirectData(client *commands.MessageClient, data []byte) error {
	resp := protos.MessageResp{Data: data, ErrorCode: 0}
	return commands.Response(client, &resp)
}

type RedirectHandle interface {
	RedirectType() protos.RedirectType
	HandleReqData(client *commands.MessageClient, data []byte) error
}

type RedirectCommand struct {
	handles map[protos.RedirectType]RedirectHandle
}

func NewRedirectCommand() *RedirectCommand {
	dump := NewDumpCommand()
	spoof := NewSpoofCommand()
	tuntap := NewTuntapCommand()
	return &RedirectCommand{
		handles: map[protos.RedirectType]RedirectHandle{
			dump.RedirectType():   dump,
			spoof.RedirectType():  spoof,
			tuntap.RedirectType(): tuntap,
		},
	}
}

func (RedirectCommand) CommandType() protos.Type {
	return protos.TypeRedirect
}

func (r *RedirectCommand) GetCommandHandle(redirectType protos.RedirectType) RedirectHandle {
	return r.handles[redirectType]
}

func (r *RedirectCommand) HandleReqData(client *commands.MessageClient, data []byte) error {
	logrus.WithField("data", string(data)).Debug("Handle redirect request data")

	var req protos.RedirectReq
	if err := json.Unmarshal(data, &req); err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}

	handle, ok := r.handles[req.RedirectType]
	if !ok {
		return commands.ResponseErrorCode(client, fmt.Errorf("invalid redirect type: %s", req.RedirectType), protos.ErrorCode_InvalidRequest)
	}
	return handle.HandleReqData(client, req.RedirectData)
}
