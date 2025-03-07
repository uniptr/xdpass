package redirectcmd

import (
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
)

func doRequest[Q, R any](redirectType protos.RedirectType, v *Q) (*R, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	req := protos.RedirectReq{RedirectType: redirectType, RedirectData: data}
	resp, err := commands.GetMessage[protos.RedirectReq, R](protos.TypeRedirect, "", &req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func response(client *commands.MessageClient, data []byte) error {
	resp := protos.MessageResp{Data: data, ErrorCode: 0}
	return commands.Response(client, &resp)
}

type RedirectHandle interface {
	RedirectType() protos.RedirectType
	HandleReqData(client *commands.MessageClient, data []byte) error
}

var handles = map[protos.RedirectType]RedirectHandle{}

func registerHandle(handle RedirectHandle) { handles[handle.RedirectType()] = handle }

type RedirectCommand struct{}

func (RedirectCommand) CommandType() protos.Type {
	return protos.TypeRedirect
}

func (RedirectCommand) HandleReqData(client *commands.MessageClient, data []byte) error {
	logrus.WithField("data", string(data)).Debug("Handle redirect request data")

	var req protos.RedirectReq
	if err := json.Unmarshal(data, &req); err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}

	handle, ok := handles[req.RedirectType]
	if !ok {
		return commands.ResponseErrorCode(client, fmt.Errorf("invalid redirect type: %s", req.RedirectType), protos.ErrorCode_InvalidRequest)
	}
	return handle.HandleReqData(client, req.RedirectData)
}
