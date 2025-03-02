package redirect

import (
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/dump"
	"github.com/zxhio/xdpass/internal/redirect/handle"
	"github.com/zxhio/xdpass/internal/redirect/spoof"
	"github.com/zxhio/xdpass/internal/redirect/tuntap"
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/utils"
)

type Redirect struct {
	// TODO: Use array to avoid map lookup
	handles map[protos.RedirectType]handle.RedirectHandle
	closers utils.NamedClosers
}

func NewRedirect(ifaceName string) (*Redirect, error) {
	handles := map[protos.RedirectType]handle.RedirectHandle{}

	// Dump
	dumpHandle, err := dump.NewDumpHandle()
	if err != nil {
		return nil, err
	}
	handles[dumpHandle.RedirectType()] = dumpHandle
	closers := utils.NamedClosers{utils.NamedCloser{Name: "dump.DumpHandle", Close: dumpHandle.Close}}

	// Remote
	// TODO: implement

	// Spoof handle
	spoofHandle, err := spoof.NewSpoofHandle(ifaceName)
	if err != nil {
		return nil, err
	}
	handles[spoofHandle.RedirectType()] = spoofHandle
	closers = append(closers, utils.NamedCloser{Name: "spoof.SpoofHandle", Close: spoofHandle.Close})

	// Tun
	tunHandle, err := tuntap.NewTuntapHandle()
	if err != nil {
		return nil, err
	}
	handles[tunHandle.RedirectType()] = tunHandle
	closers = append(closers, utils.NamedCloser{Name: "tun.TunHandle", Close: tunHandle.Close})

	return &Redirect{handles: handles, closers: closers}, nil
}

func (r *Redirect) Close() error {
	r.closers.Close(nil)
	return nil
}

func (r *Redirect) HandlePacket(pkts *fastpkt.Packet) {
	for _, handle := range r.handles {
		handle.HandlePacket(pkts)
	}
}

func (*Redirect) CommandType() protos.Type {
	return protos.TypeRedirect
}

func (r *Redirect) HandleReqData(client *commands.MessageClient, data []byte) error {
	logrus.WithField("data", string(data)).Debug("Handle redirect request data")

	var req protos.RedirectReq
	err := json.Unmarshal(data, &req)
	if err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}

	handle, ok := r.handles[req.RedirectType]
	if !ok {
		return commands.ResponseErrorCode(client, fmt.Errorf("invalid redirect type: %s", req.RedirectType), protos.ErrorCode_InvalidRequest)
	}
	return handle.HandleReqData(client, req.RedirectData)
}
