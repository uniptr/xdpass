package internal

import (
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/xdp"
)

type Stats struct {
	xsks []*xdp.XDPSocket
}

func (s *Stats) CommandType() protos.Type {
	return protos.TypeStats
}

func (s *Stats) HandleReqData(client *commands.MessageClient, _ []byte) error {
	resp := &protos.StatsResp{}
	resp.Queues = make([]protos.StatsQueueID, len(s.xsks))
	for i, xsk := range s.xsks {
		resp.Queues[i] = protos.StatsQueueID{
			QueueID:    xsk.QueueID(),
			Statistics: xsk.Stats(),
		}
	}
	return commands.ResponseMessage(client, resp)
}
