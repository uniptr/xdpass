package redirect

import (
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/xdp"
)

type redirectStats struct {
	xsks []*xdp.XDPSocket
}

func (s *redirectStats) CommandType() protos.Type {
	return protos.TypeStats
}

func (s *redirectStats) HandleReqData(client *commands.MessageClient, _ []byte) error {
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
