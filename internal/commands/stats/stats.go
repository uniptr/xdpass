package stats

import (
	"context"

	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
)

type StatsServer struct {
	stats map[string]func() protos.StatsQueueID
}

func NewStatsServer() *StatsServer {
	return &StatsServer{
		stats: make(map[string]func() protos.StatsQueueID),
	}
}

func (s *StatsServer) AddStatsGetter(iface string, getter func() protos.StatsQueueID) {
	s.stats[iface] = getter
}

func (s *StatsServer) DelStatsGetter(iface string) {
	delete(s.stats, iface)
}

func (s *StatsServer) Serve(ctx context.Context) error {
	return nil
}

func (s *StatsServer) Close() error {
	return nil
}

func (s *StatsServer) HandleReqData(client *commands.MessageClient, req []byte) error {
	return nil
}
