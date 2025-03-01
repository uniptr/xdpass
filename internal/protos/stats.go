package protos

import "github.com/zxhio/xdpass/pkg/netutil"

type StatsReq struct{}

type StatsResp struct {
	Queues []StatsQueueID `json:"queues"`
}

type StatsQueueID struct {
	QueueID uint32 `json:"queue_id"`
	netutil.Statistics
}
