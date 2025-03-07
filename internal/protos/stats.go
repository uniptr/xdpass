package protos

import "github.com/zxhio/xdpass/pkg/netutil"

type StatsReq struct {
	Interface string `json:"interface"`
}

type StatsResp struct {
	Interfaces []InterfaceStats `json:"interfaces"`
}

type InterfaceStats struct {
	Interface string       `json:"interface"`
	Queues    []QueueStats `json:"queues"`
}

type QueueStats struct {
	QueueID uint32 `json:"queue_id"`
	netutil.Statistics
}
