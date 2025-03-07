package exports

import (
	"sync"

	"github.com/zxhio/xdpass/internal/protos"
)

type StatsAPI interface {
	GetQueueStats() []protos.QueueStats
}

type statsAPI struct {
	mu    *sync.RWMutex
	stats map[string]StatsAPI
}

var stats = &statsAPI{
	mu:    &sync.RWMutex{},
	stats: make(map[string]StatsAPI),
}

func RegisterStatsAPI(ifaceName string, api StatsAPI) {
	registerAPI(stats.mu, stats.stats, ifaceName, api)
}

func UnregisterStatsAPI(ifaceName string) {
	unregisterAPI(stats.mu, stats.stats, ifaceName)
}

func GetStatsAPI(ifaceName string) (StatsAPI, bool) {
	return getAPI(stats.mu, stats.stats, ifaceName)
}

func GetStatsAPIs() map[string]StatsAPI {
	return getAllAPIs(stats.mu, stats.stats)
}
