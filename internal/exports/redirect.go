package exports

import (
	"context"
	"sync"

	"github.com/zxhio/xdpass/internal/protos"
)

type RedirectDumpAPI interface {
	KeepPacketHook(context.Context, func([]byte))
}

type RedirectSpoofAPI interface {
	GetSpoofRules() []protos.SpoofRule
	AddSpoofRule(rule protos.SpoofRule) error
	DelSpoofRule(rule protos.SpoofRule) error
}

type RedirectTuntapAPI interface {
	GetTuntaps() []protos.TuntapDevice
	AddTuntap(device *protos.TuntapDevice) error
	DelTuntap(device *protos.TuntapDevice) error
}

type redirectAPIs struct {
	mu         *sync.RWMutex
	dumpAPIs   map[string]RedirectDumpAPI
	tuntapAPIs map[string]RedirectTuntapAPI
	spoofAPIs  map[string]RedirectSpoofAPI
}

var redirects = &redirectAPIs{
	mu:         &sync.RWMutex{},
	dumpAPIs:   make(map[string]RedirectDumpAPI),
	tuntapAPIs: make(map[string]RedirectTuntapAPI),
	spoofAPIs:  make(map[string]RedirectSpoofAPI),
}

// Dump APIs

func RegisterDumpAPI(ifaceName string, api RedirectDumpAPI) {
	registerAPI(redirects.mu, redirects.dumpAPIs, ifaceName, api)
}

func UnregisterDumpAPI(ifaceName string) {
	unregisterAPI(redirects.mu, redirects.dumpAPIs, ifaceName)
}

func GetDumpAPI(ifaceName string) (RedirectDumpAPI, bool) {
	return getAPI(redirects.mu, redirects.dumpAPIs, ifaceName)
}

func GetAllDumpAPIs() map[string]RedirectDumpAPI {
	return getAllAPIs(redirects.mu, redirects.dumpAPIs)
}

// Tuntap APIs

func RegisterTuntapAPI(ifaceName string, api RedirectTuntapAPI) {
	registerAPI(redirects.mu, redirects.tuntapAPIs, ifaceName, api)
}

func UnregisterTuntapAPI(ifaceName string) {
	unregisterAPI(redirects.mu, redirects.tuntapAPIs, ifaceName)
}

func GetTuntapAPI(ifaceName string) (RedirectTuntapAPI, bool) {
	return getAPI(redirects.mu, redirects.tuntapAPIs, ifaceName)
}

func GetAllTuntapAPIs() map[string]RedirectTuntapAPI {
	return getAllAPIs(redirects.mu, redirects.tuntapAPIs)
}

// Spoof APIs

func RegisterSpoofAPI(ifaceName string, api RedirectSpoofAPI) {
	registerAPI(redirects.mu, redirects.spoofAPIs, ifaceName, api)
}

func UnregisterSpoofAPI(ifaceName string) {
	unregisterAPI(redirects.mu, redirects.spoofAPIs, ifaceName)
}

func GetSpoofAPI(ifaceName string) (RedirectSpoofAPI, bool) {
	return getAPI(redirects.mu, redirects.spoofAPIs, ifaceName)
}

func GetAllSpoofAPIs() map[string]RedirectSpoofAPI {
	return getAllAPIs(redirects.mu, redirects.spoofAPIs)
}
