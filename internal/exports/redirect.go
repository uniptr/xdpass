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
	mu         *sync.Mutex
	dumpAPIs   map[string]RedirectDumpAPI
	tuntapAPIs map[string]RedirectTuntapAPI
	spoofAPIs  map[string]RedirectSpoofAPI
}

var redirects = &redirectAPIs{
	mu:         &sync.Mutex{},
	dumpAPIs:   make(map[string]RedirectDumpAPI),
	tuntapAPIs: make(map[string]RedirectTuntapAPI),
	spoofAPIs:  make(map[string]RedirectSpoofAPI),
}

func registerWithLock[T any](r *redirectAPIs, m map[string]T, ifaceName string, api T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m[ifaceName] = api
}

func unregisterWithLock[T any](r *redirectAPIs, m map[string]T, ifaceName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(m, ifaceName)
}

func getWithLock[T any](r *redirectAPIs, m map[string]T, ifaceName string) (T, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	api, ok := m[ifaceName]
	return api, ok
}

func getAllWithLock[T any](r *redirectAPIs, m map[string]T) map[string]T {
	r.mu.Lock()
	defer r.mu.Unlock()

	apis := make(map[string]T)
	for ifaceName, api := range m {
		apis[ifaceName] = api
	}
	return apis
}

// Dump APIs

func RegisterDumpAPI(ifaceName string, api RedirectDumpAPI) {
	registerWithLock(redirects, redirects.dumpAPIs, ifaceName, api)
}

func UnregisterDumpAPI(ifaceName string) {
	unregisterWithLock(redirects, redirects.dumpAPIs, ifaceName)
}

func GetDumpAPI(ifaceName string) (RedirectDumpAPI, bool) {
	return getWithLock(redirects, redirects.dumpAPIs, ifaceName)
}

func GetAllDumpAPIs() map[string]RedirectDumpAPI {
	return getAllWithLock(redirects, redirects.dumpAPIs)
}

// Tuntap APIs

func RegisterTuntapAPI(ifaceName string, api RedirectTuntapAPI) {
	registerWithLock(redirects, redirects.tuntapAPIs, ifaceName, api)
}

func UnregisterTuntapAPI(ifaceName string) {
	unregisterWithLock(redirects, redirects.tuntapAPIs, ifaceName)
}

func GetTuntapAPI(ifaceName string) (RedirectTuntapAPI, bool) {
	return getWithLock(redirects, redirects.tuntapAPIs, ifaceName)
}

func GetAllTuntapAPIs() map[string]RedirectTuntapAPI {
	return getAllWithLock(redirects, redirects.tuntapAPIs)
}

// Spoof APIs

func RegisterSpoofAPI(ifaceName string, api RedirectSpoofAPI) {
	registerWithLock(redirects, redirects.spoofAPIs, ifaceName, api)
}

func UnregisterSpoofAPI(ifaceName string) {
	unregisterWithLock(redirects, redirects.spoofAPIs, ifaceName)
}

func GetSpoofAPI(ifaceName string) (RedirectSpoofAPI, bool) {
	return getWithLock(redirects, redirects.spoofAPIs, ifaceName)
}

func GetAllSpoofAPIs() map[string]RedirectSpoofAPI {
	return getAllWithLock(redirects, redirects.spoofAPIs)
}
