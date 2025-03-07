package exports

import (
	"sync"

	"github.com/zxhio/xdpass/pkg/xdpprog"
)

type FirewallAPI interface {
	ListIPKey() ([]xdpprog.IPLpmKey, error)
	AddIPKey(xdpprog.IPLpmKey) error
	DelIPKey(xdpprog.IPLpmKey) error
}

type firewallAPI struct {
	mu         *sync.RWMutex
	interfaces map[string]FirewallAPI
}

var firewalls = &firewallAPI{
	mu:         &sync.RWMutex{},
	interfaces: make(map[string]FirewallAPI),
}

func RegisterFirewallAPI(ifaceName string, api FirewallAPI) {
	registerAPI(firewalls.mu, firewalls.interfaces, ifaceName, api)
}

func UnregisterFirewallAPI(ifaceName string) {
	unregisterAPI(firewalls.mu, firewalls.interfaces, ifaceName)
}

func GetFirewallAPI(ifaceName string) (FirewallAPI, bool) {
	return getAPI(firewalls.mu, firewalls.interfaces, ifaceName)
}

func GetFirewallAPIs() map[string]FirewallAPI {
	return getAllAPIs(firewalls.mu, firewalls.interfaces)
}
