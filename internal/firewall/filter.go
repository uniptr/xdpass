package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/xdpprog"
)

type Firewall struct {
	mu      *sync.Mutex
	filters map[string]*Filter
}

func NewFirewall() (*Firewall, error) {
	return &Firewall{
		mu:      &sync.Mutex{},
		filters: make(map[string]*Filter),
	}, nil
}

func (f *Firewall) Add(iface string, trie *ebpf.Map) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	_, ok := f.filters[iface]
	if ok {
		return fmt.Errorf("interface %s already exists", iface)
	}
	f.filters[iface] = NewFilter(iface, trie)
	return nil
}

func (f *Firewall) Del(iface string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.filters[iface]; !ok {
		return fmt.Errorf("interface %s not found", iface)
	}

	// Delete all keys
	keys, err := f.ListIPKey(iface)
	if err != nil {
		return err
	}
	for _, key := range keys {
		err := f.DelIPKey(iface, key)
		if err != nil {
			return err
		}
	}
	delete(f.filters, iface)
	return nil
}

func (f *Firewall) AddIPKey(iface string, key xdpprog.IPLpmKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addIPKey(iface, key)
}

func (f *Firewall) addIPKey(iface string, key xdpprog.IPLpmKey) error {
	filter, ok := f.filters[iface]
	if !ok {
		return fmt.Errorf("not found interface: %s", iface)
	}
	return filter.AddIPKey(key)
}

func (f *Firewall) DelIPKey(iface string, key xdpprog.IPLpmKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.delIPKey(iface, key)
}

func (f *Firewall) delIPKey(iface string, key xdpprog.IPLpmKey) error {
	filter, ok := f.filters[iface]
	if !ok {
		return fmt.Errorf("not found interface: %s", iface)
	}
	return filter.DelIPKey(key)
}

func (f *Firewall) ListIPKey(iface string) ([]xdpprog.IPLpmKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listIPKey(iface)
}

func (f *Firewall) listIPKey(iface string) ([]xdpprog.IPLpmKey, error) {
	filter, ok := f.filters[iface]
	if !ok {
		return nil, fmt.Errorf("not found interface: %s", iface)
	}
	return filter.ListIPKey()
}

// For cmdconn.ReqDataHandle
func (f *Firewall) CommandType() protos.Type { return protos.TypeFilter }

// For cmdconn.ReqDataHandle
func (f *Firewall) HandleReqData(client *commands.MessageClient, data []byte) error {
	var req protos.FilterReq
	err := json.Unmarshal(data, &req)
	if err != nil {
		return commands.ResponseError(client, err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	switch req.Operation {
	case protos.OperationNop:
		data, err = []byte("{}"), nil
	case protos.OperationList:
		data, err = f.handleOpShowList(req.Interface)
	case protos.OperationAdd:
		data, err = f.handleOpAddDel(req, protos.OperationAdd, f.addIPKey)
	case protos.OperationDel:
		data, err = f.handleOpAddDel(req, protos.OperationDel, f.delIPKey)
	}
	if err != nil {
		return commands.ResponseError(client, err)
	}
	return commands.Response(client, &protos.MessageResp{Data: data})
}

func (f *Firewall) handleOpShowList(iface string) ([]byte, error) {
	var filters map[string]*Filter

	if iface == "" {
		filters = f.filters
	} else {
		filter, ok := f.filters[iface]
		if !ok {
			return nil, fmt.Errorf("not found interface: %s", iface)
		}
		filters = map[string]*Filter{iface: filter}
	}

	var resp []protos.FilterIPKeys
	for iface, filter := range filters {
		keys, err := filter.ListIPKey()
		if err != nil {
			return nil, err
		}
		resp = append(resp, protos.FilterIPKeys{
			Interface: iface,
			Keys:      keys,
		})
	}
	return json.Marshal(&protos.FilterResp{Interfaces: resp})
}

func (f *Firewall) handleOpAddDel(req protos.FilterReq, op protos.Operation, handle func(iface string, key xdpprog.IPLpmKey) error) ([]byte, error) {
	for _, key := range req.Keys {
		logrus.WithFields(logrus.Fields{"key": key, "iface": req.Interface, "op": op}).Debug("Operate ip lpm key")
		err := handle(req.Interface, key)
		if err != nil {
			return nil, err
		}
	}
	return []byte("{}"), nil
}

type Filter struct {
	ifaceName string
	trie      *ebpf.Map
	keys      map[xdpprog.IPLpmKey]struct{}
	mu        *sync.Mutex
}

func NewFilter(ifaceName string, trie *ebpf.Map) *Filter {
	return &Filter{
		ifaceName: ifaceName,
		trie:      trie,
		keys:      make(map[xdpprog.IPLpmKey]struct{}),
		mu:        &sync.Mutex{},
	}
}

func (f *Filter) AddIPKey(key xdpprog.IPLpmKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// TODO: Aggregate these keys

	err := f.trie.Update(&key, uint8(0), 0)
	if err != nil {
		return err
	}
	f.keys[key] = struct{}{}
	return nil
}

func (f *Filter) DelIPKey(key xdpprog.IPLpmKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	err := f.trie.Delete(&key)
	if err != nil {
		return err
	}
	delete(f.keys, key)
	return nil
}

func (f *Filter) ListIPKey() ([]xdpprog.IPLpmKey, error) {
	var (
		key     xdpprog.IPLpmKey
		nextKey xdpprog.IPLpmKey
		keys    []xdpprog.IPLpmKey
	)

	for {
		err := f.trie.NextKey(&key, &nextKey)
		if err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, err
		}
		key = nextKey
		keys = append(keys, key)
	}
	return keys, nil
}
