package firewall

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/xdpprog"
)

type Filter struct {
	ifaceName string
	trie      *ebpf.Map
	keys      map[xdpprog.IPLpmKey]struct{}
	mu        sync.Mutex
}

func NewFilter(ifaceName string, trie *ebpf.Map) (*Filter, error) {
	return &Filter{
		ifaceName: ifaceName,
		trie:      trie,
		keys:      make(map[xdpprog.IPLpmKey]struct{}),
	}, nil
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

func (f *Filter) List() ([]xdpprog.IPLpmKey, error) {
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

// For cmdconn.ReqDataHandle
func (f *Filter) CommandType() protos.Type { return protos.Type_Filter }

// For cmdconn.ReqDataHandle
func (f *Filter) HandleReqData(client *commands.MessageClient, data []byte) error {
	var req protos.FilterReq
	err := json.Unmarshal(data, &req)
	if err != nil {
		return commands.ResponseError(client, err)
	}

	switch req.Operation {
	case protos.OperationNop:
		data, err = []byte("{}"), nil
	case protos.OperationList:
		data, err = f.handleOpShowList()
	case protos.OperationAdd:
		data, err = f.handleOpAddDel(req.Rules, protos.OperationAdd, f.AddIPKey)
	case protos.OperationDel:
		data, err = f.handleOpAddDel(req.Rules, protos.OperationDel, f.DelIPKey)
	}
	if err != nil {
		return commands.ResponseError(client, err)
	}
	return commands.Response(client, &protos.MessageResp{Data: data})
}

func (f *Filter) handleOpShowList() ([]byte, error) {
	keys, err := f.List()
	if err != nil {
		return nil, err
	}
	resp := protos.FilterResp{Rules: []protos.FilterRule{{
		Interface: f.ifaceName,
		Keys:      keys,
	}}}
	return json.Marshal(&resp)
}

func (f *Filter) handleOpAddDel(rules []protos.FilterRule, op protos.Operation, handle func(key xdpprog.IPLpmKey) error) ([]byte, error) {
	for _, rule := range rules {
		for _, key := range rule.Keys {
			logrus.WithFields(logrus.Fields{"key": key, "iface": f.ifaceName, "op": op}).Debug("Operate ip lpm key")
			err := handle(key)
			if err != nil {
				return nil, err
			}
		}
	}
	return []byte("{}"), nil
}
