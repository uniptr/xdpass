package firewall

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
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
func (f *Filter) HandleReqData(data []byte) ([]byte, error) {
	var req protos.FilterReq
	err := json.Unmarshal(data, &req)
	if err != nil {
		return nil, err
	}

	if req.Show {
		return f.handleCommandShow()
	}

	for _, key := range req.AddKeys {
		logrus.WithField("key", key).Info("Add lpm key")
		err = f.AddIPKey(key)
		if err != nil {
			return nil, err
		}
	}

	for _, key := range req.DelKeys {
		logrus.WithField("key", key).Info("Del lpm key")
		err = f.DelIPKey(key)
		if err != nil {
			return nil, err
		}
	}

	return nil, nil
}

func (f *Filter) handleCommandShow() ([]byte, error) {
	keys, err := f.List()
	if err != nil {
		return nil, err
	}
	resp := protos.FilterResp{InterfacesKeys: []protos.FilterInterfaceKeys{{
		Interface: f.ifaceName,
		Keys:      keys,
	}}}
	return json.Marshal(&resp)
}
