package fw

import (
	"errors"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/zxhio/xdpass/pkg/xdpprog"
)

type Firewall struct {
	ifaceName string
	trie      *ebpf.Map
	keys      map[xdpprog.IPLpmKey]struct{}
	mu        *sync.Mutex
}

func NewFirewall(ifaceName string, trie *ebpf.Map) *Firewall {
	return &Firewall{
		ifaceName: ifaceName,
		trie:      trie,
		keys:      make(map[xdpprog.IPLpmKey]struct{}),
		mu:        &sync.Mutex{},
	}
}

func (f *Firewall) AddIPKey(key xdpprog.IPLpmKey) error {
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

func (f *Firewall) DelIPKey(key xdpprog.IPLpmKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	err := f.trie.Delete(&key)
	if err != nil {
		return err
	}
	delete(f.keys, key)
	return nil
}

func (f *Firewall) ListIPKey() ([]xdpprog.IPLpmKey, error) {
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
