package dump

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/fastpkt"
)

type DumpHandle struct {
	rxDataPool *sync.Pool
	rxDataCh   chan []byte
	id         uint64 // id of the handle
	refCount   uint32 // ref count of the handle
	mu         *sync.RWMutex
	hooks      map[uint64]func([]byte)
}

func NewDumpHandle() (*DumpHandle, error) {
	h := &DumpHandle{
		rxDataPool: &sync.Pool{
			New: func() any {
				return make([]byte, 2048)
			},
		},
		rxDataCh: make(chan []byte, 1024),
		mu:       &sync.RWMutex{},
		hooks:    make(map[uint64]func([]byte)),
	}
	go h.txLoop()
	return h, nil
}

func (DumpHandle) RedirectType() protos.RedirectType {
	return protos.RedirectTypeDump
}

func (h *DumpHandle) Close() error {
	close(h.rxDataCh)
	return nil
}

func (h *DumpHandle) txLoop() bool {
	for data := range h.rxDataCh {
		h.mu.RLock()
		for _, hook := range h.hooks {
			hook(data)
		}
		h.mu.RUnlock()
	}
	return true
}

func (h *DumpHandle) KeepPacketHook(ctx context.Context, fn func([]byte)) {
	h.mu.Lock()
	h.id++
	hookId := h.id
	h.hooks[hookId] = fn
	atomic.AddUint32(&h.refCount, 1)
	h.mu.Unlock()

	<-ctx.Done()

	h.mu.Lock()
	delete(h.hooks, hookId)
	atomic.AddUint32(&h.refCount, ^uint32(0))
	h.mu.Unlock()
}

func (h *DumpHandle) HandlePacket(data *fastpkt.Packet) {
	if atomic.LoadUint32(&h.refCount) == 0 {
		return
	}
	rxData := h.rxDataPool.Get().([]byte)[:len(data.RxData)]
	copy(rxData, data.RxData)
	h.rxDataCh <- rxData
}
