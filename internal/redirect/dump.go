package redirect

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/xdp"
)

var (
	rxDataPool2048 = sync.Pool{New: func() any { return new([2048]byte) }}
	rxDataPool4096 = sync.Pool{New: func() any { return new([4096]byte) }}
)

func rxDataPool2048Get(p *sync.Pool) []byte    { return p.Get().(*[2048]byte)[:] }
func rxDataPool4096Get(p *sync.Pool) []byte    { return p.Get().(*[4096]byte)[:] }
func rxDataPool2048Put(p *sync.Pool, b []byte) { p.Put((*[2048]byte)(unsafe.Pointer(&b[0]))) }
func rxDataPool4096Put(p *sync.Pool, b []byte) { p.Put((*[4096]byte)(unsafe.Pointer(&b[0]))) }

type DumpHandle struct {
	rxDataPool    *sync.Pool
	rxDataPoolGet func(*sync.Pool) []byte
	rxDataPoolPut func(*sync.Pool, []byte)
	rxDataCh      chan []byte
	id            uint64 // id of the handle
	refCount      uint32 // ref count of the handle
	mu            *sync.RWMutex
	hooks         map[uint64]func([]byte)
}

func NewDumpHandle(frameSize int) (*DumpHandle, error) {
	var (
		rxDataPool    *sync.Pool
		rxDataPoolGet func(*sync.Pool) []byte
		rxDataPoolPut func(*sync.Pool, []byte)
	)
	switch frameSize {
	case xdp.UmemFrameSize2048:
		rxDataPool = &rxDataPool2048
		rxDataPoolGet = rxDataPool2048Get
		rxDataPoolPut = rxDataPool2048Put
	case xdp.UmemFrameSize4096:
		rxDataPool = &rxDataPool4096
		rxDataPoolGet = rxDataPool4096Get
		rxDataPoolPut = rxDataPool4096Put
	default:
		return nil, fmt.Errorf("invalid frame size: %d", frameSize)
	}

	h := &DumpHandle{
		rxDataPool:    rxDataPool,
		rxDataPoolGet: rxDataPoolGet,
		rxDataPoolPut: rxDataPoolPut,
		rxDataCh:      make(chan []byte, 1024),
		mu:            &sync.RWMutex{},
		hooks:         make(map[uint64]func([]byte)),
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
		h.rxDataPoolPut(h.rxDataPool, data)
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
	rxData := h.rxDataPoolGet(h.rxDataPool)[:len(data.RxData)]
	copy(rxData, data.RxData)
	h.rxDataCh <- rxData
}
