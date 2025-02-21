package xdp

import (
	"fmt"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

type queue[T any] struct {
	mem        []byte
	cachedProd uint32
	cachedCons uint32
	mask       uint32
	size       uint32
	producer   *uint32
	consumer   *uint32
	flags      *uint32
	ring       []T
}

func (q *queue[T]) get(idx uint32) *T {
	return &q.ring[idx&q.mask]
}

func (q *queue[T]) format(name string) string {
	return fmt.Sprintf("%s(cached_prod:%d cached_cons:%d producer:%d consumer:%d)",
		name, q.cachedProd, q.cachedCons, atomic.LoadUint32(q.producer), atomic.LoadUint32(q.consumer))
}

// Producer queue
type prodQ[T any] queue[T]

func (q *prodQ[T]) raw() *queue[T] { return (*queue[T])(q) }

func (q *prodQ[T]) GetFreeNum(n uint32) uint32 {
	entries := q.cachedCons - q.cachedProd
	if entries >= n {
		return entries
	}
	q.cachedCons = atomic.LoadUint32(q.consumer)
	q.cachedCons += q.size
	return q.cachedCons - q.cachedProd
}

func (q *prodQ[T]) Reserve(n uint32, idx *uint32) uint32 {
	if q.GetFreeNum(n) < n {
		return 0
	}
	*idx = q.cachedProd
	q.cachedProd += n
	return n
}

func (q *prodQ[T]) Submit(n uint32) {
	atomic.StoreUint32(q.producer, *q.producer+n)
}

func (q *prodQ[T]) NeedWakeup() bool {
	return *q.flags&unix.XDP_RING_NEED_WAKEUP != 0
}

// Consumer queue
type consQ[T any] queue[T]

func (q *consQ[T]) raw() *queue[T] { return (*queue[T])(q) }

func (q *consQ[T]) GetAvailNum(n uint32) uint32 {
	entries := q.cachedProd - q.cachedCons
	if entries == 0 {
		q.cachedProd = atomic.LoadUint32(q.producer)
		entries = q.cachedProd - q.cachedCons
	}
	return min(entries, n)
}

func (q *consQ[T]) Peek(n uint32, idx *uint32) uint32 {
	entries := q.GetAvailNum(n)
	if entries > 0 {
		*idx = q.cachedCons
		q.cachedCons += entries
	}
	return entries
}

func (q *consQ[T]) Cancel(n uint32) {
	q.cachedCons -= n
}

func (q *consQ[T]) Release(n uint32) {
	atomic.StoreUint32(q.consumer, *q.consumer+n)
}

type FillQueue struct{ prodQ[uint64] }
type CompletionQueue struct{ consQ[uint64] }
type TxQueue struct{ prodQ[unix.XDPDesc] }
type RxQueue struct{ consQ[unix.XDPDesc] }

func (q *FillQueue) GetAddr(idx uint32) *uint64       { return q.raw().get(idx) }
func (q *CompletionQueue) GetAddr(idx uint32) *uint64 { return q.raw().get(idx) }
func (q *TxQueue) GetDesc(idx uint32) *unix.XDPDesc   { return q.raw().get(idx) }
func (q *RxQueue) GetDesc(idx uint32) *unix.XDPDesc   { return q.raw().get(idx) }

func (q *FillQueue) String() string       { return q.raw().format("FillQueue") }
func (q *CompletionQueue) String() string { return q.raw().format("CompletionQueue") }
func (q *TxQueue) String() string         { return q.raw().format("TxQueue") }
func (q *RxQueue) String() string         { return q.raw().format("RxQueue") }
