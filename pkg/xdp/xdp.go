package xdp

import (
	"math"
	"math/bits"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/zxhio/xdpass/pkg/netutil"
	"golang.org/x/sys/unix"
)

const (
	ConsRingDefaultDescs     = 2048 // For Rx/Completion queue
	ProdRingDefaultDescs     = 2048 // For Tx/Fill queue
	UmemDefaultFrameNum      = 4096
	UmemDefaultFrameSize     = 4096
	UmemDefaultFrameHeadroom = 0
	UmemDefaultFlags         = 0

	INVALID_UMEM_FRAME = math.MaxUint64
)

type xdpOpts struct {
	// Umem opts
	FillSize      uint32
	CompSize      uint32
	FrameNum      uint32
	FrameSize     uint32
	FrameHeadRoom uint32
	UmemFlags     uint32

	// Shared umem
	sharedUmemPtr **XDPUmem

	// Rx/Tx opts
	RxSize uint32
	TxSize uint32

	// Flags
	BindFlags XSKBindFlags
}

func XDPDefaultOpts() xdpOpts {
	return xdpOpts{
		FillSize:      ProdRingDefaultDescs,
		CompSize:      ConsRingDefaultDescs,
		FrameNum:      UmemDefaultFrameNum,
		FrameSize:     UmemDefaultFrameSize,
		FrameHeadRoom: UmemDefaultFrameHeadroom,
		RxSize:        ConsRingDefaultDescs,
		TxSize:        ProdRingDefaultDescs,
	}
}

type XDPOpt func(*xdpOpts)

func WithXDPUmemRing(fillSize, compSize uint32) XDPOpt {
	return func(o *xdpOpts) {
		o.FillSize = fillSize
		o.CompSize = compSize
	}
}

func WithXDPUmemFrame(frameNum, frameSize, frameHeadRoom uint32) XDPOpt {
	return func(o *xdpOpts) {
		o.FrameNum = frameNum
		o.FrameSize = frameSize
		o.FrameHeadRoom = frameHeadRoom
	}
}

func WithXDPUmemFlags(umemFlags uint32) XDPOpt {
	return func(o *xdpOpts) { o.UmemFlags = umemFlags }
}

func WithXDPSharedUmem(umem **XDPUmem) XDPOpt {
	return func(o *xdpOpts) { o.sharedUmemPtr = umem }
}

func WithXDPRxTx(rxSize, txSize uint32) XDPOpt {
	return func(o *xdpOpts) {
		o.RxSize = rxSize
		o.TxSize = txSize
	}
}

func WithXDPBindFlags(bindFlags XSKBindFlags) XDPOpt {
	return func(o *xdpOpts) { o.BindFlags = bindFlags }
}

type XDPSocket struct {
	sockfd  int
	queueID uint32

	umem *XDPUmem
	rx   RxQueue
	tx   TxQueue

	// for tx
	standing uint32
	stats    netutil.Statistics
}

// NewXDPSocket create a new xdp socket
//
// Note(queue):
//
//	Each xsk can only be bound to one queue
//
// Note(umem):
//
//	The idea is to share the same umem, fill ring, and completion ring for multiple
//	sockets. The sockets sharing that umem/fr/cr are tied (bound) to one
//	hardware ring.
//
// Ref:
//
//	https://marc.info/?l=xdp-newbies&m=158399973616672&w=2
func NewXDPSocket(ifIndex, queueID uint32, opts ...XDPOpt) (*XDPSocket, error) {
	o := XDPDefaultOpts()
	for _, opt := range opts {
		opt(&o)
	}

	// Check Rx/Tx ring size, allow use one ring.
	if bits.OnesCount32(o.RxSize) != 1 && o.RxSize != 0 {
		return nil, wrapPowerOf2Error(o.RxSize, "invalid size of rx ring")
	}
	if bits.OnesCount32(o.TxSize) != 1 && o.TxSize != 0 {
		return nil, wrapPowerOf2Error(o.TxSize, "invalid size of tx ring")
	}
	if o.RxSize == 0 && o.TxSize == 0 {
		return nil, errors.New("invalid size, both rx/tx rings are 0")
	}

	sockfd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, errors.Wrap(err, "unix.Socket")
	}

	var umem *XDPUmem
	if o.sharedUmemPtr != nil && *o.sharedUmemPtr != nil {
		umem = *o.sharedUmemPtr
	} else {
		umem, err = NewXDPUmem(sockfd, opts...)
		if err != nil {
			return nil, err
		}
		if o.sharedUmemPtr != nil && *o.sharedUmemPtr == nil {
			*o.sharedUmemPtr = umem
		}
	}

	off, err := getXDPMmapOffsets(sockfd)
	if err != nil {
		return nil, err
	}

	// Create rx ring
	var rx RxQueue
	if o.RxSize != 0 {
		err = unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_RX_RING, int(o.RxSize))
		if err != nil {
			return nil, errors.Wrap(err, "unix.SetsockoptInt(XDP_RX_RING)")
		}

		rxMem, err := unix.Mmap(sockfd, unix.XDP_PGOFF_RX_RING, int(off.Rx.Desc+uint64(o.RxSize)*sizeofXDPDesc),
			unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			return nil, errors.Wrap(err, "unix.Mmap(XDP_PGOFF_RX_RING)")
		}

		initQueueByOffset(rx.raw(), rxMem, &off.Rx, o.RxSize)
		rx.mask = o.RxSize - 1
		rx.size = o.RxSize
		rx.cachedProd = atomic.LoadUint32(rx.producer)
		rx.cachedCons = atomic.LoadUint32(rx.consumer)
	}

	// Create tx ring
	var tx TxQueue
	if o.TxSize != 0 {
		err = unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_TX_RING, int(o.TxSize))
		if err != nil {
			return nil, errors.Wrap(err, "unix.SetsockoptInt(XDP_TX_RING)")
		}

		txMem, err := unix.Mmap(sockfd, unix.XDP_PGOFF_TX_RING, int(off.Tx.Desc+uint64(o.TxSize)*sizeofXDPDesc),
			unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			return nil, errors.Wrap(err, "unix.Mmap(XDP_PGOFF_TX_RING)")
		}

		initQueueByOffset(tx.raw(), txMem, &off.Tx, o.TxSize)
		tx.mask = o.TxSize - 1
		tx.size = o.TxSize
		tx.cachedProd = atomic.LoadUint32(tx.producer)
		tx.cachedCons = atomic.LoadUint32(tx.consumer) + o.TxSize
	}

	// Bind xdp socket
	addr := &unix.SockaddrXDP{Ifindex: ifIndex, QueueID: queueID}
	if umem.refCount > 0 {
		// Cannot specify flags for shared sockets.
		// See kernel source tree net/xdp/xsk.c *xsk_bind* implement
		addr.Flags = unix.XDP_SHARED_UMEM
		addr.SharedUmemFD = uint32(umem.fd)
	} else {
		addr.Flags = uint16(o.BindFlags)
	}

	err = unix.Bind(sockfd, addr)
	if err != nil {
		return nil, errors.Wrap(err, "unix.Bind")
	}
	umem.refCount++

	return &XDPSocket{
		sockfd:  sockfd,
		queueID: queueID,
		umem:    umem,
		rx:      rx,
		tx:      tx,
	}, nil
}

func (x *XDPSocket) Close() error {
	// Complete all pending tx
	x.completeAll()

	unix.Close(x.sockfd)
	if x.umem.refCount == 1 {
		x.umem.Close()
	}
	x.umem.refCount--
	unix.Munmap(x.rx.mem)
	unix.Munmap(x.tx.mem)
	return nil
}

func (x *XDPSocket) SocketFd() int { return x.sockfd }

func (x *XDPSocket) QueueID() uint32 { return x.queueID }

// Stats returns the statistics copy of the socket
func (x *XDPSocket) Stats() netutil.Statistics {
	x.stats.Timestamp = time.Now()
	return x.stats
}

// Peek at RX non-blockingly and copy data to vec
// Return iovec read count
func (x *XDPSocket) Readv(iovs [][]byte) uint32 {
	x.stuffFillQ()

	var idx uint32
	n := x.rx.Peek(uint32(len(iovs)), &idx)
	if n == 0 {
		return 0
	}

	x.stats.RxIOs++
	for i := uint32(0); i < n; i++ {
		desc := x.rx.GetDesc(idx + i)
		copy(iovs[i], x.umem.GetData(desc))
		x.umem.FreeFrame(desc.Addr)

		x.stats.RxPackets++
		x.stats.RxBytes += uint64(desc.Len)
	}
	x.rx.Release(n)

	return n
}

// Reserve non-blockingly and copy data to TX
// Return iovec written count
func (x *XDPSocket) Writev(iovs [][]byte) uint32 {
	idx := uint32(0)
	batch := uint32(len(iovs))

	if x.tx.Reserve(batch, &idx) < batch {
		x.complete()
		return 0
	}

	for i := uint32(0); i < batch; i++ {
		desc := x.tx.GetDesc(idx + i)
		desc.Len = uint32(len(iovs[i]))
		desc.Addr = x.umem.AllocFrame()
		copy(x.umem.GetData(desc), iovs[i])

		x.stats.TxPackets++
		x.stats.TxBytes += uint64(desc.Len)
	}

	x.standing += batch
	x.tx.Submit(batch)
	x.complete()

	return batch
}

func (x *XDPSocket) stuffFillQ() {
	frames := x.umem.Fill.GetFreeNum(x.umem.GetFrameFreeNum())
	if frames == 0 {
		return
	}

	var idx uint32
	x.umem.Fill.Reserve(frames, &idx)

	for i := uint32(0); i < frames; i++ {
		*x.umem.Fill.GetAddr(idx) = x.umem.AllocFrame()
	}
	x.umem.Fill.Submit(frames)
}

func (x *XDPSocket) complete() {
	if x.standing == 0 {
		return
	}

	err := unix.Sendto(x.sockfd, nil, unix.MSG_DONTWAIT, nil)
	if err != nil {
		x.stats.TxErrors++
	}
	x.stats.TxIOs++

	var (
		idx       uint32
		completed uint32
	)
	completed = x.umem.Comp.Peek(x.standing, &idx)
	if completed == 0 {
		return
	}
	for i := uint32(0); i < completed; i++ {
		x.umem.FreeFrame(*x.umem.Comp.GetAddr(idx + i))
	}
	x.umem.Comp.Release(completed)
	x.standing -= completed
}

func (x *XDPSocket) completeAll() {
	retries := max(x.standing/64, 1)
	for x.standing != 0 && retries > 0 {
		x.complete()
		time.Sleep(time.Millisecond * 10)
		retries--
	}
}

func wrapPowerOf2Error(n uint32, msg string) error {
	return errors.Errorf("invalid %s %d, must be a power of 2", msg, n)
}
