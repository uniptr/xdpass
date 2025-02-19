package xdp

import (
	"math"
	"math/bits"
	"sync/atomic"

	"github.com/pkg/errors"
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

	Umem *XDPUmem
	Rx   RxQueue
	Tx   TxQueue
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
		sockfd: sockfd,
		Umem:   umem,
		Rx:     rx,
		Tx:     tx,
	}, nil
}

func (x *XDPSocket) Close() error {
	unix.Close(x.sockfd)
	if x.Umem.refCount == 1 {
		x.Umem.Close()
	}
	x.Umem.refCount--
	unix.Munmap(x.Rx.mem)
	unix.Munmap(x.Tx.mem)
	return nil
}

func (x *XDPSocket) SocketFd() int { return x.sockfd }

func (x *XDPSocket) QueueID() uint32 { return x.queueID }

func wrapPowerOf2Error(n uint32, msg string) error {
	return errors.Errorf("invalid %s %d, must be a power of 2", msg, n)
}
