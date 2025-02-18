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
	opts xdpOpts

	sockfd           int
	umemFrameAddrs   []uint64 // Save fill/completion ring element or rx/tx desc.Addr
	umemFrameFreeNum uint32

	Umem *XDPUmem
	Rx   RxQueue
	Tx   TxQueue
}

func NewXDPSocket(ifIndex, queueID uint32, opts ...XDPOpt) (*XDPSocket, error) {
	o := XDPDefaultOpts()
	for _, opt := range opts {
		opt(&o)
	}

	// Check Rx/Tx ring size
	if bits.OnesCount32(o.RxSize) != 1 {
		return nil, wrapPowerOf2Error(o.RxSize, "invalid size of rx ring")
	}
	if bits.OnesCount32(o.TxSize) != 1 {
		return nil, wrapPowerOf2Error(o.TxSize, "invalid size of tx ring")
	}

	sockfd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, errors.Wrap(err, "unix.Socket")
	}

	umem, err := NewXDPUmem(sockfd, opts...)
	if err != nil {
		return nil, err
	}

	err = unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_RX_RING, int(o.RxSize))
	if err != nil {
		return nil, errors.Wrap(err, "unix.SetsockoptInt(XDP_RX_RING)")
	}
	err = unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_TX_RING, int(o.TxSize))
	if err != nil {
		return nil, errors.Wrap(err, "unix.SetsockoptInt(XDP_TX_RING)")
	}

	off, err := getXDPMmapOffsets(sockfd)
	if err != nil {
		return nil, err
	}

	// Create rx ring
	rxMem, err := unix.Mmap(sockfd, unix.XDP_PGOFF_RX_RING, int(off.Rx.Desc+uint64(o.RxSize)*sizeofXDPDesc),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return nil, errors.Wrap(err, "unix.Mmap(XDP_PGOFF_RX_RING)")
	}

	var rx RxQueue
	initQueueByOffset(rx.raw(), rxMem, &off.Rx, o.RxSize)
	rx.mask = o.RxSize - 1
	rx.size = o.RxSize
	rx.cachedProd = atomic.LoadUint32(rx.producer)
	rx.cachedCons = atomic.LoadUint32(rx.consumer)

	// Create tx ring
	txMem, err := unix.Mmap(sockfd, unix.XDP_PGOFF_TX_RING, int(off.Tx.Desc+uint64(o.TxSize)*sizeofXDPDesc),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return nil, errors.Wrap(err, "unix.Mmap(XDP_PGOFF_TX_RING)")
	}

	var tx TxQueue
	initQueueByOffset(tx.raw(), txMem, &off.Tx, o.TxSize)
	tx.mask = o.TxSize - 1
	tx.size = o.TxSize
	tx.cachedProd = atomic.LoadUint32(tx.producer)
	tx.cachedCons = atomic.LoadUint32(tx.consumer) + o.TxSize

	// Bind xdp socket
	err = unix.Bind(sockfd, &unix.SockaddrXDP{Flags: uint16(o.BindFlags), Ifindex: ifIndex, QueueID: queueID})
	if err != nil {
		return nil, errors.Wrap(err, "unix.Bind")
	}

	frames := []uint64{}
	for i := uint32(0); i < o.FrameNum; i++ {
		frames = append(frames, uint64(i*o.FrameSize))
	}

	return &XDPSocket{
		opts:             o,
		sockfd:           sockfd,
		umemFrameAddrs:   frames,
		umemFrameFreeNum: o.FrameNum,
		Umem:             umem,
		Rx:               rx,
		Tx:               tx,
	}, nil
}

func (x *XDPSocket) Close() error {
	unix.Close(x.sockfd)
	x.Umem.Close()
	unix.Munmap(x.Rx.mem)
	unix.Munmap(x.Tx.mem)
	return nil
}

func (x *XDPSocket) Opts() xdpOpts { return x.opts }

func (x *XDPSocket) SocketFd() int { return x.sockfd }

func (x *XDPSocket) AllocUmemFrame() uint64 {
	if x.umemFrameFreeNum == 0 {
		return INVALID_UMEM_FRAME
	}

	x.umemFrameFreeNum--
	frameAddr := x.umemFrameAddrs[x.umemFrameFreeNum]
	x.umemFrameAddrs[x.umemFrameFreeNum] = INVALID_UMEM_FRAME

	return frameAddr
}

func (x *XDPSocket) FreeUmemFrame(addr uint64) {
	x.umemFrameAddrs[x.umemFrameFreeNum] = addr
	x.umemFrameFreeNum++
}

func (x *XDPSocket) GetUmemFrameFreeNum() uint32 {
	return x.umemFrameFreeNum
}

func wrapPowerOf2Error(n uint32, msg string) error {
	return errors.Errorf("invalid %s %d, must be a power of 2", msg, n)
}
