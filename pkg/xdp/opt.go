package xdp

import "golang.org/x/sys/unix"

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
		BindFlags:     XSKBindFlags(unix.XDP_USE_NEED_WAKEUP),
	}
}

type XDPOpt func(*xdpOpts)

// Umem Fill ring size
func WithFillSize(size uint32) XDPOpt {
	return func(o *xdpOpts) { o.FillSize = size }
}

// Umem Completion ring size
func WithCompSize(size uint32) XDPOpt {
	return func(o *xdpOpts) { o.CompSize = size }
}

// Umem Frame number
func WithFrameNum(n uint32) XDPOpt {
	return func(o *xdpOpts) { o.FrameNum = n }
}

// Umem Frame size
func WithFrameSize(size uint32) XDPOpt {
	return func(o *xdpOpts) { o.FrameSize = size }
}

// Umem Frame head room
func WithFrameHeadRoom(room uint32) XDPOpt {
	return func(o *xdpOpts) { o.FrameHeadRoom = room }
}

// Umem flags XDP_UMEM_UNALIGNED_CHUNK_FLAG
func WithUmemUnalignedChunk() XDPOpt {
	return func(o *xdpOpts) { o.UmemFlags |= unix.XDP_UMEM_UNALIGNED_CHUNK_FLAG }
}

// Shared umem
func WithSharedUmem(umem **XDPUmem) XDPOpt {
	return func(o *xdpOpts) { o.sharedUmemPtr = umem }
}

// XSK rx ring size
func WithRxSize(size uint32) XDPOpt {
	return func(o *xdpOpts) { o.RxSize = size }
}

// XSK tx ring size
func WithTxSize(size uint32) XDPOpt {
	return func(o *xdpOpts) { o.TxSize = size }
}

// XSK bind flags ~XDP_USE_NEED_WAKEUP
func WithNoNeedWakeup() XDPOpt {
	return func(o *xdpOpts) {
		o.BindFlags &= ^XSKBindFlags(unix.XDP_USE_NEED_WAKEUP)
	}
}

// XSK bind flags XDP_COPY
func WithCopy() XDPOpt {
	return func(o *xdpOpts) {
		o.BindFlags |= XSKBindFlags(unix.XDP_COPY)
		o.BindFlags &= ^XSKBindFlags(unix.XDP_ZEROCOPY)
	}
}

// XSK bind flags XDP_ZEROCOPY
func WithZeroCopy() XDPOpt {
	return func(o *xdpOpts) {
		o.BindFlags |= XSKBindFlags(unix.XDP_ZEROCOPY)
		o.BindFlags &= ^XSKBindFlags(unix.XDP_COPY)
	}
}
