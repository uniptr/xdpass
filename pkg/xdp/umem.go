package xdp

import (
	"fmt"
	"math/bits"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type XDPUmem struct {
	mem      []byte
	fd       int
	refCount uint32

	frameAddrs   []uint64 // Save fill/completion ring element or rx/tx desc.Addr
	frameFreeNum uint32

	Fill FillQueue
	Comp CompletionQueue
}

func NewXDPUmem(sockfd int, opts ...XDPOpt) (*XDPUmem, error) {
	o := XDPDefaultOpts()
	for _, opt := range opts {
		opt(&o)
	}

	// Check umem size valid
	if o.FrameSize != 2048 && o.FrameSize != 4096 {
		return nil, fmt.Errorf("invalid size of frame %d: must be either 2048 or 4096", o.FrameSize)
	}
	if bits.OnesCount32(o.FrameNum) != 1 {
		return nil, wrapPowerOf2Error(o.FrameNum, "frame number")
	}
	// Fill/Comp ring both must exist
	// See kernel net/xdp/xsk.c *xsk_bind* and *xsk_validate_queues*
	if bits.OnesCount32(o.FillSize) != 1 {
		return nil, wrapPowerOf2Error(o.FillSize, "fill ring")
	}
	if bits.OnesCount32(o.CompSize) != 1 {
		return nil, wrapPowerOf2Error(o.CompSize, "completion ring")
	}

	area, err := unix.Mmap(-1, 0, int(o.FrameNum*o.FrameSize),
		unix.PROT_READ|unix.PROT_WRITE, int(unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE|o.UmemFlags))
	if err != nil {
		return nil, errors.Wrap(err, "unix.Mmap(MAP_PRIVATE|MAP_ANONYMOUS)")
	}

	// Register umem
	err = registerUmem(sockfd, area, &o)
	if err != nil {
		return nil, errors.Wrap(err, "setsockopt(XDP_UMEM_REG)")
	}

	err = unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING, int(o.FillSize))
	if err != nil {
		return nil, errors.Wrap(err, "unix.SetsockoptInt(XDP_UMEM_FILL_RING)")
	}
	err = unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING, int(o.CompSize))
	if err != nil {
		return nil, errors.Wrap(err, "unix.SetsockoptInt(XDP_UMEM_COMPLETION_RING)")
	}

	off, err := getXDPMmapOffsets(sockfd)
	if err != nil {
		return nil, err
	}

	// Create fill ring
	fillMem, err := unix.Mmap(sockfd, unix.XDP_UMEM_PGOFF_FILL_RING, int(off.Fr.Desc+uint64(o.FillSize)*sizeofUint64),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return nil, errors.Wrap(err, "unix.Mmap(XDP_UMEM_PGOFF_FILL_RING)")
	}

	var fill FillQueue
	initQueueByOffset(fill.raw(), fillMem, &off.Fr, o.FillSize)
	fill.mask = o.FillSize - 1
	fill.size = o.FillSize
	fill.cachedCons = o.FillSize

	// Create comletion ring
	compMem, err := unix.Mmap(sockfd, unix.XDP_UMEM_PGOFF_COMPLETION_RING, int(off.Cr.Desc+uint64(o.CompSize)*sizeofUint64),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return nil, errors.Wrap(err, "unix.Mmap(XDP_UMEM_PGOFF_COMPLETION_RING)")
	}

	var comp CompletionQueue
	initQueueByOffset(comp.raw(), compMem, &off.Cr, o.CompSize)
	comp.mask = o.CompSize - 1
	comp.size = o.CompSize

	frames := []uint64{}
	for i := uint32(0); i < o.FrameNum; i++ {
		frames = append(frames, uint64(i*o.FrameSize))
	}

	return &XDPUmem{
		mem:          area,
		fd:           sockfd,
		frameAddrs:   frames,
		frameFreeNum: o.FrameNum,
		Fill:         fill,
		Comp:         comp,
	}, nil
}

func (x *XDPUmem) Close() error {
	unix.Munmap(x.mem)
	unix.Munmap(x.Fill.mem)
	unix.Munmap(x.Comp.mem)
	return nil
}

func (x *XDPUmem) GetData(desc *unix.XDPDesc) []byte {
	return x.mem[desc.Addr : desc.Addr+uint64(desc.Len)]
}

func (x *XDPUmem) AllocFrame() uint64 {
	if x.frameFreeNum == 0 {
		return INVALID_UMEM_FRAME
	}

	x.frameFreeNum--
	frameAddr := x.frameAddrs[x.frameFreeNum]
	x.frameAddrs[x.frameFreeNum] = INVALID_UMEM_FRAME

	return frameAddr
}

func (x *XDPUmem) FreeFrame(addr uint64) {
	x.frameAddrs[x.frameFreeNum] = addr
	x.frameFreeNum++
}

func (x *XDPUmem) GetFrameFreeNum() uint32 {
	return x.frameFreeNum
}
