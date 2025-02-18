package xdp

import (
	"fmt"
	"math/bits"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type XDPUmem struct {
	mem []byte

	Fill FillQueue
	Comp CompletionQueue

	opts xdpOpts
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
		return nil, wrapPowerOf2Error(o.FrameNum, "invalid number of frame")
	}
	if bits.OnesCount32(o.FillSize) != 1 {
		return nil, wrapPowerOf2Error(o.FillSize, "invalid size of fill ring")
	}
	if bits.OnesCount32(o.CompSize) != 1 {
		return nil, wrapPowerOf2Error(o.CompSize, "invalid size of compeletion ring")
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

	return &XDPUmem{
		mem:  area,
		Fill: fill,
		Comp: comp,
		opts: o,
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
