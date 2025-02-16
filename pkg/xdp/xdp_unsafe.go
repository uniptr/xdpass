package xdp

import (
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

var (
	sizeofUint64  = uint64(unsafe.Sizeof(uint64(0)))
	sizeofXDPDesc = uint64(unsafe.Sizeof(unix.XDPDesc{}))
)

func initQueueByOffset[T any](q *queue[T], data []byte, off *unix.XDPRingOffset, size uint32) {
	q.mem = data
	q.producer = (*uint32)(unsafe.Pointer(&data[off.Producer]))
	q.consumer = (*uint32)(unsafe.Pointer(&data[off.Consumer]))
	q.flags = (*uint32)(unsafe.Pointer(&data[off.Flags]))
	q.ring = unsafe.Slice((*T)(unsafe.Pointer(&data[off.Desc])), size)
}

func registerUmem(sockfd int, area []byte, o *xdpOpts) error {
	reg := unix.XDPUmemReg{
		Addr:     uint64(uintptr(unsafe.Pointer(unsafe.SliceData(area)))),
		Len:      uint64(len(area)),
		Size:     o.FrameSize,
		Headroom: o.FrameHeadRoom,
		Flags:    o.UmemFlags,
	}
	return setsockopt(sockfd, unix.SOL_XDP, unix.XDP_UMEM_REG, unsafe.Pointer(&reg), unsafe.Sizeof(reg))
}

func getXDPMmapOffsets(fd int) (*unix.XDPMmapOffsets, error) {
	off := unix.XDPMmapOffsets{}
	len := uint32(unsafe.Sizeof(off))

	err := getsockopt(fd, unix.SOL_XDP, unix.XDP_MMAP_OFFSETS, unsafe.Pointer(&off), &len)
	return &off, errors.Wrap(err, "getsockopt(XDP_MMAP_OFFSETS)")
}

func getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *uint32) (err error) {
	_, _, e1 := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error) {
	_, _, e1 := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(vallen), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case unix.EAGAIN:
		return unix.EAGAIN
	case unix.EINVAL:
		return unix.EINVAL
	case unix.ENOENT:
		return unix.ENOENT
	}
	return e
}
