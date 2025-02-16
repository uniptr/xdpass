package bench

import (
	"net"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/pkg/netq"
	"github.com/zxhio/xdpass/pkg/xdp"
	"golang.org/x/sys/unix"
)

type TxOpt struct {
	BenchmarkOpt

	Packets int
	Batch   uint32
	Data    []byte // Prepare transmit data
}

type Tx interface {
	Transmit(*TxOpt)
	Wait(*TxOpt)
}

type afpTx struct {
	fd   int
	addr unix.SockaddrLinklayer
}

func newAFPTx(ifaceName string) (*afpTx, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, errors.Wrap(err, "net.InterfaceByName")
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, unix.ETH_P_ALL)
	if err != nil {
		return nil, errors.Wrap(err, "unix.Socket")
	}
	logrus.WithField("fd", fd).Info("New raw socket")

	return &afpTx{
		fd: fd,
		addr: unix.SockaddrLinklayer{
			Protocol: uint16(syscall.ETH_P_ALL),
			Ifindex:  iface.Index,
			Hatype:   1, // ARPHRD_ETHER
			Pkttype:  syscall.PACKET_OUTGOING,
		},
	}, nil
}

func (r *afpTx) Transmit(b *TxOpt) {
	for i := uint32(0); i < b.Batch; i++ {
		err := unix.Sendto(r.fd, b.Data, 0, &r.addr)
		if err != nil {
			b.stat.IOFailCount++
		} else {
			b.stat.Packets++
			b.stat.Bytes += uint64(b.Batch)
		}
		b.stat.IOCount++
	}
}

func (r *afpTx) Wait(b *TxOpt) {}

type xdpTx struct {
	*xdp.XDPSocket
	standing uint32
}

func newXDPTxList(ifaceName string, queueID int) ([]Tx, error) {
	var txList []Tx
	if queueID != -1 {
		tx, err := newXDPTx(ifaceName, uint32(queueID))
		if err != nil {
			return nil, err
		}
		txList = append(txList, tx)
	} else {
		queues, err := netq.GetTxQueues(ifaceName)
		if err != nil {
			return nil, err
		}

		for _, id := range queues {
			tx, err := newXDPTx(ifaceName, uint32(id))
			if err != nil {
				return nil, err
			}
			txList = append(txList, tx)
		}
	}
	return txList, nil
}

func newXDPTx(ifaceName string, queueId uint32) (*xdpTx, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, errors.Wrap(err, "net.InterfaceByName")
	}

	// For compatibility reasons, use SKB mode.
	s, err := xdp.NewXDPSocket(uint32(iface.Index), queueId, xdp.WithXDPBindFlags(unix.XDP_FLAGS_SKB_MODE))
	if err != nil {
		return nil, err
	}
	logrus.WithFields(logrus.Fields{"fd": s.SocketFd(), "queue_id": queueId}).Info("New xdp socket")

	return &xdpTx{XDPSocket: s}, nil
}

func (b *xdpTx) Transmit(opt *TxOpt) {
	var idx uint32
	for b.Tx.Reserve(opt.Batch, &idx) < opt.Batch {
		b.complete(opt)
		if *opt.done {
			return
		}
	}

	for i := uint32(0); i < opt.Batch; i++ {
		desc := b.Tx.GetDesc(idx + i)
		desc.Len = uint32(len(opt.Data))
		desc.Addr = b.AllocUmemFrame()
		copy(b.Umem.GetData(desc), opt.Data)
	}

	b.standing += opt.Batch
	b.Tx.Submit(opt.Batch)
	b.complete(opt)
}

func (b *xdpTx) complete(opt *TxOpt) {
	if b.standing == 0 {
		return
	}

	err := unix.Sendto(b.SocketFd(), nil, unix.MSG_DONTWAIT, nil)
	if err != nil {
		opt.stat.IOFailCount++
	}
	opt.stat.IOCount++

	var (
		idx       uint32
		completed uint32
	)
	completed = b.Umem.Comp.Peek(opt.Batch, &idx)
	if completed == 0 {
		return
	}
	for i := uint32(0); i < completed; i++ {
		opt.stat.Packets++
		opt.stat.Bytes += uint64(len(opt.Data))
		b.FreeUmemFrame(*b.Umem.Comp.GetAddr(idx + i))
	}
	b.Umem.Comp.Release(completed)
	b.standing -= completed
}

func (b *xdpTx) Wait(opt *TxOpt) {
	for b.standing != 0 {
		b.complete(opt)
		time.Sleep(time.Millisecond * 10)
	}
}
