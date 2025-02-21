package bench

import (
	"net"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/pkg/netutil"
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
	Fd() int
	QueueID() int
	Transmit(*TxOpt)
	Close() error
	Stats() netutil.Statistics
}

type afpTx struct {
	fd   int
	addr unix.SockaddrLinklayer
	stat netutil.Statistics
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

func (p *afpTx) Fd() int { return p.fd }

func (p *afpTx) QueueID() int { return -1 }

func (p *afpTx) Transmit(b *TxOpt) {
	for i := uint32(0); i < b.Batch; i++ {
		err := unix.Sendto(p.fd, b.Data, 0, &p.addr)
		if err != nil {
			p.stat.TxErrors++
		} else {
			p.stat.TxBytes += uint64(len(b.Data))
			p.stat.TxPackets++
		}
		p.stat.TxIOs++
	}
}

func (p *afpTx) Stats() netutil.Statistics {
	p.stat.Timestamp = time.Now()
	return p.stat
}

func (p *afpTx) Close() error {
	return unix.Close(p.fd)
}

type xdpTx struct {
	*xdp.XDPSocket
	// standing uint32
	dataVec [][]byte
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
		queues, err := netutil.GetTxQueues(ifaceName)
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
	s, err := xdp.NewXDPSocket(uint32(iface.Index), queueId)
	if err != nil {
		return nil, err
	}
	logrus.WithFields(logrus.Fields{"fd": s.SocketFD(), "queue_id": queueId}).Info("New xdp socket")

	return &xdpTx{XDPSocket: s}, nil
}

func (x *xdpTx) Fd() int {
	return x.SocketFD()
}

func (x *xdpTx) QueueID() int {
	return int(x.XDPSocket.QueueID())
}

func (x *xdpTx) Transmit(opt *TxOpt) {
	if len(x.dataVec) < int(opt.Batch) {
		x.dataVec = make([][]byte, opt.Batch)
		for i := uint32(0); i < opt.Batch; i++ {
			x.dataVec[i] = make([]byte, len(opt.Data))
			copy(x.dataVec[i], opt.Data)
		}
	}

	remain := opt.Batch
	for remain > 0 {
		n := x.Writev(x.dataVec)
		remain -= n
	}
}

func (x *xdpTx) Close() error {
	return x.XDPSocket.Close()
}
