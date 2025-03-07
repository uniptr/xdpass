package internal

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/commands/redirectcmd"
	"github.com/zxhio/xdpass/internal/firewall"
	"github.com/zxhio/xdpass/internal/redirect"
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/netutil"
	"github.com/zxhio/xdpass/pkg/utils"
	"github.com/zxhio/xdpass/pkg/xdp"
	"github.com/zxhio/xdpass/pkg/xdpprog"
	"golang.org/x/sys/unix"
)

type linkHandleOpts struct {
	queueID     int
	attachMode  xdp.XDPAttachMode
	xdpOpts     []xdp.XDPOpt
	pollTimeout int
	cores       []int
}

type LinkHandleOpt func(*linkHandleOpts)

func WithLinkQueueID(queueID int) LinkHandleOpt {
	return func(o *linkHandleOpts) { o.queueID = queueID }
}

func WithLinkXDPFlags(attachMode xdp.XDPAttachMode, opts ...xdp.XDPOpt) LinkHandleOpt {
	return func(o *linkHandleOpts) {
		o.attachMode = attachMode
		o.xdpOpts = opts
	}
}

func WithLinkHandleTimeout(timeout int) LinkHandleOpt {
	return func(o *linkHandleOpts) { o.pollTimeout = timeout }
}

func WithLinkHandleCores(cores []int) LinkHandleOpt {
	return func(o *linkHandleOpts) { o.cores = cores }
}

type LinkHandle struct {
	*linkHandleOpts
	*xdpprog.Objects
	xsks     []*xdp.XDPSocket
	firewall *firewall.Firewall
	redirect *redirect.Redirect
	stats    *Stats
	server   *commands.MessageServer
	closers  utils.NamedClosers
}

func NewLinkHandle(name string, opts ...LinkHandleOpt) (*LinkHandle, error) {
	var o linkHandleOpts
	for _, opt := range opts {
		opt(&o)
	}

	l := logrus.WithField("name", name)

	ifaceLink, err := netlink.LinkByName(name)
	if err != nil {
		return nil, errors.Wrap(err, "netlink.LinkByName")
	}
	l.WithFields(logrus.Fields{
		"name": ifaceLink.Attrs().Name, "index": ifaceLink.Attrs().Index,
		"num_rx": ifaceLink.Attrs().NumRxQueues, "num_tx": ifaceLink.Attrs().NumTxQueues,
	}).Info("Found link")

	objs, err := xdpprog.LoadObjects(nil)
	if err != nil {
		return nil, err
	}
	closers := utils.NamedClosers{{Name: "xdpprog.Objects", Close: objs.Close}}

	// Attach xdp program
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRedirectXskProg,
		Interface: ifaceLink.Attrs().Index,
		Flags:     link.XDPAttachFlags(o.attachMode),
	})
	if err != nil {
		closers.Close(nil)
		return nil, errors.Wrap(err, "link.AttachXDP")
	}
	closers = append(closers, utils.NamedCloser{Name: "ebpf.Link", Close: xdpLink.Close})
	l.WithField("flags", o.attachMode).Info("Attached xdp prog")

	info, err := xdpLink.Info()
	if err != nil {
		l.WithError(err).Warn("Fail to get xdp link info")
	} else {
		l.WithFields(logrus.Fields{"id": info.ID, "type": info.Type, "prog": info.Program}).Info("Get xdp link info")
	}

	// Generate xdp socket per queue
	queues, err := netutil.GetRxQueues(name)
	if err != nil {
		return nil, err
	}
	l.WithField("queues", queues).Info("Get rx queues")

	var xsks []*xdp.XDPSocket
	for _, queueID := range queues {
		s, err := xdp.NewXDPSocket(uint32(ifaceLink.Attrs().Index), uint32(queueID), append(o.xdpOpts, xdp.WithFrameSize(2048))...)
		if err != nil {
			return nil, err
		}

		closers = append(closers, utils.NamedCloser{Name: fmt.Sprintf("xdp.XDPSocket(fd:%d queue:%d)", s.SocketFD(), queueID), Close: s.Close})
		xsks = append(xsks, s)
		l.WithFields(logrus.Fields{"fd": s.SocketFD(), "queue_id": queueID}).Info("New xdp socket")

		// Update xsk map
		// Note: xsk map not support lookup element
		// See kernel tree net/xdp/xdpmap.c *xsk_map_lookup_elem_sys_only* implement
		err = objs.XskMap.Update(uint32(queueID), uint32(s.SocketFD()), 0)
		if err != nil {
			closers.Close(nil)
			return nil, errors.Wrap(err, "XskMap.Update")
		}
		l.WithFields(logrus.Fields{"k": queueID, "v": s.SocketFD()}).Info("Update xsk map")
	}

	firewall, err := firewall.NewFirewall()
	if err != nil {
		closers.Close(nil)
		return nil, err
	}
	firewall.Add(name, objs.IpLpmTrie)
	l.Info("New firewall")

	redirect, err := redirect.NewRedirect(name)
	if err != nil {
		closers.Close(nil)
		return nil, err
	}
	closers = append(closers, utils.NamedCloser{Name: "redirect.Redirect", Close: redirect.Close})
	l.Info("New redirect")

	stats := &Stats{xsks: xsks}

	// TODO: add address option
	server, err := commands.NewMessageServer(commands.DefUnixSock, firewall, stats, redirectcmd.RedirectCommand{})
	if err != nil {
		closers.Close(nil)
		return nil, err
	}
	closers = append(closers, utils.NamedCloser{Name: "cmdconn.Server", Close: server.Close})

	return &LinkHandle{
		linkHandleOpts: &o,
		xsks:           xsks,
		Objects:        objs,
		firewall:       firewall,
		redirect:       redirect,
		stats:          &Stats{xsks: xsks},
		server:         server,
		closers:        closers,
	}, nil
}

func (x *LinkHandle) Close() error {
	x.closers.Close(nil)
	return nil
}

type xskGroup struct {
	xsks []*xdp.XDPSocket
	core int
}

func (x *LinkHandle) Run(ctx context.Context) error {
	done := false
	go func() {
		<-ctx.Done()
		done = true
	}()

	// Close in r.closers, not use ctx args
	go x.server.Serve(context.Background())

	var xskGroups []*xskGroup
	cores := x.cores[:min(len(x.xsks), len(x.cores))]
	for _, core := range cores {
		xskGroups = append(xskGroups, &xskGroup{core: core})
	}
	for k, xsk := range x.xsks {
		xskGroups[k%len(xskGroups)].xsks = append(xskGroups[k%len(xskGroups)].xsks, xsk)
	}

	wg := sync.WaitGroup{}
	wg.Add(len(xskGroups))

	for _, xg := range xskGroups {
		go func(g *xskGroup) {
			defer wg.Done()

			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			l := logrus.WithField("tid", unix.Gettid())
			if g.core != -1 {
				setAffinityCPU(g.core)
				l = l.WithField("affinity_core", g.core)
			}
			l.Info("Start xsk group")

			// TODO: use option vec size
			numRxTxData := 64
			rxDataVec := make([][]byte, numRxTxData)
			txDataVec := make([][]byte, numRxTxData)
			tmpTxDataVec := make([][]byte, numRxTxData)
			pkts := make([]*fastpkt.Packet, numRxTxData)
			for i := 0; i < numRxTxData; i++ {
				rxDataVec[i] = make([]byte, xdp.UmemDefaultFrameSize)
				txDataVec[i] = make([]byte, xdp.UmemDefaultFrameSize)
				pkts[i] = &fastpkt.Packet{RxData: rxDataVec[i], TxData: txDataVec[i]}
			}

			for !done {
				err := x.waitPoll()
				if err != nil {
					continue
				}
				for _, xsk := range g.xsks {
					for i := 0; i < numRxTxData; i++ {
						pkts[i].Clear()
						pkts[i].RxData = rxDataVec[i]
						pkts[i].TxData = txDataVec[i][:0]
					}
					x.handleXSK(xsk, rxDataVec, tmpTxDataVec, pkts)
				}
			}
		}(xg)
	}
	wg.Wait()

	return nil
}

func (x *LinkHandle) handleXSK(xsk *xdp.XDPSocket, rxDataVec, tmpTxDataVec [][]byte, pkts []*fastpkt.Packet) {
	n := xsk.Readv(rxDataVec)
	if n == 0 {
		return
	}

	txIdx := 0
	for i := uint32(0); i < n; i++ {
		err := pkts[i].DecodeFromData(rxDataVec[i])
		if err != nil {
			continue
		}
		x.redirect.HandlePacket(pkts[i])
		if len(pkts[i].TxData) > 0 {
			tmpTxDataVec[txIdx] = pkts[i].TxData
			txIdx++
		}
	}
	if txIdx > 0 {
		xsk.Writev(tmpTxDataVec[:txIdx])
	}
}

func (x *LinkHandle) waitPoll() error {
	if x.pollTimeout == 0 {
		return nil
	}

	fds := []unix.PollFd{}
	for _, xsk := range x.xsks {
		fds = append(fds, unix.PollFd{Fd: int32(xsk.SocketFD()), Events: unix.POLLIN})
	}
	_, err := unix.Poll(fds, x.pollTimeout)
	if err != nil {
		if errors.Is(err, unix.EINTR) {
			return nil
		}
		return errors.Wrap(err, "unix.Poll")
	}
	return nil
}

func setAffinityCPU(cpu int) error {
	var s unix.CPUSet
	s.Zero()
	s.Set(cpu)
	return unix.SchedSetaffinity(0, &s)
}
