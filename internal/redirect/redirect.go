package redirect

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/zxhio/xdpass/internal/commands/cmdconn"
	"github.com/zxhio/xdpass/internal/firewall"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/handle"
	"github.com/zxhio/xdpass/internal/redirect/spoof"
	"github.com/zxhio/xdpass/internal/stats"
	"github.com/zxhio/xdpass/pkg/netq"
	"github.com/zxhio/xdpass/pkg/utils"
	"github.com/zxhio/xdpass/pkg/xdp"
	"github.com/zxhio/xdpass/pkg/xdpprog"
	"golang.org/x/sys/unix"
)

type redirectOpts struct {
	queueID      int
	attachMode   xdp.XDPAttachMode
	xskBindFlags xdp.XSKBindFlags
	pollTimeout  int
}

type RedirectOpt func(*redirectOpts)

func WithRedirectQueueID(queueID int) RedirectOpt {
	return func(o *redirectOpts) { o.queueID = queueID }
}

func WithRedirectXDPFlags(attachMode xdp.XDPAttachMode, xdkBindFlags xdp.XSKBindFlags) RedirectOpt {
	return func(o *redirectOpts) {
		o.attachMode = attachMode
		o.xskBindFlags = xdkBindFlags
	}
}

func WithRedirectPollTimeout(timeout int) RedirectOpt {
	return func(o *redirectOpts) { o.pollTimeout = timeout }
}

type Redirect struct {
	*redirectOpts

	*xdpprog.Objects
	xsks    []*xdp.XDPSocket
	filter  *firewall.Filter
	server  *cmdconn.TLVServer
	handles map[protos.RedirectType]handle.RedirectHandle
	closers utils.NamedClosers
}

func NewRedirect(ifaceName string, opts ...RedirectOpt) (*Redirect, error) {
	var o redirectOpts
	for _, opt := range opts {
		opt(&o)
	}

	ifaceLink, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, errors.Wrap(err, "netlink.LinkByName")
	}
	logrus.WithFields(logrus.Fields{
		"name": ifaceLink.Attrs().Name, "index": ifaceLink.Attrs().Index,
		"num_rx": ifaceLink.Attrs().NumRxQueues, "num_tx": ifaceLink.Attrs().NumTxQueues,
	}).Info("Found link")

	var closers utils.NamedClosers

	objs, err := xdpprog.LoadObjects(nil)
	if err != nil {
		closers.Close(nil)
		return nil, err
	}
	closers = append(closers, utils.NamedCloser{Name: "xdpprog.Objects", Close: objs.Close})

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
	logrus.WithField("flags", o.attachMode).Info("Attached xdp prog")

	info, err := xdpLink.Info()
	if err != nil {
		logrus.WithError(err).Warn("Fail to get xdp link info")
	} else {
		logrus.WithFields(logrus.Fields{"id": info.ID, "type": info.Type, "prog": info.Program}).Info("Get xdp link info")
	}

	queues, err := netq.GetRxQueues(ifaceName)
	if err != nil {
		return nil, err
	}
	logrus.WithField("queues", queues).Info("Get rx queues")

	var xsks []*xdp.XDPSocket
	for _, queueID := range queues {
		s, err := xdp.NewXDPSocket(uint32(ifaceLink.Attrs().Index), uint32(queueID), xdp.WithXDPBindFlags(o.xskBindFlags))
		if err != nil {
			return nil, err
		}

		closers = append(closers, utils.NamedCloser{Name: fmt.Sprintf("xdp.XDPSocket(fd:%d queue:%d)", s.SocketFd(), queueID), Close: s.Close})
		xsks = append(xsks, s)
		logrus.WithFields(logrus.Fields{"fd": s.SocketFd(), "queue_id": queueID}).Info("New xdp socket")

		// Update xsk map
		// Note: xsk map not support lookup element
		// See kernel tree net/xdp/xdpmap.c *xsk_map_lookup_elem_sys_only* implement
		err = objs.XskMap.Update(uint32(queueID), uint32(s.SocketFd()), 0)
		if err != nil {
			closers.Close(nil)
			return nil, errors.Wrap(err, "XskMap.Update")
		}
		logrus.WithFields(logrus.Fields{"k": queueID, "v": s.SocketFd()}).Info("Update xsk map")
	}

	filter, err := firewall.NewFilter(ifaceName, objs.IpLpmTrie)
	if err != nil {
		closers.Close(nil)
		return nil, err
	}

	r := Redirect{
		redirectOpts: &o,
		xsks:         xsks,
		Objects:      objs,
		filter:       filter,
	}

	// Command server
	server, err := cmdconn.NewTLVServer(filter, &r)
	if err != nil {
		closers.Close(nil)
		return nil, err
	}
	closers = append(closers, utils.NamedCloser{Name: "cmdconn.Server", Close: server.Close})

	err = r.setHandles(ifaceName)
	if err != nil {
		closers.Close(nil)
		return nil, err
	}

	r.server = server
	r.closers = closers
	return &r, nil
}

func (r *Redirect) setHandles(ifaceName string) error {
	r.handles = map[protos.RedirectType]handle.RedirectHandle{}

	// Dump
	// TODO: implement

	// Remote
	// TODO: implement

	// Spoof handle
	spoofHandle, err := spoof.NewSpoofHandle(ifaceName)
	if err != nil {
		return err
	}
	r.handles[spoofHandle.RedirectType()] = spoofHandle
	r.closers = append(r.closers, utils.NamedCloser{Name: "spoof.SpoofHandle", Close: spoofHandle.Close})

	// Tap
	// TODO: implement

	return nil
}

func (r *Redirect) Run(ctx context.Context) error {
	var (
		done bool
		stat stats.Statistics
	)

	go func() {
		<-ctx.Done()
		done = true
	}()

	// Close in r.closers, not use ctx args
	go r.server.Serve(context.Background())

	for !done {
		err := r.waitPoll()
		if err != nil {
			return err
		}

		for _, xsk := range r.xsks {
			r.handleXSK(xsk, &stat)
		}
	}

	return nil
}

func (r *Redirect) handleXSK(xsk *xdp.XDPSocket, stat *stats.Statistics) {
	stuffFillQ(xsk)

	var idx uint32
	n := xsk.Rx.Peek(64, &idx)
	if n == 0 {
		return
	}

	for i := uint32(0); i < n; i++ {
		desc := xsk.Rx.GetDesc(idx)

		stat.Bytes += uint64(desc.Len)
		stat.Packets++

		for _, handle := range r.handles {
			handle.HandlePacketData(xsk.Umem.GetData(desc))
		}
		xsk.Umem.FreeFrame(desc.Addr)
	}

	xsk.Rx.Release(n)
}

func (r *Redirect) waitPoll() error {
	if r.pollTimeout == 0 {
		return nil
	}

	fds := []unix.PollFd{}
	for _, xsk := range r.xsks {
		fds = append(fds, unix.PollFd{Fd: int32(xsk.SocketFd()), Events: unix.POLLIN})
	}
	_, err := unix.Poll(fds, r.pollTimeout)
	if err != nil {
		if errors.Is(err, unix.EINTR) {
			return nil
		}
		return errors.Wrap(err, "unix.Poll")
	}
	return nil
}

func (r *Redirect) Stop() error {
	r.closers.Close(&utils.CloseOpt{ReverseOrder: true, Output: logrus.Debug, ErrorOutput: logrus.Error})
	return nil
}

func (*Redirect) CommandType() protos.Type {
	return protos.Type_Redirect
}

func (r *Redirect) HandleReqData(data []byte) ([]byte, error) {
	var req protos.RedirectReq
	err := json.Unmarshal(data, &req)
	if err != nil {
		return nil, err
	}

	handle, ok := r.handles[req.RedirectType]
	if !ok {
		return nil, fmt.Errorf("invalid redirect type: %s", req.RedirectType)
	}
	return handle.HandleReqData(req.RedirectData)
}

func stuffFillQ(x *xdp.XDPSocket) {
	frames := x.Umem.Fill.GetFreeNum(x.Umem.GetFrameFreeNum())
	if frames == 0 {
		return
	}

	var idx uint32
	x.Umem.Fill.Reserve(frames, &idx)

	for i := uint32(0); i < frames; i++ {
		*x.Umem.Fill.GetAddr(idx) = x.Umem.AllocFrame()
	}
	x.Umem.Fill.Submit(frames)
}
