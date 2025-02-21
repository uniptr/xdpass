package redirect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/zxhio/xdpass/internal/commands/cmdconn"
	"github.com/zxhio/xdpass/internal/firewall"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/handle"
	"github.com/zxhio/xdpass/internal/redirect/spoof"
	"github.com/zxhio/xdpass/pkg/humanize"
	"github.com/zxhio/xdpass/pkg/netutil"
	"github.com/zxhio/xdpass/pkg/utils"
	"github.com/zxhio/xdpass/pkg/xdp"
	"github.com/zxhio/xdpass/pkg/xdpprog"
	"golang.org/x/sys/unix"
)

type redirectOpts struct {
	queueID     int
	attachMode  xdp.XDPAttachMode
	xdpOpts     []xdp.XDPOpt
	pollTimeout int
}

type RedirectOpt func(*redirectOpts)

func WithRedirectQueueID(queueID int) RedirectOpt {
	return func(o *redirectOpts) { o.queueID = queueID }
}

func WithRedirectXDPFlags(attachMode xdp.XDPAttachMode, opts ...xdp.XDPOpt) RedirectOpt {
	return func(o *redirectOpts) {
		o.attachMode = attachMode
		o.xdpOpts = opts
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

	queues, err := netutil.GetRxQueues(ifaceName)
	if err != nil {
		return nil, err
	}
	logrus.WithField("queues", queues).Info("Get rx queues")

	var xsks []*xdp.XDPSocket
	for _, queueID := range queues {
		s, err := xdp.NewXDPSocket(uint32(ifaceLink.Attrs().Index), uint32(queueID), append(o.xdpOpts, xdp.WithTxSize(0))...)
		if err != nil {
			return nil, err
		}

		closers = append(closers, utils.NamedCloser{Name: fmt.Sprintf("xdp.XDPSocket(fd:%d queue:%d)", s.SocketFD(), queueID), Close: s.Close})
		xsks = append(xsks, s)
		logrus.WithFields(logrus.Fields{"fd": s.SocketFD(), "queue_id": queueID}).Info("New xdp socket")

		// Update xsk map
		// Note: xsk map not support lookup element
		// See kernel tree net/xdp/xdpmap.c *xsk_map_lookup_elem_sys_only* implement
		err = objs.XskMap.Update(uint32(queueID), uint32(s.SocketFD()), 0)
		if err != nil {
			closers.Close(nil)
			return nil, errors.Wrap(err, "XskMap.Update")
		}
		logrus.WithFields(logrus.Fields{"k": queueID, "v": s.SocketFD()}).Info("Update xsk map")
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
	done := false
	go func() {
		<-ctx.Done()
		done = true
	}()

	// Close in r.closers, not use ctx args
	go r.server.Serve(context.Background())

	// Test output
	// TODO: response to xdpass stats
	go func() {
		prev := make(map[int]netutil.Statistics)

		timer := time.NewTicker(time.Second * 3)
		for range timer.C {
			tbl := tablewriter.NewWriter(os.Stdout)
			tbl.SetHeader([]string{"fd", "queue", "rx_pps", "tx_pps", "rx_bps", "tx_bps", "rx_iops", "tx_iops", "rx_error_ps", "tx_error_ps", "rx_dropped_ps", "tx_dropped_ps"})

			sum := netutil.StatisticsRate{}
			for _, xsk := range r.xsks {
				stat := xsk.Stats()
				rate := stat.Rate(prev[xsk.SocketFD()])
				prev[xsk.SocketFD()] = stat

				tbl.Append([]string{
					fmt.Sprintf("%d", xsk.SocketFD()),
					fmt.Sprintf("%d", xsk.QueueID()),
					fmt.Sprintf("%.0f", rate.RxPPS),
					fmt.Sprintf("%.0f", rate.TxPPS),
					humanize.BitsRate(int(rate.RxBPS)),
					humanize.BitsRate(int(rate.TxBPS)),
					// fmt.Sprintf("%.0f", rate.RxBPS),
					// fmt.Sprintf("%.0f", rate.TxBPS),
					fmt.Sprintf("%.0f", rate.RxIOPS),
					fmt.Sprintf("%.0f", rate.TxIOPS),
					fmt.Sprintf("%.0f", rate.RxErrorPS),
					fmt.Sprintf("%.0f", rate.TxErrorPS),
					fmt.Sprintf("%.0f", rate.RxDroppedPS),
					fmt.Sprintf("%.0f", rate.TxDroppedPS),
				})
				sum.RxPPS += rate.RxPPS
				sum.TxPPS += rate.TxPPS
				sum.RxBPS += rate.RxBPS
				sum.TxBPS += rate.TxBPS
				sum.RxIOPS += rate.RxIOPS
				sum.TxIOPS += rate.TxIOPS
				sum.RxErrorPS += rate.RxErrorPS
				sum.TxErrorPS += rate.TxErrorPS
				sum.RxDroppedPS += rate.RxDroppedPS
				sum.TxDroppedPS += rate.TxDroppedPS
			}
			tbl.Append([]string{
				"",
				"",
				fmt.Sprintf("%.0f", sum.RxPPS),
				fmt.Sprintf("%.0f", sum.TxPPS),
				humanize.BitsRate(int(sum.RxBPS)),
				humanize.BitsRate(int(sum.TxBPS)),
				// fmt.Sprintf("%.0f", sum.RxBPS),
				// fmt.Sprintf("%.0f", sum.TxBPS),
				fmt.Sprintf("%.0f", sum.RxIOPS),
				fmt.Sprintf("%.0f", sum.TxIOPS),
				fmt.Sprintf("%.0f", sum.RxErrorPS),
				fmt.Sprintf("%.0f", sum.TxErrorPS),
				fmt.Sprintf("%.0f", sum.RxDroppedPS),
				fmt.Sprintf("%.0f", sum.TxDroppedPS),
			})
			tbl.Render()
		}
	}()

	// TODO: use option vec size
	dataVec := make([][]byte, 64)
	for i := range dataVec {
		dataVec[i] = make([]byte, xdp.UmemDefaultFrameSize)
	}

	for !done {
		err := r.waitPoll()
		if err != nil {
			return err
		}

		for _, xsk := range r.xsks {
			r.handleXSK(xsk, dataVec)
		}
	}

	return nil
}

func (r *Redirect) handleXSK(xsk *xdp.XDPSocket, dataVec [][]byte) {
	n := xsk.Readv(dataVec)
	if n == 0 {
		return
	}

	for i := uint32(0); i < n; i++ {
		for _, handle := range r.handles {
			handle.HandlePacketData(dataVec[i])
		}
	}
}

func (r *Redirect) waitPoll() error {
	if r.pollTimeout == 0 {
		return nil
	}

	fds := []unix.PollFd{}
	for _, xsk := range r.xsks {
		fds = append(fds, unix.PollFd{Fd: int32(xsk.SocketFD()), Events: unix.POLLIN})
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
