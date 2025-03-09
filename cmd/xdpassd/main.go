package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/zxhio/xdpass/internal"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/commands/fwcmd"
	"github.com/zxhio/xdpass/internal/commands/redirectcmd"
	"github.com/zxhio/xdpass/internal/commands/statscmd"
	"github.com/zxhio/xdpass/pkg/builder"
	"github.com/zxhio/xdpass/pkg/xdp"
)

var opt struct {
	ifaces      []string
	queueID     int
	pollTimeout int
	verbose     bool
	cores       []int
	attachModeOpt
	bindFlagsOpt
	version bool
}

type attachModeOpt struct {
	attachModeGeneric bool
	attachModeNative  bool
	attachModeOffload bool
}

type bindFlagsOpt struct {
	bindFlagsXSKCopy      bool
	bindFlagsXSKZeroCopy  bool
	bindFlagsNoNeedWakeup bool
}

func main() {
	pflag.StringSliceVarP(&opt.ifaces, "interfaces", "i", []string{}, "Interface name list")
	pflag.IntVarP(&opt.queueID, "queue-id", "q", 0, "Interface rx queue index")
	pflag.IntVar(&opt.pollTimeout, "poll", 0, "Poll timeout (us), 0 means not use poll")
	pflag.IntSliceVarP(&opt.cores, "cores", "c", []int{-1}, "Affinity cpu cores, -1 not set, cores must <= queues")
	pflag.BoolVarP(&opt.verbose, "verbose", "v", false, "Verbose output")
	pflag.BoolVarP(&opt.version, "version", "V", false, "Prints the build information")

	// attach mode
	pflag.BoolVar(&opt.attachModeGeneric, xdp.XDPAttachModeStrGeneric, false, "Attach in SKB (AKA generic) mode")
	pflag.BoolVar(&opt.attachModeNative, xdp.XDPAttachModeStrNative, false, "Attach in native mode")
	pflag.BoolVar(&opt.attachModeOffload, xdp.XDPAttachModeStrOffload, false, "Attach in offload mode")

	// bind flags
	pflag.BoolVar(&opt.bindFlagsXSKCopy, xdp.XSKBindFlagsStrCopy, false, "Force copy mode")
	pflag.BoolVar(&opt.bindFlagsXSKZeroCopy, xdp.XSKBindFlagsStrZeroCopy, false, "Force zero-copy mode")
	pflag.BoolVar(&opt.bindFlagsNoNeedWakeup, "no-need-wakeup", false, "Disable need wakeup flag")
	pflag.Parse()

	if opt.version {
		fmt.Println(builder.BuildInfo())
		return
	}

	if opt.verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGUSR1)
	go func() {
		sig := <-sigCh
		cancel()
		logrus.WithField("sig", sig).Info("Recv signal")
	}()

	server, err := commands.NewMessageServer(commands.DefUnixSock, fwcmd.FirewallCommandHandle{}, redirectcmd.RedirectCommandHandle{}, statscmd.StatsCommandHandle{})
	if err != nil {
		logrus.WithField("err", err).Fatal("Fail to create message server")
	}
	defer server.Close()
	go server.Serve(ctx)

	attachMode := xdp.XDPAttachModeGeneric
	if opt.attachModeNative {
		attachMode = xdp.XDPAttachModeNative
	} else if opt.attachModeOffload {
		attachMode = xdp.XDPAttachModeOffload
	}

	xdpOpts := []xdp.XDPOpt{}
	if opt.bindFlagsXSKCopy {
		xdpOpts = append(xdpOpts, xdp.WithCopy())
	} else if opt.bindFlagsXSKZeroCopy {
		xdpOpts = append(xdpOpts, xdp.WithZeroCopy())
	}
	if opt.bindFlagsNoNeedWakeup {
		xdpOpts = append(xdpOpts, xdp.WithNoNeedWakeup())
	}
	opts := []internal.LinkHandleOpt{
		internal.WithLinkQueueID(opt.queueID),
		internal.WithLinkXDPFlags(attachMode, xdpOpts...),
		internal.WithLinkHandleTimeout(opt.pollTimeout),
		internal.WithLinkHandleCores(opt.cores),
	}

	wg := sync.WaitGroup{}
	wg.Add(len(opt.ifaces))
	for _, iface := range opt.ifaces {
		go func(iface string) {
			defer wg.Done()
			newLinkHandle(ctx, iface, opts...)
		}(iface)
	}
	wg.Wait()
}

func newLinkHandle(ctx context.Context, iface string, opts ...internal.LinkHandleOpt) error {
	link, err := internal.NewLinkHandle(iface, opts...)
	if err != nil {
		return err
	}
	defer link.Close()
	return link.Run(ctx)
}
