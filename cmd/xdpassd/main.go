package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/zxhio/xdpass/internal/redirect"
	"github.com/zxhio/xdpass/pkg/xdp"
)

var opt struct {
	ifaceName   string
	queueID     int
	pollTimeout int
	verbose     bool

	attachModeOpt
	bindFlagsOpt
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
	pflag.StringVarP(&opt.ifaceName, "interface", "i", "", "Interface name")
	pflag.IntVarP(&opt.queueID, "queue-id", "q", 0, "Interface rx queue index")
	pflag.IntVar(&opt.pollTimeout, "poll", 0, "Poll timeout (us), 0 means not use poll")
	pflag.BoolVarP(&opt.verbose, "verbose", "v", false, "Verbose output")

	// attach mode
	pflag.BoolVar(&opt.attachModeGeneric, xdp.XDPAttachModeStrGeneric, false, "Attach in SKB (AKA generic) mode")
	pflag.BoolVar(&opt.attachModeNative, xdp.XDPAttachModeStrNative, false, "Attach in native mode")
	pflag.BoolVar(&opt.attachModeOffload, xdp.XDPAttachModeStrOffload, false, "Attach in offload mode")

	// bind flags
	pflag.BoolVar(&opt.bindFlagsXSKCopy, xdp.XSKBindFlagsStrCopy, false, "Force copy mode")
	pflag.BoolVar(&opt.bindFlagsXSKZeroCopy, xdp.XSKBindFlagsStrZeroCopy, false, "Force zero-copy mode")
	pflag.BoolVar(&opt.bindFlagsNoNeedWakeup, "no-need-wakeup", false, "Disable need wakeup flag")
	pflag.Parse()

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

	rx, err := redirect.NewRedirect(opt.ifaceName,
		redirect.WithRedirectQueueID(opt.queueID),
		redirect.WithRedirectXDPFlags(attachMode, xdpOpts...),
		redirect.WithRedirectPollTimeout(opt.pollTimeout),
	)
	if err != nil {
		logrus.WithError(err).Fatal("Fatal to new packet rx")
	}
	defer rx.Stop()

	err = rx.Run(ctx)
	if err != nil {
		logrus.WithError(err).Fatal("Fatal to serve rx")
	}
}
