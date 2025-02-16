package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/zxhio/xdpass/internal/redirect"
	"github.com/zxhio/xdpass/internal/xdpflags"
)

var opt struct {
	ifaceName   string
	queueID     int
	pollTimeout int
	xdpFlags    xdpflags.XDPFlagsMode
	ips         []string
	verbose     bool
}

func main() {
	pflag.StringVarP(&opt.ifaceName, "interface", "i", "", "Interface name")
	pflag.IntVarP(&opt.queueID, "queue-id", "q", 0, "Interface rx queue index")
	pflag.IntVar(&opt.pollTimeout, "poll", 0, "Poll timeout (us)")
	pflag.Var(&opt.xdpFlags, "xdp-flags", xdpflags.UsageXDPFlagsMode())
	pflag.StringSliceVar(&opt.ips, "ips", []string{}, "IP/CIDR list")
	pflag.BoolVarP(&opt.verbose, "verbose", "v", false, "Verbose output")
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

	rx, err := redirect.NewRedirect(opt.ifaceName,
		redirect.WithRedirectQueueID(opt.queueID),
		redirect.WithRedirectXDPFlags(opt.xdpFlags),
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
