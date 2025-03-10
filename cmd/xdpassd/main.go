package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/zxhio/xdpass/internal"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/commands/fwcmd"
	"github.com/zxhio/xdpass/internal/commands/redirectcmd"
	"github.com/zxhio/xdpass/internal/commands/statscmd"
	"github.com/zxhio/xdpass/internal/config"
	"github.com/zxhio/xdpass/pkg/builder"
)

var opt struct {
	verbose    bool
	version    bool
	config     string
	dumpConfig string
}

func main() {
	pflag.BoolVarP(&opt.verbose, "verbose", "v", false, "Verbose output")
	pflag.BoolVarP(&opt.version, "version", "V", false, "Prints the build information")
	pflag.StringVarP(&opt.config, "config", "c", "/etc/xdpass/xdpassd.toml", "Config file path")
	pflag.StringVar(&opt.dumpConfig, "dump-config", "", "Dump default config [generic|native]")
	pflag.Parse()

	if opt.version {
		fmt.Println(builder.BuildInfo())
		return
	}

	if opt.dumpConfig != "" {
		if err := dumpConfig(opt.dumpConfig); err != nil {
			logrus.WithField("err", err).Fatal("Fail to dump config")
		}
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

	cfg, err := config.NewConfig(opt.config)
	if err != nil {
		logrus.WithField("err", err).Fatal("Fail to load config")
	}

	links := make([]*internal.LinkHandle, len(cfg.Interfaces))
	for i, iface := range cfg.Interfaces {
		opts := []internal.LinkHandleOpt{
			internal.WithLinkHandleCores(cfg.Cores),
			internal.WithLinkQueueID(iface.QueueID),
			internal.WithLinkXDPFlags(iface.AttachMode, iface.XDPOpts...),
			internal.WithLinkHandleTimeout(cfg.PollTimeoutMs),
		}
		link, err := internal.NewLinkHandle(iface.Name, opts...)
		if err != nil {
			logrus.WithField("err", err).Fatal("Fail to new link handle")
		}
		links[i] = link
	}

	wg := sync.WaitGroup{}
	wg.Add(len(links))
	for _, link := range links {
		go func(link *internal.LinkHandle) {
			defer wg.Done()
			defer link.Close()
			if err := link.Run(ctx); err != nil {
				logrus.WithField("err", err).Fatal("Fail to run link handle")
			}
		}(link)
	}
	wg.Wait()
}

func dumpConfig(dumpType string) error {
	var data []byte
	var err error
	switch dumpType {
	case "generic":
		data, err = toml.Marshal(config.DefaultConfigGeneric())
	case "native":
		data, err = toml.Marshal(config.DefaultConfigOffload())
	default:
		return fmt.Errorf("invalid dump type: %s", dumpType)
	}
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
