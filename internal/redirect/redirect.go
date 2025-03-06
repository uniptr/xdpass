package redirect

import (
	"github.com/zxhio/xdpass/internal/commands/redirects"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/dump"
	"github.com/zxhio/xdpass/internal/redirect/handle"
	"github.com/zxhio/xdpass/internal/redirect/spoof"
	"github.com/zxhio/xdpass/internal/redirect/tuntap"
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/utils"
)

type Redirect struct {
	// TODO: Use array to avoid map lookup
	handles map[protos.RedirectType]handle.RedirectHandle
	closers utils.NamedClosers
}

func NewRedirect(ifaceName string, cmd *redirects.RedirectCommand) (*Redirect, error) {
	handles := map[protos.RedirectType]handle.RedirectHandle{}

	// Dump
	dumpHandle, err := dump.NewDumpHandle()
	if err != nil {
		return nil, err
	}
	handles[dumpHandle.RedirectType()] = dumpHandle
	cmd.GetCommandHandle(dumpHandle.RedirectType()).(*redirects.DumpCommand).Register(ifaceName, dumpHandle)
	closers := utils.NamedClosers{utils.NamedCloser{Name: "dump.DumpHandle", Close: dumpHandle.Close}}

	// Remote
	// TODO: implement

	// Spoof handle
	spoofHandle, err := spoof.NewSpoofHandle(ifaceName)
	if err != nil {
		return nil, err
	}
	handles[spoofHandle.RedirectType()] = spoofHandle
	cmd.GetCommandHandle(spoofHandle.RedirectType()).(*redirects.SpoofCommand).Register(ifaceName, spoofHandle)
	closers = append(closers, utils.NamedCloser{Name: "spoof.SpoofHandle", Close: spoofHandle.Close})

	// Tuntap
	tuntapHandle, err := tuntap.NewTuntapHandle()
	if err != nil {
		return nil, err
	}
	handles[tuntapHandle.RedirectType()] = tuntapHandle
	cmd.GetCommandHandle(tuntapHandle.RedirectType()).(*redirects.TuntapCommand).Register(ifaceName, tuntapHandle)
	closers = append(closers, utils.NamedCloser{Name: "tun.TunHandle", Close: tuntapHandle.Close})

	return &Redirect{handles: handles, closers: closers}, nil
}

func (r *Redirect) Close() error {
	r.closers.Close(nil)
	return nil
}

func (r *Redirect) HandlePacket(pkts *fastpkt.Packet) {
	for _, handle := range r.handles {
		handle.HandlePacket(pkts)
	}
}
