package redirect

import (
	"github.com/zxhio/xdpass/internal/exports"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/fastpkt"
	"github.com/zxhio/xdpass/pkg/utils"
)

type RedirectHandle interface {
	RedirectType() protos.RedirectType
	HandlePacket(pkt *fastpkt.Packet)
	Close() error
}

type Redirect struct {
	// TODO: Use array to avoid map lookup
	handles map[protos.RedirectType]RedirectHandle
	closers utils.NamedClosers
}

func NewRedirect(ifaceName string, frameSize int) (*Redirect, error) {
	handles := map[protos.RedirectType]RedirectHandle{}

	// Dump
	dump, err := NewDumpHandle(frameSize)
	if err != nil {
		return nil, err
	}
	handles[protos.RedirectTypeDump] = dump
	exports.RegisterDumpAPI(ifaceName, dump)
	closers := utils.NamedClosers{utils.NamedCloser{Name: "dump.DumpHandle", Close: dump.Close}}

	// Remote
	// TODO: implement

	// Spoof handle
	spoof, err := NewSpoofHandle(ifaceName)
	if err != nil {
		return nil, err
	}
	handles[protos.RedirectTypeSpoof] = spoof
	exports.RegisterSpoofAPI(ifaceName, spoof)
	closers = append(closers, utils.NamedCloser{Name: "spoof.SpoofHandle", Close: spoof.Close})

	// Tuntap
	tuntap, err := NewTuntapHandle()
	if err != nil {
		return nil, err
	}
	handles[protos.RedirectTypeTuntap] = tuntap
	exports.RegisterTuntapAPI(ifaceName, tuntap)
	closers = append(closers, utils.NamedCloser{Name: "tun.TunHandle", Close: tuntap.Close})

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
