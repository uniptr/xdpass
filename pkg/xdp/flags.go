package xdp

import (
	"fmt"

	"golang.org/x/sys/unix"
)

type XDPAttachMode int

const (
	XDPAttachModeUnspec  XDPAttachMode = 0
	XDPAttachModeGeneric XDPAttachMode = unix.XDP_FLAGS_SKB_MODE
	XDPAttachModeNative  XDPAttachMode = unix.XDP_FLAGS_DRV_MODE
	XDPAttachModeOffload XDPAttachMode = unix.XDP_FLAGS_HW_MODE
)

const (
	XDPAttachModeStrUnspec  = ""
	XDPAttachModeStrGeneric = "generic"
	XDPAttachModeStrNative  = "native"
	XDPAttachModeStrOffload = "offload"
)

var attachModeLookup = map[string]XDPAttachMode{
	XDPAttachModeStrUnspec:  XDPAttachModeUnspec,
	XDPAttachModeStrGeneric: XDPAttachModeGeneric,
	XDPAttachModeStrNative:  XDPAttachModeNative,
	XDPAttachModeStrOffload: XDPAttachModeOffload,
}

var attachModeStrLookup = map[XDPAttachMode]string{
	XDPAttachModeUnspec:  XDPAttachModeStrUnspec,
	XDPAttachModeGeneric: XDPAttachModeStrGeneric,
	XDPAttachModeNative:  XDPAttachModeStrNative,
	XDPAttachModeOffload: XDPAttachModeStrOffload,
}

func (m XDPAttachMode) String() string {
	return attachModeStrLookup[m]
}

func (m *XDPAttachMode) Set(s string) error {
	mode, ok := attachModeLookup[s]
	if !ok {
		return fmt.Errorf("invalid xdp attach mode: %s", s)
	}
	*m = mode
	return nil
}

type XSKBindFlags int

const (
	XSKBindFlagsSharedUmem XSKBindFlags = unix.XDP_SHARED_UMEM
	XSKBindFlagsCopy       XSKBindFlags = unix.XDP_COPY
	XSKBindFlagsZeroCopy   XSKBindFlags = unix.XDP_ZEROCOPY
	XSKBindFlagsNeedWakeup XSKBindFlags = unix.XDP_USE_NEED_WAKEUP
)

const (
	XSKBindFlagsStrSharedUmem = "shared-umem"
	XSKBindFlagsStrCopy       = "copy"
	XSKBindFlagsStrZeroCopy   = "zero-copy"
	XSKBindFlagsStrNeedWakeup = "use-need-wakeup"
)

var bindFlagsLookup = map[string]XSKBindFlags{
	XSKBindFlagsStrSharedUmem: XSKBindFlagsSharedUmem,
	XSKBindFlagsStrCopy:       XSKBindFlagsCopy,
	XSKBindFlagsStrZeroCopy:   XSKBindFlagsZeroCopy,
	XSKBindFlagsStrNeedWakeup: XSKBindFlagsNeedWakeup,
}

var bindFlagsStrLookup = map[XSKBindFlags]string{
	XSKBindFlagsSharedUmem: XSKBindFlagsStrSharedUmem,
	XSKBindFlagsCopy:       XSKBindFlagsStrCopy,
	XSKBindFlagsZeroCopy:   XSKBindFlagsStrZeroCopy,
	XSKBindFlagsNeedWakeup: XSKBindFlagsStrNeedWakeup,
}

func (f XSKBindFlags) String() string {
	return bindFlagsStrLookup[f]
}

func (f *XSKBindFlags) Set(s string) error {
	flag, ok := bindFlagsLookup[s]
	if !ok {
		return fmt.Errorf("invalid xsk bind flag: %s", s)
	}
	*f = flag
	return nil
}
