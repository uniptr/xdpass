package xdpflags

import (
	"fmt"

	"golang.org/x/sys/unix"
)

type XDPFlagsMode int

const (
	XDPFlagsModeGeneric XDPFlagsMode = unix.XDP_FLAGS_SKB_MODE
	XDPFlagsModeDriver  XDPFlagsMode = unix.XDP_FLAGS_DRV_MODE
	XDPFlagsModeOffload XDPFlagsMode = unix.XDP_FLAGS_HW_MODE
)

const (
	XDPFlagsModeStrGeneric = "skb"
	XDPFlagsModeStrDriver  = "drv"
	XDPFlagsModeStrOffload = "hw"
)

func (m XDPFlagsMode) String() string {
	switch m {
	case XDPFlagsModeGeneric:
		return XDPFlagsModeStrGeneric
	case XDPFlagsModeDriver:
		return XDPFlagsModeStrDriver
	case XDPFlagsModeOffload:
		return XDPFlagsModeStrOffload
	default:
		return XDPFlagsModeStrGeneric
	}
}

func (m *XDPFlagsMode) Set(s string) error {
	*m = XDPFlagsModeByStr(s)
	return nil
}

func (m *XDPFlagsMode) Type() string {
	return "string"
}

func UsageXDPFlagsMode() string {
	return fmt.Sprintf("XDP flags mode [%s|%s|%s]",
		XDPFlagsModeStrGeneric, XDPFlagsModeStrDriver, XDPFlagsModeStrOffload)
}

func XDPFlagsModeByStr(s string) XDPFlagsMode {
	switch s {
	case XDPFlagsModeStrGeneric:
		return XDPFlagsModeGeneric
	case XDPFlagsModeStrDriver:
		return XDPFlagsModeDriver
	case XDPFlagsModeStrOffload:
		return XDPFlagsModeOffload
	default:
		return 0
	}
}
