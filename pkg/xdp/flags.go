package xdp

import (
	"encoding/json"
	"fmt"

	"github.com/BurntSushi/toml"
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

func (m XDPAttachMode) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.String())
}

func (m *XDPAttachMode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	return m.Set(s)
}

func (m XDPAttachMode) MarshalTOML() ([]byte, error) {
	return toml.Marshal(m.String())
}

func (m *XDPAttachMode) UnmarshalTOML(data any) error {
	switch v := data.(type) {
	case string:
		return m.Set(v)
	case []byte:
		return m.Set(string(v))
	default:
		return fmt.Errorf("invalid type: %T", v)
	}
}

type XSKBindFlags uint16

const (
	XSKBindFlagsUnspec     XSKBindFlags = 0
	XSKBindFlagsCopy       XSKBindFlags = unix.XDP_COPY
	XSKBindFlagsZeroCopy   XSKBindFlags = unix.XDP_ZEROCOPY
	XSKBindFlagsNeedWakeup XSKBindFlags = unix.XDP_USE_NEED_WAKEUP
)

const (
	XSKBindFlagsStrUnspec     = ""
	XSKBindFlagsStrCopy       = "copy"
	XSKBindFlagsStrZeroCopy   = "zero-copy"
	XSKBindFlagsStrNeedWakeup = "use-need-wakeup"
)

var bindFlagsLookup = map[string]XSKBindFlags{
	XSKBindFlagsStrUnspec:     XSKBindFlagsUnspec,
	XSKBindFlagsStrCopy:       XSKBindFlagsCopy,
	XSKBindFlagsStrZeroCopy:   XSKBindFlagsZeroCopy,
	XSKBindFlagsStrNeedWakeup: XSKBindFlagsNeedWakeup,
}

var bindFlagsStrLookup = map[XSKBindFlags]string{
	XSKBindFlagsUnspec:     XSKBindFlagsStrUnspec,
	XSKBindFlagsCopy:       XSKBindFlagsStrCopy,
	XSKBindFlagsZeroCopy:   XSKBindFlagsStrZeroCopy,
	XSKBindFlagsNeedWakeup: XSKBindFlagsStrNeedWakeup,
}

func (f XSKBindFlags) String() string {
	s, ok := bindFlagsStrLookup[f]
	if !ok {
		return "<invalid-flags>"
	}
	return s
}

func (f *XSKBindFlags) Set(s string) error {
	flag, ok := bindFlagsLookup[s]
	if !ok {
		return fmt.Errorf("invalid xsk bind flag: %s", s)
	}
	*f = flag
	return nil
}

func (f XSKBindFlags) MarshalJSON() ([]byte, error) {
	s, ok := bindFlagsStrLookup[f]
	if !ok {
		return nil, fmt.Errorf("invalid xsk bind flag: %d", f)
	}
	return json.Marshal(s)
}

func (f *XSKBindFlags) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	return f.Set(s)
}
