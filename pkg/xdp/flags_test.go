package xdp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttachMode(t *testing.T) {
	testCases := []struct {
		mode XDPAttachMode
		json string
	}{
		{XDPAttachModeUnspec, `""`},
		{XDPAttachModeNative, `"native"`},
		{XDPAttachModeGeneric, `"generic"`},
		{XDPAttachModeOffload, `"offload"`},
	}

	for _, tc := range testCases {
		json, err := tc.mode.MarshalJSON()
		assert.NoError(t, err)
		assert.Equal(t, string(json), tc.json)
	}

	var mode XDPAttachMode
	err := mode.UnmarshalJSON([]byte(`"xxx"`))
	assert.Error(t, err, "invalid attach mode")
}

func TestBindFlags(t *testing.T) {
	testCases := []struct {
		flags XSKBindFlags
		json  string
	}{
		{XSKBindFlagsUnspec, `""`},
		{XSKBindFlagsCopy, `"copy"`},
		{XSKBindFlagsZeroCopy, `"zero-copy"`},
		{XSKBindFlagsNeedWakeup, `"use-need-wakeup"`},
	}

	for _, tc := range testCases {
		json, err := tc.flags.MarshalJSON()
		assert.NoError(t, err)
		assert.Equal(t, string(json), tc.json)
	}

	var flags XSKBindFlags
	err := flags.UnmarshalJSON([]byte(`"xxx"`))
	assert.Error(t, err, "invalid flags")
}
