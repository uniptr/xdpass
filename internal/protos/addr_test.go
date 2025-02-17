package protos

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddrPort(t *testing.T) {
	addr := AddrPort(netip.MustParseAddrPort("192.168.1.1:80"))
	data, err := json.Marshal(addr)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, string(data), `"192.168.1.1:80"`)

	var addr2 AddrPort
	err = json.Unmarshal([]byte(`"192.168.1.1:80"`), &addr2)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, addr2, addr)
}
