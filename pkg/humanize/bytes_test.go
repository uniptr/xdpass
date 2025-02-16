package humanize

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBytes(t *testing.T) {
	testCases := []struct {
		bytes  int
		expect string
	}{
		{
			bytes:  1,
			expect: "1 Bytes",
		},
		{
			bytes:  1000,
			expect: "1.0 KBytes",
		},
		{
			bytes:  1001,
			expect: "1.0 KBytes",
		},
		{
			bytes:  1200,
			expect: "1.2 KBytes",
		},
		{
			bytes:  1000_000,
			expect: "1.0 MBytes",
		},
		{
			bytes:  1000_000_000,
			expect: "1.0 GBytes",
		},
		{
			bytes:  1000_000_000_000,
			expect: "1.0 TBytes",
		},
		{
			bytes:  1000_000_000_000_000,
			expect: "1.0 PBytes",
		},
		{
			bytes:  1000_000_000_000_000_000,
			expect: "1.0 EBytes",
		},
	}

	for _, c := range testCases {
		assert.Equal(t, c.expect, Bytes(c.bytes))
	}
}
