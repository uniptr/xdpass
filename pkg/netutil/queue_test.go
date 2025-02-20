package netutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetQueues(t *testing.T) {
	rx, tx, err := GetQueues("lo")
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, rx, []int{0})
	assert.Equal(t, tx, []int{0})
}
