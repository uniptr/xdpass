package netutil

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
)

func GetRxQueues(iface string) ([]int, error) {
	rx, _, err := GetQueues(iface)
	return rx, err
}

func GetTxQueues(iface string) ([]int, error) {
	_, tx, err := GetQueues(iface)
	return tx, err
}

func GetQueues(iface string) ([]int, []int, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/sys/class/net/%s/queues", iface))
	if err != nil {
		return nil, nil, errors.Wrap(err, "os.ReadDir")
	}

	var (
		rxQueues []int
		txQueues []int
	)

	matchIdx := func(path, qFmt string) []int {
		var id int
		_, err := fmt.Sscanf(path, qFmt, &id)
		if err != nil {
			return nil
		}
		return []int{id}
	}

	for _, entry := range entries {
		rxQueues = append(rxQueues, matchIdx(entry.Name(), "rx-%d")...)
		txQueues = append(txQueues, matchIdx(entry.Name(), "tx-%d")...)
	}
	return rxQueues, txQueues, nil
}
