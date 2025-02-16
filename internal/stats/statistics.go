package stats

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zxhio/xdpass/pkg/humanize"
)

type Statistics struct {
	Packets     uint64
	Bytes       uint64
	IOCount     uint64 // sendto / recvmsg
	IOFailCount uint64
}

func DumpStatistics(name string, prev, curr *Statistics, lastDumpTm time.Time) string {
	period := float64(time.Since(lastDumpTm)) / float64(time.Second)

	packets := curr.Packets - prev.Packets
	pps := float64(packets) / period

	bytes := curr.Bytes - prev.Bytes
	bps := float64(bytes*8) / period

	ios := curr.IOCount - prev.IOCount
	iops := float64(ios*8) / period

	iofs := curr.IOFailCount - prev.IOFailCount
	iofps := float64(iofs*8) / period

	var fields []string
	fields = append(fields, name)
	fields = append(fields, fmt.Sprintf("%12d pkts %8.0f pkts/s", curr.Packets, pps))
	fields = append(fields, fmt.Sprintf("%12s %13s", humanize.Bytes(int(curr.Bytes)), humanize.BitsRate(int(bps))))
	fields = append(fields, fmt.Sprintf("%6.0f %6.0f iops", iops, iofps))
	return strings.Join(fields, "  ")
}

func DumpStatisticsLoop(ctx context.Context, name string, s *Statistics, d time.Duration, output func(...interface{})) {
	DumpStatisticsListLoop(ctx, name, []*Statistics{s}, d, output)
}

func DumpStatisticsListLoop(ctx context.Context, name string, list []*Statistics, d time.Duration, output func(...interface{})) {
	var (
		lastDumpTm time.Time
		prev       Statistics
	)

	t := time.NewTicker(d)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		curr := joinStatisticsList(list)
		if output != nil {
			output(DumpStatistics(name, &prev, &curr, lastDumpTm))
			lastDumpTm = time.Now()
		}
		prev = curr
	}
}

func joinStatisticsList(list []*Statistics) Statistics {
	var stat Statistics
	for _, s := range list {
		stat.Packets += s.Packets
		stat.Bytes += s.Bytes
		stat.IOCount += s.IOCount
		stat.IOFailCount += s.IOFailCount
	}
	return stat
}
