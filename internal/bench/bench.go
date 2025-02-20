package bench

// Package independently completes benchmark testing functionality

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/pkg/humanize"
	"github.com/zxhio/xdpass/pkg/netutil"
	"golang.org/x/sys/unix"
)

type BenchmarkOpt struct {
	done *bool
}

type txGroup struct {
	TxOpt
	core   int
	txList []Tx
}

func runTxBenchmark(ctx context.Context, opt *benchOpt, data []byte) error {
	done := false
	go func() {
		<-ctx.Done()
		done = true
	}()

	var (
		txList []Tx
		err    error
	)

	txList, err = newXDPTxList(opt.ifaceName, opt.queueID)
	if err != nil {
		tx, err := newAFPTx(opt.ifaceName)
		if err != nil {
			return err
		}
		txList = append(txList, tx)
	}

	var (
		batch uint32
		cores []int
	)
	if opt.rateLimit == -1 {
		batch = uint32(opt.batch)
		cores = opt.cores
	} else {
		batch = 1
		cores = opt.cores[:1]
	}
	// cpu num should not greater than tx queue num
	if len(cores) > len(txList) {
		cores = cores[:len(txList)]
	}

	var txGroups []*txGroup
	for _, c := range cores {
		txGroups = append(txGroups, &txGroup{
			TxOpt: TxOpt{
				BenchmarkOpt: BenchmarkOpt{done: &done},
				Batch:        batch,
				Data:         data,
			},
			core: c,
		})
	}

	for k, tx := range txList {
		txGroups[k%len(txGroups)].txList = append(txGroups[k%len(txGroups)].txList, tx)
	}
	for k := range opt.n {
		txGroups[k%len(txGroups)].Packets++
	}

	wg := sync.WaitGroup{}
	wg.Add(len(cores))

	for _, tg := range txGroups {
		go func() {
			defer wg.Done()
			runTxBenchmarkGroup(tg)
		}()
	}

	if opt.statsDur > 0 {
		go dumpStats(txList, time.Duration(opt.statsDur)*time.Second)
	}

	wg.Wait()

	return nil
}

func runTxBenchmarkGroup(tg *txGroup) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if tg.core != -1 {
		logrus.WithFields(logrus.Fields{"core": tg.core, "txList": len(tg.txList)}).Info("Set affinity cpu")
		setAffinityCPU(tg.core)
	}

	limiter := newRateLimiter(opt.rateLimit, opt.rateLimitPrec)
	remain := opt.n

	for idx := 0; opt.n == -1 || remain > 0; idx++ {
		if opt.rateLimit != -1 && !limiter.allow() {
			continue
		}

		tg.Batch = min(tg.Batch, uint32(remain))
		tg.txList[idx%len(tg.txList)].Transmit(&tg.TxOpt)
		remain -= int(tg.Batch)
	}

	for _, tx := range tg.txList {
		tx.Close()
	}
}

func setAffinityCPU(cpu int) error {
	var s unix.CPUSet
	s.Zero()
	s.Set(cpu)
	return unix.SchedSetaffinity(0, &s)
}

func dumpStats(txList []Tx, dur time.Duration) {
	prev := make(map[int]netutil.Statistics)
	timer := time.NewTicker(dur)
	for range timer.C {
		tbl := tablewriter.NewWriter(os.Stdout)
		tbl.SetHeader([]string{"fd", "queue", "tx_pps", "tx_bps", "tx_iops", "tx_error_ps"})

		sum := netutil.StatisticsRate{}
		for _, tx := range txList {
			stat := tx.Stats()
			rate := stat.Rate(prev[tx.Fd()])
			prev[tx.Fd()] = stat

			tbl.Append([]string{
				fmt.Sprintf("%d", tx.Fd()),
				fmt.Sprintf("%d", tx.QueueID()),
				fmt.Sprintf("%.0f", rate.TxPPS),
				humanize.BitsRate(int(rate.TxBPS)),
				fmt.Sprintf("%.0f", rate.TxIOPS),
				fmt.Sprintf("%.0f", rate.TxErrorPS),
			})
			sum.TxPPS += rate.TxPPS
			sum.TxBPS += rate.TxBPS
			sum.TxIOPS += rate.TxIOPS
			sum.TxErrorPS += rate.TxErrorPS
		}
		tbl.Append([]string{
			"",
			"",
			fmt.Sprintf("%.0f", sum.TxPPS),
			humanize.BitsRate(int(sum.TxBPS)),
			fmt.Sprintf("%.0f", sum.TxIOPS),
			fmt.Sprintf("%.0f", sum.TxErrorPS),
		})
		tbl.Render()
	}
}
