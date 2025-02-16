package bench

// Package independently completes benchmark testing functionality

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/stats"
	"golang.org/x/sys/unix"
)

type BenchmarkOpt struct {
	stat *stats.Statistics
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
				BenchmarkOpt: BenchmarkOpt{
					stat: &stats.Statistics{},
					done: &done,
				},
				Batch: batch,
				Data:  data,
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

	var statsList []*stats.Statistics
	for _, tg := range txGroups {
		statsList = append(statsList, tg.stat)
		go func() {
			defer wg.Done()
			runTxBenchmarkGroup(tg)
		}()
	}
	if opt.statsDur > 0 {
		go stats.DumpStatisticsListLoop(ctx, "TX:", statsList, time.Duration(opt.statsDur)*time.Second, logrus.Info)
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
		tx.Wait(&tg.TxOpt)
	}
}

func setAffinityCPU(cpu int) error {
	var s unix.CPUSet
	s.Zero()
	s.Set(cpu)
	return unix.SchedSetaffinity(0, &s)
}
