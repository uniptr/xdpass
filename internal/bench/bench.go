package bench

// Package independently completes benchmark testing functionality

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/pkg/humanize"
	"github.com/zxhio/xdpass/pkg/netutil"
	"github.com/zxhio/xdpass/pkg/xdp"
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

func (tg *txGroup) formatTxData() string {
	s := []string{}
	for _, tx := range tg.txList {
		s = append(s, fmt.Sprintf("tx(queue:%d fd:%d)", tx.QueueID(), tx.Fd()))
	}
	return strings.Join(s, ",")
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

	opts := []xdp.XDPOpt{}
	if opt.bindCopy {
		opts = append(opts, xdp.WithCopy())
	}
	if opt.bindZeroCopy {
		opts = append(opts, xdp.WithZeroCopy())
	}

	var queues []int
	if opt.queueID != -1 {
		queues = append(queues, opt.queueID)
	} else {
		var err error
		queues, err = netutil.GetTxQueues(opt.ifaceName)
		if err != nil {
			return err
		}
	}

	batch := valueExpect(opt.rateLimit == -1, opt.batch, 1)
	cores := opt.cores[:min(len(queues), len(opt.cores))]

	// Human readable tx packet
	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	logrus.Info(pkt.String())
	logrus.Debugf("Packet hexdump %d bytes:\n%v", len(data), hex.Dump(data))

	logrus.WithFields(logrus.Fields{"pkts": opt.n, "batch": batch, "data_len": len(data)}).Debug("Set benchmark pkts")
	logrus.WithFields(logrus.Fields{"rate_limit": opt.rateLimit, "rate_limit_prec": opt.rateLimitPrec.String()}).Debug("Set benchmark rate limit")
	logrus.WithFields(logrus.Fields{"queues": queues, "cores": cores}).Debug("Set benchmark cpu cores")

	for _, queue := range queues {
		var tx Tx
		tx, err = newXDPTx(opt.ifaceName, uint32(queue), append(opts, xdp.WithFrameSize(2048))...)
		if err != nil {
			tx, err = newAFPTx(opt.ifaceName)
			if err != nil {
				return err
			}
		}
		txList = append(txList, tx)
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

	// Assign the average txList to txGroups
	for k, tx := range txList {
		txGroups[k%len(txGroups)].txList = append(txGroups[k%len(txGroups)].txList, tx)
	}

	if opt.n == -1 {
		for _, tg := range txGroups {
			tg.Packets = -1
		}
	} else {
		// Simple method to assign the pkts to txGroups
		for k := range opt.n {
			txGroups[k%len(txGroups)].Packets++
		}
	}

	wg := sync.WaitGroup{}
	wg.Add(len(txGroups))

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

	l := logrus.WithField("tx_group", tg.formatTxData())
	if tg.core != -1 {
		l = l.WithField("core", tg.core)
		setAffinityCPU(tg.core)
	}
	l.Info("Benchmark tx group")

	limiter := newRateLimiter(opt.rateLimit, opt.rateLimitPrec)
	remain := tg.Packets

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
		tbl.SetHeader([]string{"queue", "tx_pkts", "tx_pps", "tx_bytes", "tx_bps", "tx_iops", "tx_err_iops"})
		tbl.SetAlignment(tablewriter.ALIGN_RIGHT)
		tbl.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})

		sum := struct {
			netutil.Statistics
			netutil.StatisticsRate
		}{}
		for _, tx := range txList {
			stat := tx.Stats()
			rate := stat.Rate(prev[tx.Fd()])
			prev[tx.Fd()] = stat

			tbl.Append([]string{
				fmt.Sprintf("%d", tx.QueueID()),
				fmt.Sprintf("%d", stat.TxPackets),
				fmt.Sprintf("%.0f", rate.TxPPS),
				humanize.Bytes(int(stat.TxBytes)),
				humanize.BitsRate(int(rate.TxBPS)),
				fmt.Sprintf("%.0f", rate.TxIOPS),
				fmt.Sprintf("%.0f", rate.TxErrorPS),
			})
			sum.TxPackets += stat.TxPackets
			sum.TxBytes += stat.TxBytes
			sum.TxPPS += rate.TxPPS
			sum.TxBPS += rate.TxBPS
			sum.TxIOPS += rate.TxIOPS
			sum.TxErrorPS += rate.TxErrorPS
		}
		tbl.Append([]string{
			"SUM",
			fmt.Sprintf("%d", sum.TxPackets),
			fmt.Sprintf("%.0f", sum.TxPPS),
			humanize.Bytes(int(sum.TxBytes)),
			humanize.BitsRate(int(sum.TxBPS)),
			fmt.Sprintf("%.0f", sum.TxIOPS),
			fmt.Sprintf("%.0f", sum.TxErrorPS),
		})
		tbl.Render()
		fmt.Println()
	}
}
