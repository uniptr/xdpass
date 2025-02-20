package netutil

import "time"

type Statistics struct {
	RxPackets uint64
	TxPackets uint64
	RxBytes   uint64
	TxBytes   uint64
	RxIOs     uint64 // recv
	TxIOs     uint64 // sendto
	RxErrors  uint64
	TxErrors  uint64
	RxDropped uint64
	TxDropped uint64
	Timestamp time.Time // Get statistics time
}

type StatisticsRate struct {
	RxPPS       float64 // Packets Per Second
	TxPPS       float64
	RxBPS       float64 // Bits Per Second
	TxBPS       float64
	RxIOPS      float64 // IOs Per Second
	TxIOPS      float64
	RxErrorPS   float64 // Errors Per Second
	TxErrorPS   float64
	RxDroppedPS float64 // Dropped Per Second
	TxDroppedPS float64
}

func (s Statistics) Rate(prev Statistics) StatisticsRate {
	pps := func(prev, curr uint64, period float64) float64 {
		packets := curr - prev
		return float64(packets) / period
	}

	bps := func(prev, curr uint64, period float64) float64 {
		bytes := curr - prev
		return float64(bytes*8) / period
	}

	iops := func(prev, curr uint64, period float64) float64 {
		ios := curr - prev
		return float64(ios) / period
	}

	ioerrps := func(prev, curr uint64, period float64) float64 {
		ioerrs := curr - prev
		return float64(ioerrs) / period
	}

	dps := func(prev, curr uint64, period float64) float64 {
		dropped := curr - prev
		return float64(dropped) / period
	}

	period := float64(s.Timestamp.Sub(prev.Timestamp)) / float64(time.Second)
	if period == 0.0 {
		return StatisticsRate{}
	}
	return StatisticsRate{
		RxPPS:       pps(prev.RxPackets, s.RxPackets, period),
		TxPPS:       pps(prev.TxPackets, s.TxPackets, period),
		RxBPS:       bps(prev.RxBytes, s.RxBytes, period),
		TxBPS:       bps(prev.TxBytes, s.TxBytes, period),
		RxIOPS:      iops(prev.RxIOs, s.RxIOs, period),
		TxIOPS:      iops(prev.TxIOs, s.TxIOs, period),
		RxErrorPS:   ioerrps(prev.RxErrors, s.RxErrors, period),
		TxErrorPS:   ioerrps(prev.TxErrors, s.TxErrors, period),
		RxDroppedPS: dps(prev.RxDropped, s.RxDropped, period),
		TxDroppedPS: dps(prev.TxDropped, s.TxDropped, period),
	}
}
