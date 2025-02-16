package bench

import (
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
)

type rateLimitPrecision int

const (
	rateLimitLow = iota
	rateLimitMid
	rateLimitHigh

	rateLimitStrLow  = "low"
	rateLimitStrMid  = "mid"
	rateLimitStrHigh = "high"
)

func rateLimitPrecisionFrom(s string) rateLimitPrecision {
	switch s {
	case rateLimitStrMid:
		return rateLimitMid
	case rateLimitStrHigh:
		return rateLimitHigh
	default:
		return rateLimitLow
	}
}

func (r *rateLimitPrecision) String() string {
	switch *r {
	case rateLimitLow:
		return rateLimitStrLow
	case rateLimitMid:
		return rateLimitStrMid
	case rateLimitHigh:
		return rateLimitStrHigh
	default:
		return ""
	}
}

func (r *rateLimitPrecision) Set(s string) error {
	*r = rateLimitPrecisionFrom(s)
	return nil
}

func (*rateLimitPrecision) Type() string {
	return "string"
}

type rateLimiter struct {
	rateLimiter rate.Limiter
	limitN      int
	precision   rateLimitPrecision

	nowTs unix.Timespec
}

func newRateLimiter(lim int, perc rateLimitPrecision) *rateLimiter {
	return &rateLimiter{
		rateLimiter: *rate.NewLimiter(rate.Limit(lim), 1),
		limitN:      lim,
		precision:   perc,
	}
}

func (r *rateLimiter) allow() bool {
	if r.limitN == -1 {
		return true
	}

	switch r.precision {
	case rateLimitMid:
		err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &r.nowTs)
		if err == nil {
			r.nowTs = unix.NsecToTimespec(r.nowTs.Nano() + int64(time.Second/time.Duration(opt.rateLimit)))
			err = unix.ClockNanosleep(unix.CLOCK_MONOTONIC, unix.TIMER_ABSTIME, &r.nowTs, nil)
			if err == nil {
				return true
			}
		}
	case rateLimitHigh:
		return r.rateLimiter.Allow()
	}

	time.Sleep(time.Second / time.Duration(opt.rateLimit))
	return true
}
