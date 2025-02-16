package humanize

import "fmt"

const (
	// For decimal (SI) units: KB, MB, GB, etc.
	SIUnitBase = 1000

	// For binary (IEC) units: KiB, MiB, GiB, etc.
	IECUnitBase = 1024
)

var (
	siUnits  = []string{"", "K", "M", "G", "T", "P", "E"}
	iecUnits = []string{"", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei"}
)

func Bytes(bytes int) string  { return FormatSIUnit(bytes, "Bytes") }
func IBytes(bytes int) string { return FormatIECUnit(bytes, "Bytes") }

func BytesRate(bytes int) string  { return FormatSIUnit(bytes, "Bytes/s") }
func IBytesRate(bytes int) string { return FormatIECUnit(bytes, "Bytes/s") }

func Bits(bits int) string  { return FormatSIUnit(bits, "Bits") }
func IBits(bits int) string { return FormatIECUnit(bits, "Bits") }

func BitsRate(bits int) string  { return FormatSIUnit(bits, "Bits/s") }
func IBitsRate(bits int) string { return FormatIECUnit(bits, "Bits/s") }

func FormatSIUnit(b int, suffix string) string  { return formatUnit(b, SIUnitBase, siUnits) + suffix }
func FormatIECUnit(b int, suffix string) string { return formatUnit(b, IECUnitBase, iecUnits) + suffix }

func formatUnit(b, base int, units []string) string {
	if b < base {
		return fmt.Sprintf("%d %s", b, units[0])
	}
	var value float64 = float64(b)
	for i := 1; i < len(units); i++ {
		value /= float64(base)
		if value < float64(base) {
			return fmt.Sprintf("%.1f %s", value, units[i])
		}
	}
	return fmt.Sprintf("%.1f %s", value, units[len(units)-1])
}
