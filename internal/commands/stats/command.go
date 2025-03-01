package stats

import (
	"fmt"
	"os"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/humanize"
	"github.com/zxhio/xdpass/pkg/netutil"
)

var statsCommand = &cobra.Command{
	Use:   protos.TypeStats.String(),
	Short: "Display a live stream of network traffic statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()
		return opt.run()
	},
}

type statsOpt struct {
	stats time.Duration
}

var opt statsOpt

func init() {
	statsCommand.Flags().DurationVarP(&opt.stats, "duration", "d", time.Second*3, "Statistics duration")
	commands.Register(statsCommand)
}

func (o statsOpt) run() error {
	prev := make(map[uint32]netutil.Statistics)

	timer := time.NewTicker(o.stats)
	for range timer.C {
		tbl := tablewriter.NewWriter(os.Stdout)
		tbl.SetHeader([]string{"queue", "rx_pkts", "rx_pps", "tx_pkts", "tx_pps", "rx_bytes", "rx_bps", "rx_iops", "rx_err_iops"})
		tbl.SetAlignment(tablewriter.ALIGN_RIGHT)
		tbl.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})

		sum := struct {
			netutil.Statistics
			netutil.StatisticsRate
		}{}
		resp, err := commands.GetMessageByAddr[protos.StatsReq, protos.StatsResp](commands.DefUnixSock, protos.TypeStats, "", nil)
		if err != nil {
			return err
		}
		for _, queue := range resp.Queues {
			stat := queue.Statistics
			rate := stat.Rate(prev[queue.QueueID])
			prev[queue.QueueID] = stat

			tbl.Append([]string{
				fmt.Sprintf("%d", queue.QueueID),
				fmt.Sprintf("%d", stat.RxPackets),
				fmt.Sprintf("%.0f", rate.RxPPS),
				fmt.Sprintf("%d", stat.TxPackets),
				fmt.Sprintf("%.0f", rate.TxPPS),
				humanize.Bytes(int(stat.RxBytes)),
				humanize.BitsRate(int(rate.RxBPS)),
				fmt.Sprintf("%.0f", rate.RxIOPS),
				fmt.Sprintf("%.0f", rate.RxErrorPS),
			})

			sum.RxPackets += stat.RxPackets
			sum.TxPackets += stat.TxPackets
			sum.RxBytes += stat.RxBytes
			sum.RxPPS += rate.RxPPS
			sum.TxPPS += rate.TxPPS
			sum.RxBPS += rate.RxBPS
			sum.RxIOPS += rate.RxIOPS
			sum.RxErrorPS += rate.RxErrorPS
		}
		tbl.Append([]string{
			"SUM",
			fmt.Sprintf("%d", sum.RxPackets),
			fmt.Sprintf("%.0f", sum.RxPPS),
			fmt.Sprintf("%d", sum.TxPackets),
			fmt.Sprintf("%.0f", sum.TxPPS),
			humanize.Bytes(int(sum.RxBytes)),
			humanize.BitsRate(int(sum.RxBPS)),
			fmt.Sprintf("%.0f", sum.RxIOPS),
			fmt.Sprintf("%.0f", sum.RxErrorPS),
		})
		tbl.Render()
		fmt.Println()
	}

	return nil
}
