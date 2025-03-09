package statscmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/exports"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/humanize"
	"github.com/zxhio/xdpass/pkg/netutil"
)

var statsCommand = &cobra.Command{
	Use:   protos.TypeStats.String(),
	Short: "Display a live stream of network traffic statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()
		return StatsCommandClient{}.DoReq(opt)
	},
}

func init() {
	commands.SetFlagsInterface(statsCommand.Flags(), &opt.Interface)
	statsCommand.Flags().DurationVarP(&opt.StatsDur, "duration", "d", time.Second*3, "Statistics duration")
	commands.Register(statsCommand)
}

type StatsOpt struct {
	Interface string
	StatsDur  time.Duration
}

var opt StatsOpt

type StatsCommandClient struct{}

func (StatsCommandClient) DoReq(opt StatsOpt) error {
	statsKey := func(iface string, queueID uint32) string {
		return fmt.Sprintf("%s:%d", iface, queueID)
	}
	prev := make(map[string]netutil.Statistics)

	timer := time.NewTicker(opt.StatsDur)
	for range timer.C {
		tbl := tablewriter.NewWriter(os.Stdout)
		tbl.SetHeader([]string{"interface", "queue", "rx_pkts", "rx_pps", "tx_pkts", "tx_pps", "rx_bytes", "rx_bps", "rx_iops", "rx_err_iops"})
		tbl.SetAutoMergeCellsByColumnIndex([]int{0})
		tbl.SetAlignment(tablewriter.ALIGN_CENTER)

		sum := struct {
			netutil.Statistics
			netutil.StatisticsRate
		}{}

		req := &protos.StatsReq{Interface: opt.Interface}
		resp, err := commands.GetMessageByAddr[protos.StatsReq, protos.StatsResp](commands.DefUnixSock, protos.TypeStats, "", req)
		if err != nil {
			return err
		}
		sort.Sort(statsSlice(resp.Interfaces))
		for _, iface := range resp.Interfaces {
			for _, queue := range iface.Queues {
				stat := queue.Statistics
				rate := stat.Rate(prev[statsKey(iface.Interface, queue.QueueID)])
				prev[statsKey(iface.Interface, queue.QueueID)] = stat

				tbl.Append([]string{
					iface.Interface,
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
		}

		tbl.SetFooter([]string{
			"SUM",
			fmt.Sprintf("%d", len(resp.Interfaces)),
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

type statsSlice []protos.InterfaceStats

func (s statsSlice) Len() int           { return len(s) }
func (s statsSlice) Less(i, j int) bool { return s[i].Interface < s[j].Interface }
func (s statsSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

type StatsCommandHandle struct{}

func (StatsCommandHandle) CommandType() protos.Type {
	return protos.TypeStats
}

func (StatsCommandHandle) HandleReqData(client *commands.MessageClient, data []byte) error {
	req := &protos.StatsReq{}
	if err := json.Unmarshal(data, req); err != nil {
		return err
	}

	var apis map[string]exports.StatsAPI
	if req.Interface != "" {
		api, ok := exports.GetStatsAPI(req.Interface)
		if !ok {
			return errors.New("interface not found")
		}
		apis = map[string]exports.StatsAPI{req.Interface: api}
	} else {
		apis = exports.GetStatsAPIs()
	}

	resp := &protos.StatsResp{}
	resp.Interfaces = make([]protos.InterfaceStats, len(apis))
	for ifaceName, api := range apis {
		stats := api.GetQueueStats()
		resp.Interfaces = append(resp.Interfaces, protos.InterfaceStats{
			Interface: ifaceName,
			Queues:    stats,
		})
	}
	return commands.ResponseMessage(client, resp)
}
