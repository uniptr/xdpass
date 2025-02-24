package redirects

import (
	"os"
	"strconv"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
)

var tunCmd = &cobra.Command{
	Use:   protos.RedirectTypeStr_Tuntap,
	Short: "Redirect network traffic to tuntap devices",
	RunE: func(cmd *cobra.Command, args []string) error {
		return tuntap{}.handleCommand(&opt.tuntap)
	},
}

type tunOpt struct {
	show       bool
	addTuns    []string
	addTaps    []string
	delDevices []string
}

func init() {
	// Tuntap
	commands.SetFlagsList(tunCmd.Flags(), &opt.tuntap.show, "List tuntap devices info")
	tunCmd.Flags().StringSliceVarP(&opt.tuntap.addTuns, "add-tun", "U", []string{}, "Add tun devices")
	tunCmd.Flags().StringSliceVarP(&opt.tuntap.addTaps, "add-tap", "A", []string{}, "Add tap devices")
	tunCmd.Flags().StringSliceVarP(&opt.tuntap.delDevices, "del", "D", []string{}, "Delete tuntap devices")
	redirectCmd.AddCommand(tunCmd)
}

type tuntap struct{}

func (t tuntap) handleCommand(opt *tunOpt) error {
	commands.SetVerbose()

	if opt.show {
		return t.show()
	}

	if len(opt.addTuns) > 0 {
		return t.postRules(protos.TuntapOperation_Add, opt.addTuns, netlink.TUNTAP_MODE_TUN)
	}
	if len(opt.addTaps) > 0 {
		return t.postRules(protos.TuntapOperation_Add, opt.addTaps, netlink.TUNTAP_MODE_TAP)
	}
	if len(opt.delDevices) > 0 {
		return t.postRules(protos.TuntapOperation_Del, opt.delDevices, netlink.TUNTAP_MODE_TAP)
	}
	return nil
}

func (tuntap) show() error {
	var req protos.TuntapReq
	req.Operation = protos.TuntapOperation_List

	resp, err := postRequest[protos.TuntapReq, protos.TuntapResp](protos.RedirectType_Tuntap, &req)
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	table.SetHeader([]string{"Index", "Device", "Mode"})
	for i, dev := range resp.Devices {
		table.Append([]string{strconv.Itoa(i + 1), dev.Name, dev.Mode.String()})
	}
	table.Render()

	return nil
}

func (tuntap) postRules(op protos.TuntapOperation, devs []string, mode netlink.TuntapMode) error {
	var req protos.TuntapReq
	req.Operation = op
	req.Devices = []protos.TuntapDevice{}
	for _, dev := range devs {
		req.Devices = append(req.Devices, protos.TuntapDevice{Name: dev, Mode: mode})
	}
	_, err := postRequest[protos.TuntapReq, protos.TuntapResp](protos.RedirectType_Tuntap, &req)
	return err
}
