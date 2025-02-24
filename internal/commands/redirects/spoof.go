package redirects

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/xdpprog"
)

type spoofOpt struct {
	showList  bool
	showTypes bool
	add       bool
	del       bool
	typ       protos.SpoofType
	srcIPLPM  xdpprog.IPLpmKey
	dstIPLPM  xdpprog.IPLpmKey
	srcPort   uint16
	dstPort   uint16
}

var spoofCmd = &cobra.Command{
	Use:   protos.RedirectTypeStr_Spoof,
	Short: "Traffic spoof based on rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		return spoof{}.handleCommand()
	},
}

func init() {
	commands.SetFlagsList(spoofCmd.Flags(), &opt.spoof.showList, "Show spoof rule list")
	spoofCmd.Flags().BoolVar(&opt.spoof.showTypes, "list-types", false, "Show supported spoof type list")
	spoofCmd.Flags().BoolVar(&opt.spoof.add, "add", false, "Add spoof rule")
	spoofCmd.Flags().BoolVar(&opt.spoof.del, "del", false, "Delete spoof rule")
	spoofCmd.Flags().VarP(&opt.spoof.srcIPLPM, "src-ip", "s", "Source IP")
	spoofCmd.Flags().VarP(&opt.spoof.dstIPLPM, "dst-ip", "d", "Destination IP")
	spoofCmd.Flags().Uint16Var(&opt.spoof.srcPort, "src-port", 0, "Source port")
	spoofCmd.Flags().Uint16Var(&opt.spoof.dstPort, "dst-port", 0, "Destination port")
	spoofCmd.Flags().VarP(&opt.spoof.typ, "spoof-type", "t", "Type for spoof rule")

	redirectCmd.AddCommand(spoofCmd)
}

type spoof struct{}

func (s spoof) handleCommand() error {
	commands.SetVerbose()

	if opt.spoof.showList {
		return s.showList()
	}

	if opt.spoof.showTypes {
		return s.showListTypes()
	}

	if opt.spoof.add {
		return s.opRule(protos.SpoofOperation_Add)
	}

	if opt.spoof.del {
		return s.opRule(protos.SpoofOperation_Del)
	}
	return nil
}

func (spoof) showList() error {
	req := protos.SpoofReq{Operation: protos.SpoofOperation_List}
	resp, err := postRequest[protos.SpoofReq, protos.SpoofResp](protos.RedirectType_Spoof, &req)
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Spoof Type", "Src IP", "Dst IP", "Src Port", "Dst Port"})
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	for _, rule := range resp.Rules {
		table.Append([]string{
			fmt.Sprintf("%d", rule.ID), rule.SpoofType.String(),
			rule.SrcIPAddrLPM.String(), rule.DstIPAddrLPM.String(),
			fmt.Sprintf("%d", rule.SrcPort), fmt.Sprintf("%d", rule.DstPort),
		})
	}
	table.Render()

	return nil
}

func (spoof) showListTypes() error {
	req := protos.SpoofReq{Operation: protos.SpoofOperation_ListTypes}
	resp, err := postRequest[protos.SpoofReq, protos.SpoofResp](protos.RedirectType_Spoof, &req)
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Supported Spoof Type"})
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	for _, typ := range resp.Rules {
		table.Append([]string{typ.SpoofType.String()})
	}
	table.Render()

	return nil
}

func (spoof) opRule(op protos.SpoofOperation) error {
	req := protos.SpoofReq{Operation: op, Rules: []protos.SpoofRule{{
		SpoofType:    opt.spoof.typ,
		SrcIPAddrLPM: opt.spoof.srcIPLPM,
		DstIPAddrLPM: opt.spoof.dstIPLPM,
		SrcPort:      opt.spoof.srcPort,
		DstPort:      opt.spoof.dstPort,
	}}}
	_, err := postRequest[protos.SpoofReq, protos.SpoofResp](protos.RedirectType_Spoof, &req)
	return err
}
