package redirects

import (
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
)

type spoofOpt struct {
	showList    bool
	showTypes   bool
	add         bool
	del         bool
	typ         protos.SpoofType
	source      protos.AddrPort
	destination protos.AddrPort
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
	spoofCmd.Flags().VarP(&opt.spoof.source, "source", "s", "Source address")
	spoofCmd.Flags().VarP(&opt.spoof.destination, "dest", "d", "Destination address")
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
	table.SetHeader([]string{"Interface", "Spoof Type", "Source", "Destination"})
	for _, rule := range resp.Rules {
		table.Append([]string{rule.Interface, rule.SpoofType.String(), rule.Source.String(), rule.Destination.String()})
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
		Interface:   opt.ifaceName,
		SpoofType:   opt.spoof.typ,
		Source:      opt.spoof.source,
		Destination: opt.spoof.destination,
	}}}
	_, err := postRequest[protos.SpoofReq, protos.SpoofResp](protos.RedirectType_Spoof, &req)
	return err
}
