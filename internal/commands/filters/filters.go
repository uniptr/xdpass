package filters

import (
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/xdpprog"
)

type filter struct{}

func (f filter) handleCommand() error {
	if opt.showList {
		return f.showList()
	}

	if opt.add {
		return f.opRule(protos.FilterOperation_Add, opt.key)
	}

	if opt.del {
		return f.opRule(protos.FilterOperation_Del, opt.key)
	}
	return nil
}

func (f filter) showList() error {
	req := protos.FilterReq{Operation: protos.FilterOperation_List}
	resp, err := commands.GetMessage[protos.FilterReq, protos.FilterResp](protos.Type_Filter, commands.DefUnixSock, &req)
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Interface", "Keys"})
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	table.SetAutoMergeCells(true)

	for _, ik := range resp.Rules {
		for _, k := range ik.Keys {
			table.Append([]string{ik.Interface, k.String()})
		}
	}
	table.Render()

	return nil
}

func (f filter) opRule(op protos.FilterOperation, key xdpprog.IPLpmKey) error {
	req := protos.FilterReq{Operation: op, Rules: []protos.FilterRule{{Keys: []xdpprog.IPLpmKey{key}}}}
	_, err := commands.GetMessage[protos.FilterReq, protos.FilterResp](protos.Type_Filter, "", &req)
	return err
}
