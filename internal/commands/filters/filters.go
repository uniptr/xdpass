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
		return f.opRule(protos.OperationAdd, opt.ifaceName, opt.key)
	}

	if opt.del {
		return f.opRule(protos.OperationDel, opt.ifaceName, opt.key)
	}
	return nil
}

func (f filter) showList() error {
	req := protos.FilterReq{Operation: protos.OperationList, Interface: opt.ifaceName}
	resp, err := commands.GetMessage[protos.FilterReq, protos.FilterResp](protos.TypeFilter, "", &req)
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Interface", "Keys"})
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	table.SetAutoMergeCells(true)

	for _, ik := range resp.Interfaces {
		for _, key := range ik.Keys {
			table.Append([]string{ik.Interface, key.String()})
		}
	}
	table.Render()

	return nil
}

func (f filter) opRule(op protos.Operation, iface string, key xdpprog.IPLpmKey) error {
	req := protos.FilterReq{Operation: op, Interface: iface, Keys: []xdpprog.IPLpmKey{key}}
	_, err := commands.GetMessage[protos.FilterReq, protos.FilterResp](protos.TypeFilter, "", &req)
	return err
}
