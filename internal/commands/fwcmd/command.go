package fwcmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/exports"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/xdpprog"
)

func init() {
	commands.SetFlagsInterface(fwCmd.Flags(), &opt.Interface)
	fwCmd.Flags().BoolVarP(&opt.ShowList, "list", "l", false, "List filter ip")
	fwCmd.Flags().BoolVarP(&opt.Add, "add", "a", false, "Add filter ip")
	fwCmd.Flags().BoolVarP(&opt.Del, "del", "d", false, "Del filter ip")
	fwCmd.Flags().Var(&opt.Key, "key", "IP key for filter")

	commands.Register(fwCmd)
}

type FirwallOpt struct {
	Interface string
	ShowList  bool
	Add       bool
	Del       bool
	Key       xdpprog.IPLpmKey
}

var opt FirwallOpt

var fwCmd = &cobra.Command{
	Use:   protos.TypeFirewall.String(),
	Short: "Manage network traffic firewall",
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()
		return FirewallCommand{}.DoReq(&opt)
	},
}

type FirewallCommand struct{}

func (f FirewallCommand) DoReq(opt *FirwallOpt) error {
	if opt.ShowList {
		return f.DoReqListIPKey(opt.Interface)
	}

	if opt.Add {
		return f.DoReqEditIPKey(protos.OperationAdd, opt.Interface, opt.Key)
	}

	if opt.Del {
		return f.DoReqEditIPKey(protos.OperationDel, opt.Interface, opt.Key)
	}
	return nil
}

func (FirewallCommand) DoReqListIPKey(ifaceName string) error {
	req := protos.FirewallReq{Operation: protos.OperationList, Interface: ifaceName}
	resp, err := commands.GetMessage[protos.FirewallReq, protos.FirewallResp](protos.TypeFirewall, "", &req)
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

func (FirewallCommand) DoReqEditIPKey(op protos.Operation, iface string, key xdpprog.IPLpmKey) error {
	req := protos.FirewallReq{Operation: op, Interface: iface, Keys: []xdpprog.IPLpmKey{key}}
	_, err := commands.GetMessage[protos.FirewallReq, protos.FirewallResp](protos.TypeFirewall, "", &req)
	return err
}

type FirewallCommandHandle struct{}

func (FirewallCommandHandle) CommandType() protos.Type {
	return protos.TypeFirewall
}

func (f FirewallCommandHandle) HandleReqData(client *commands.MessageClient, data []byte) error {
	var req protos.FirewallReq
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	var err error
	switch req.Operation {
	case protos.OperationNop:
		data, err = []byte("{}"), nil
	case protos.OperationList:
		data, err = f.handleOpShowList(req.Interface)
	case protos.OperationAdd:
		data, err = f.handleOpAddDel(req, protos.OperationAdd, func(api exports.FirewallAPI, key xdpprog.IPLpmKey) error {
			return api.AddIPKey(key)
		})
	case protos.OperationDel:
		data, err = f.handleOpAddDel(req, protos.OperationDel, func(api exports.FirewallAPI, key xdpprog.IPLpmKey) error {
			return api.DelIPKey(key)
		})
	}
	if err != nil {
		return commands.ResponseError(client, err)
	}
	return commands.Response(client, &protos.MessageResp{Data: data})
}

func (f FirewallCommandHandle) getAPIs(ifaceName string) (map[string]exports.FirewallAPI, error) {
	var apis map[string]exports.FirewallAPI
	if ifaceName != "" {
		api, ok := exports.GetFirewallAPI(ifaceName)
		if !ok {
			return nil, fmt.Errorf("interface %s not found", ifaceName)
		}
		apis = map[string]exports.FirewallAPI{ifaceName: api}
	} else {
		apis = exports.GetFirewallAPIs()
	}
	return apis, nil
}

func (f FirewallCommandHandle) handleOpShowList(ifaceName string) ([]byte, error) {
	apis, err := f.getAPIs(ifaceName)
	if err != nil {
		return nil, err
	}

	resp := protos.FirewallResp{}
	for name, api := range apis {
		keys, err := api.ListIPKey()
		if err != nil {
			return nil, err
		}
		resp.Interfaces = append(resp.Interfaces, protos.FirewallIPKeys{
			Interface: name,
			Keys:      keys,
		})
	}
	return json.Marshal(resp)
}

func (f FirewallCommandHandle) handleOpAddDel(req protos.FirewallReq, op protos.Operation, fn func(exports.FirewallAPI, xdpprog.IPLpmKey) error) ([]byte, error) {
	apis, err := f.getAPIs(req.Interface)
	if err != nil {
		return nil, err
	}

	for _, api := range apis {
		for _, key := range req.Keys {
			logrus.WithFields(logrus.Fields{"key": key, "iface": req.Interface, "op": op}).Debug("Operate ip lpm key")
			err := fn(api, key)
			if err != nil {
				return nil, err
			}
		}
	}
	return []byte("{}"), nil
}
