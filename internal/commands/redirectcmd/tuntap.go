package redirectcmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/exports"
	"github.com/zxhio/xdpass/internal/protos"
)

func init() {
	commands.SetFlagsInterface(tunCmd.Flags(), &tuntapOpt.Interface)
	commands.SetFlagsList(tunCmd.Flags(), &tuntapOpt.ShowList, "List tuntap devices info")
	tunCmd.Flags().StringSliceVarP(&tuntapOpt.AddTuns, "add-tun", "U", []string{}, "Add tun devices")
	tunCmd.Flags().StringSliceVarP(&tuntapOpt.AddTaps, "add-tap", "A", []string{}, "Add tap devices")
	tunCmd.Flags().StringSliceVarP(&tuntapOpt.DelDevices, "del", "D", []string{}, "Delete tuntap devices")

	commands.Register(tunCmd)
	redirectCmd.AddCommand(tunCmd)

	registerHandle(TuntapCommandHandle{})
}

var tuntapOpt TuntapOpt

type TuntapOpt struct {
	Interface  string
	ShowList   bool
	AddTuns    []string
	AddTaps    []string
	DelDevices []string
}

var tunCmd = &cobra.Command{
	Use:   protos.RedirectTypeTuntap.String(),
	Short: "Redirect network traffic to tuntap devices",
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()
		var t TuntapCommandClient
		return t.DoReq(&tuntapOpt)
	},
}

type TuntapCommandClient struct{}

func (t TuntapCommandClient) DoReq(opt *TuntapOpt) error {
	if opt.ShowList {
		return t.DoReqShow(opt.Interface)
	}
	if len(opt.AddTuns) > 0 {
		return t.DoReqEdit(protos.OperationAdd, opt.Interface, opt.AddTuns, netlink.TUNTAP_MODE_TUN)
	}
	if len(opt.AddTaps) > 0 {
		return t.DoReqEdit(protos.OperationAdd, opt.Interface, opt.AddTaps, netlink.TUNTAP_MODE_TAP)
	}
	if len(opt.DelDevices) > 0 {
		return t.DoReqEdit(protos.OperationDel, opt.Interface, opt.DelDevices, 0)
	}
	return nil
}

func (TuntapCommandClient) DoReqShow(ifaceName string) error {
	req := protos.TuntapReq{Operation: protos.OperationList, Interface: ifaceName}
	resp, err := doRequest[protos.TuntapReq, protos.TuntapResp](protos.RedirectTypeTuntap, &req)
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	table.SetHeader([]string{"Index", "Device", "Mode"})
	for _, dev := range resp.Interfaces {
		for _, d := range dev.Devices {
			table.Append([]string{dev.Interface, d.Name, d.Mode.String()})
		}
	}
	table.Render()

	return nil
}

func (TuntapCommandClient) DoReqEdit(op protos.Operation, ifaceName string, devs []string, mode netlink.TuntapMode) error {
	req := protos.TuntapReq{Operation: op, Interface: ifaceName}
	for _, dev := range devs {
		req.Devices = append(req.Devices, protos.TuntapDevice{Name: dev, Mode: mode})
	}
	_, err := doRequest[protos.TuntapReq, protos.TuntapResp](protos.RedirectTypeTuntap, &req)
	return err
}

type TuntapCommandHandle struct{}

func (TuntapCommandHandle) RedirectType() protos.RedirectType {
	return protos.RedirectTypeTuntap
}

func (t TuntapCommandHandle) HandleReqData(client *commands.MessageClient, data []byte) error {
	var req protos.TuntapReq
	err := json.Unmarshal(data, &req)
	if err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}

	switch req.Operation {
	case protos.OperationList:
		data, err = t.handleOpList(req.Interface)
	case protos.OperationAdd:
		data, err = t.handleOpEdit(&req, func(api exports.RedirectTuntapAPI, d *protos.TuntapDevice) error { return api.AddTuntap(d) })
	case protos.OperationDel:
		data, err = t.handleOpEdit(&req, func(api exports.RedirectTuntapAPI, d *protos.TuntapDevice) error { return api.DelTuntap(d) })
	}
	if err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}
	return response(client, data)
}

func (TuntapCommandHandle) getAPIs(ifaceName string) (map[string]exports.RedirectTuntapAPI, error) {
	var apis map[string]exports.RedirectTuntapAPI
	if ifaceName == "" {
		apis = exports.GetAllTuntapAPIs()
	} else {
		api, ok := exports.GetTuntapAPI(ifaceName)
		if !ok {
			return nil, fmt.Errorf("interface %s not found", ifaceName)
		}
		apis = map[string]exports.RedirectTuntapAPI{ifaceName: api}
	}
	return apis, nil
}

func (t TuntapCommandHandle) handleOpList(ifaceName string) ([]byte, error) {
	apis, err := t.getAPIs(ifaceName)
	if err != nil {
		return nil, err
	}

	resp := protos.TuntapResp{}
	for name, api := range apis {
		resp.Interfaces = append(resp.Interfaces, protos.TuntapInterfaceDevices{
			Interface: name,
			Devices:   api.GetTuntaps(),
		})
	}
	return json.Marshal(resp)
}

func (t TuntapCommandHandle) handleOpEdit(req *protos.TuntapReq, edit func(api exports.RedirectTuntapAPI, device *protos.TuntapDevice) error) ([]byte, error) {
	apis, err := t.getAPIs(req.Interface)
	if err != nil {
		return nil, err
	}

	for _, api := range apis {
		for _, device := range req.Devices {
			l := logrus.WithFields(logrus.Fields{
				"interface": req.Interface,
				"device":    device,
				"op":        req.Operation,
			})
			l.Info("Operate tuntap device")

			if err := edit(api, &device); err != nil {
				l.WithError(err).Error("Fail to operate tuntap device")
				return nil, err
			}
		}
	}
	return []byte("{}"), nil
}
