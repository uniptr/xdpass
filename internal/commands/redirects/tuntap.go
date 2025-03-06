package redirects

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
)

func init() {
	// Tuntap
	commands.SetFlagsList(tunCmd.Flags(), &opt.tuntap.ShowList, "List tuntap devices info")
	tunCmd.Flags().StringSliceVarP(&opt.tuntap.AddTuns, "add-tun", "U", []string{}, "Add tun devices")
	tunCmd.Flags().StringSliceVarP(&opt.tuntap.AddTaps, "add-tap", "A", []string{}, "Add tap devices")
	tunCmd.Flags().StringSliceVarP(&opt.tuntap.DelDevices, "del", "D", []string{}, "Delete tuntap devices")
	redirectCmd.AddCommand(tunCmd)
}

var tunCmd = &cobra.Command{
	Use:   protos.RedirectTypeTuntap.String(),
	Short: "Redirect network traffic to tuntap devices",
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()
		var t TuntapCommand
		return t.DoReq(opt.ifaceName, &opt.tuntap)
	},
}

type TuntapOpt struct {
	ShowList   bool
	AddTuns    []string
	AddTaps    []string
	DelDevices []string
}

type TuntapResolver interface {
	GetTuntaps() []protos.TuntapDevice
	AddTuntap(device *protos.TuntapDevice) error
	DelTuntap(device *protos.TuntapDevice) error
}

type TuntapCommand struct {
	mu               *sync.Mutex
	interfaceTuntaps map[string]TuntapResolver
}

func NewTuntapCommand() *TuntapCommand {
	return &TuntapCommand{
		mu:               &sync.Mutex{},
		interfaceTuntaps: make(map[string]TuntapResolver),
	}
}

func (t TuntapCommand) RedirectType() protos.RedirectType {
	return protos.RedirectTypeTuntap
}

func (t *TuntapCommand) DoReq(ifaceName string, opt *TuntapOpt) error {
	if opt.ShowList {
		return t.DoReqShow(ifaceName)
	}
	if len(opt.AddTuns) > 0 {
		return t.DoReqEdit(protos.OperationAdd, ifaceName, opt.AddTuns, netlink.TUNTAP_MODE_TUN)
	}
	if len(opt.AddTaps) > 0 {
		return t.DoReqEdit(protos.OperationAdd, ifaceName, opt.AddTaps, netlink.TUNTAP_MODE_TAP)
	}
	if len(opt.DelDevices) > 0 {
		return t.DoReqEdit(protos.OperationDel, ifaceName, opt.DelDevices, netlink.TUNTAP_MODE_TAP)
	}
	return nil
}

func (t *TuntapCommand) DoReqShow(ifaceName string) error {
	req := protos.TuntapReq{Operation: protos.OperationList, Interface: ifaceName}
	resp, err := getResponse[protos.TuntapReq, protos.TuntapResp](protos.RedirectTypeTuntap, &req)
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

func (t *TuntapCommand) DoReqEdit(op protos.Operation, ifaceName string, devs []string, mode netlink.TuntapMode) error {
	req := protos.TuntapReq{Operation: op, Interface: ifaceName}
	for _, dev := range devs {
		req.Devices = append(req.Devices, protos.TuntapDevice{Name: dev, Mode: mode})
	}
	_, err := getResponse[protos.TuntapReq, protos.TuntapResp](protos.RedirectTypeTuntap, &req)
	return err
}

// Server

func (t *TuntapCommand) HandleReqData(client *commands.MessageClient, data []byte) error {
	var req protos.TuntapReq
	err := json.Unmarshal(data, &req)
	if err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	switch req.Operation {
	case protos.OperationList:
		data, err = t.handleOpList(req.Interface)
	case protos.OperationAdd:
		data, err = t.handleOpEdit(&req, func(r TuntapResolver, d *protos.TuntapDevice) error { return r.AddTuntap(d) })
	case protos.OperationDel:
		data, err = t.handleOpEdit(&req, func(r TuntapResolver, d *protos.TuntapDevice) error { return r.DelTuntap(d) })
	}
	if err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}
	return ResponseRedirectData(client, data)
}

func (t *TuntapCommand) getResolvers(ifaceName string) (map[string]TuntapResolver, error) {
	var resolvers map[string]TuntapResolver
	if ifaceName == "" {
		resolvers = t.interfaceTuntaps
	} else {
		iface, ok := t.interfaceTuntaps[ifaceName]
		if !ok {
			return nil, fmt.Errorf("interface %s not found", ifaceName)
		}
		resolvers = map[string]TuntapResolver{ifaceName: iface}
	}
	return resolvers, nil
}

func (t *TuntapCommand) handleOpList(ifaceName string) ([]byte, error) {
	resolvers, err := t.getResolvers(ifaceName)
	if err != nil {
		return nil, err
	}

	resp := protos.TuntapResp{}
	for name, resolver := range resolvers {
		resp.Interfaces = append(resp.Interfaces, protos.TuntapInterfaceDevices{
			Interface: name,
			Devices:   resolver.GetTuntaps(),
		})
	}
	return json.Marshal(resp)
}

func (t *TuntapCommand) handleOpEdit(req *protos.TuntapReq, edit func(resolver TuntapResolver, device *protos.TuntapDevice) error) ([]byte, error) {
	resolvers, err := t.getResolvers(req.Interface)
	if err != nil {
		return nil, err
	}

	for _, resolver := range resolvers {
		for _, device := range req.Devices {
			l := logrus.WithFields(logrus.Fields{
				"interface": req.Interface,
				"device":    device,
				"op":        req.Operation,
			})
			l.Info("Operate tuntap device")

			if err := edit(resolver, &device); err != nil {
				l.WithError(err).Error("Fail to operate tuntap device")
				return nil, err
			}
		}
	}
	return []byte("{}"), nil
}

func (t *TuntapCommand) Register(ifaceName string, resolver TuntapResolver) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.interfaceTuntaps[ifaceName] = resolver
}
