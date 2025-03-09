package redirectcmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/exports"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/netutil"
	"github.com/zxhio/xdpass/pkg/xdpprog"
	"golang.org/x/sys/unix"
)

func init() {
	commands.SetFlagsInterface(spoofCmd.Flags(), &spoofOpt.Interface)
	commands.SetFlagsList(spoofCmd.Flags(), &spoofOpt.ShowList, "Show spoof rule list")
	spoofCmd.Flags().BoolVar(&spoofOpt.ShowTypes, "list-spoof-types", false, "Show supported spoof type list")
	spoofCmd.Flags().BoolVar(&spoofOpt.Add, "add", false, "Add spoof rule")
	spoofCmd.Flags().BoolVar(&spoofOpt.Del, "del", false, "Delete spoof rule")
	spoofCmd.Flags().VarP(&spoofOpt.SrcIPLPM, "src-ip", "s", "Source IP")
	spoofCmd.Flags().VarP(&spoofOpt.DstIPLPM, "dst-ip", "d", "Destination IP")
	spoofCmd.Flags().Uint16Var(&spoofOpt.SrcPort, "src-port", 0, "Source port")
	spoofCmd.Flags().Uint16Var(&spoofOpt.DstPort, "dst-port", 0, "Destination port")
	spoofCmd.Flags().VarP(&spoofOpt.SpoofType, "spoof-type", "t", "Type for spoof rule")

	commands.Register(spoofCmd)
	redirectCmd.AddCommand(spoofCmd)

	registerHandle(SpoofCommandHandle{})
}

var spoofOpt SpoofOpt

type SpoofOpt struct {
	Interface string
	ShowList  bool
	ShowTypes bool
	Add       bool
	Del       bool
	SpoofType protos.SpoofType
	SrcIPLPM  xdpprog.IPLpmKey
	DstIPLPM  xdpprog.IPLpmKey
	SrcPort   uint16
	DstPort   uint16
}

var spoofCmd = &cobra.Command{
	Use:     protos.RedirectTypeSpoof.String(),
	Short:   "Traffic spoof based on rules",
	Aliases: []string{"redirect spoof"},
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()
		var s SpoofCommandClient
		return s.DoReq(&spoofOpt)
	},
}

type SpoofCommandClient struct{}

func (s *SpoofCommandClient) DoReq(opt *SpoofOpt) error {
	if opt.ShowList {
		return s.DoReqShowList(opt.Interface)
	}

	if opt.ShowTypes {
		return s.DoReqShowTypes()
	}

	if opt.Add {
		return s.DoReqEditRule(protos.OperationAdd, opt)
	}

	if opt.Del {
		return s.DoReqEditRule(protos.OperationDel, opt)
	}
	return nil
}

func (SpoofCommandClient) DoReqShowList(ifaceName string) error {
	req := protos.SpoofReq{Operation: protos.OperationList, Interface: ifaceName}
	resp, err := doRequest[protos.SpoofReq, protos.SpoofResp](protos.RedirectTypeSpoof, &req)
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Interface", "ID", "Spoof Type", "Proto", "Src IP", "Dst IP", "Src Port", "Dst Port"})
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	table.SetAutoMergeCellsByColumnIndex([]int{0})
	for _, iface := range resp.Interfaces {
		sort.Sort(protos.SpoofRuleSlice(iface.Rules))
		for _, rule := range iface.Rules {
			table.Append([]string{
				iface.Interface, fmt.Sprintf("%d", rule.ID), rule.SpoofType.String(),
				formatProto(rule.Proto),
				fmt.Sprintf("%s/%d", netutil.Uint32ToIPv4(rule.SrcIP), rule.SrcIPPrefixLen),
				fmt.Sprintf("%s/%d", netutil.Uint32ToIPv4(rule.DstIP), rule.DstIPPrefixLen),
				fmt.Sprintf("%d", rule.SrcPort), fmt.Sprintf("%d", rule.DstPort),
			})
		}
	}
	table.Render()

	return nil
}

func formatProto(proto uint16) string {
	switch proto {
	case unix.IPPROTO_TCP:
		return "TCP"
	case unix.IPPROTO_UDP:
		return "UDP"
	case unix.IPPROTO_ICMP:
		return "ICMP"
	default:
		return "ALL"
	}
}

func (SpoofCommandClient) DoReqShowTypes() error {
	req := protos.SpoofReq{Operation: protos.OperationListSpoofTypes}
	resp, err := doRequest[protos.SpoofReq, protos.SpoofResp](protos.RedirectTypeSpoof, &req)
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Supported Spoof Type"})
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	for _, typ := range resp.SupportedTypes {
		table.Append([]string{typ.String()})
	}
	table.Render()

	return nil
}

func (SpoofCommandClient) DoReqEditRule(op protos.Operation, opt *SpoofOpt) error {
	req := protos.SpoofReq{Operation: op, Interface: opt.Interface, Rules: []protos.SpoofRule{{
		SpoofRuleV4: protos.SpoofRuleV4{
			SpoofType:      opt.SpoofType,
			SrcPort:        opt.SrcPort,
			DstPort:        opt.DstPort,
			SrcIPPrefixLen: uint8(opt.SrcIPLPM.PrefixLen),
			DstIPPrefixLen: uint8(opt.DstIPLPM.PrefixLen),
			SrcIP:          opt.SrcIPLPM.To4().Address,
			DstIP:          opt.DstIPLPM.To4().Address,
		},
	}}}
	_, err := doRequest[protos.SpoofReq, protos.SpoofResp](protos.RedirectTypeSpoof, &req)
	return err
}

type SpoofCommandHandle struct{}

func (SpoofCommandHandle) RedirectType() protos.RedirectType {
	return protos.RedirectTypeSpoof
}

func (s SpoofCommandHandle) HandleReqData(client *commands.MessageClient, data []byte) error {
	var req protos.SpoofReq
	err := json.Unmarshal(data, &req)
	if err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}

	switch req.Operation {
	case protos.OperationNop:
		return response(client, []byte("{}"))
	case protos.OperationList:
		data, err = s.handleOpList(req.Interface)
	case protos.OperationListSpoofTypes:
		data, err = s.handleOpListTypes(&req)
	case protos.OperationAdd:
		data, err = s.handleReqEdit(&req, func(api exports.RedirectSpoofAPI, r protos.SpoofRule) error { return api.AddSpoofRule(r) })
	case protos.OperationDel:
		data, err = s.handleReqEdit(&req, func(api exports.RedirectSpoofAPI, r protos.SpoofRule) error { return api.DelSpoofRule(r) })
	}
	if err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}
	return response(client, data)
}

func (s SpoofCommandHandle) getAPIs(ifaceName string) (map[string]exports.RedirectSpoofAPI, error) {
	var apis map[string]exports.RedirectSpoofAPI
	if ifaceName != "" {
		api, ok := exports.GetSpoofAPI(ifaceName)
		if !ok {
			return nil, fmt.Errorf("interface %s not found", ifaceName)
		}
		apis = map[string]exports.RedirectSpoofAPI{ifaceName: api}
	} else {
		apis = exports.GetAllSpoofAPIs()
	}
	return apis, nil
}

func (s SpoofCommandHandle) handleOpList(ifaceName string) ([]byte, error) {
	apis, err := s.getAPIs(ifaceName)
	if err != nil {
		return nil, err
	}

	resp := protos.SpoofResp{Interfaces: make([]protos.SpoofInterfaceRule, 0, len(apis))}
	for name, api := range apis {
		resp.Interfaces = append(resp.Interfaces, protos.SpoofInterfaceRule{
			Interface: name,
			Rules:     api.GetSpoofRules(),
		})
	}
	return json.Marshal(resp)
}

func (s SpoofCommandHandle) handleOpListTypes(*protos.SpoofReq) ([]byte, error) {
	resp := protos.SpoofResp{Interfaces: []protos.SpoofInterfaceRule{
		{Rules: []protos.SpoofRule{
			{SpoofRuleV4: protos.SpoofRuleV4{SpoofType: protos.SpoofTypeICMPEchoReply}},
			{SpoofRuleV4: protos.SpoofRuleV4{SpoofType: protos.SpoofTypeTCPReset}},
			{SpoofRuleV4: protos.SpoofRuleV4{SpoofType: protos.SpoofTypeTCPResetSYN}},
		}},
	}}
	return json.Marshal(resp)
}

func (s SpoofCommandHandle) handleReqEdit(req *protos.SpoofReq, op func(exports.RedirectSpoofAPI, protos.SpoofRule) error) ([]byte, error) {
	apis, err := s.getAPIs(req.Interface)
	if err != nil {
		return nil, err
	}

	for ifaceName, api := range apis {
		l := logrus.WithField("interface", ifaceName)
		for _, rule := range req.Rules {
			l.WithField("rule", rule.String()).Debug("Add spoof rule")
			err := op(api, rule)
			if err != nil {
				return nil, err
			}
		}
	}
	return []byte("{}"), nil
}
