package redirects

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/netutil"
	"github.com/zxhio/xdpass/pkg/xdpprog"
	"golang.org/x/sys/unix"
)

var spoofCmd = &cobra.Command{
	Use:   protos.RedirectTypeSpoof.String(),
	Short: "Traffic spoof based on rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()
		var s SpoofCommand
		return s.DoReq(opt.ifaceName, &opt.spoof)
	},
}

func init() {
	commands.SetFlagsList(spoofCmd.Flags(), &opt.spoof.showList, "Show spoof rule list")
	spoofCmd.Flags().BoolVar(&opt.spoof.showTypes, "list-spoof-types", false, "Show supported spoof type list")
	spoofCmd.Flags().BoolVar(&opt.spoof.add, "add", false, "Add spoof rule")
	spoofCmd.Flags().BoolVar(&opt.spoof.del, "del", false, "Delete spoof rule")
	spoofCmd.Flags().VarP(&opt.spoof.srcIPLPM, "src-ip", "s", "Source IP")
	spoofCmd.Flags().VarP(&opt.spoof.dstIPLPM, "dst-ip", "d", "Destination IP")
	spoofCmd.Flags().Uint16Var(&opt.spoof.srcPort, "src-port", 0, "Source port")
	spoofCmd.Flags().Uint16Var(&opt.spoof.dstPort, "dst-port", 0, "Destination port")
	spoofCmd.Flags().VarP(&opt.spoof.typ, "spoof-type", "t", "Type for spoof rule")

	redirectCmd.AddCommand(spoofCmd)
}

type SpoofOpt struct {
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

type SpoofResolver interface {
	GetSpoofRules() ([]protos.SpoofRule, error)
	AddSpoofRule(rule protos.SpoofRule) error
	DelSpoofRule(rule protos.SpoofRule) error
}

type SpoofCommand struct {
	mu        *sync.Mutex
	resolvers map[string]SpoofResolver
}

func NewSpoofCommand() *SpoofCommand {
	return &SpoofCommand{
		mu:        &sync.Mutex{},
		resolvers: make(map[string]SpoofResolver),
	}
}

func (SpoofCommand) RedirectType() protos.RedirectType {
	return protos.RedirectTypeSpoof
}

// Client

func (s *SpoofCommand) DoReq(ifaceName string, opt *SpoofOpt) error {
	if opt.showList {
		return s.DoReqShowList(ifaceName)
	}

	if opt.showTypes {
		return s.DoReqShowTypes()
	}

	if opt.add {
		return s.DoReqEditRule(protos.OperationAdd, ifaceName, opt)
	}

	if opt.del {
		return s.DoReqEditRule(protos.OperationDel, ifaceName, opt)
	}
	return nil
}

func (s *SpoofCommand) DoReqShowList(ifaceName string) error {
	req := protos.SpoofReq{Operation: protos.OperationList, Interface: ifaceName}
	resp, err := getResponse[protos.SpoofReq, protos.SpoofResp](protos.RedirectTypeSpoof, &req)
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Interface", "Spoof Type", "Proto", "Src IP", "Dst IP", "Src Port", "Dst Port"})
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	for _, iface := range resp.Interfaces {
		sort.Sort(protos.SpoofRuleSlice(iface.Rules))
		for _, rule := range iface.Rules {
			table.Append([]string{
				fmt.Sprintf("%d", rule.ID), iface.Interface, rule.SpoofType.String(),
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

func (s *SpoofCommand) DoReqShowTypes() error {
	req := protos.SpoofReq{Operation: protos.OperationListSpoofTypes}
	resp, err := getResponse[protos.SpoofReq, protos.SpoofResp](protos.RedirectTypeSpoof, &req)
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

func (s *SpoofCommand) DoReqEditRule(op protos.Operation, ifaceName string, opt *SpoofOpt) error {
	req := protos.SpoofReq{Operation: op, Interface: ifaceName, Rules: []protos.SpoofRule{{
		SpoofRuleV4: protos.SpoofRuleV4{
			SpoofType:      opt.typ,
			SrcPort:        opt.srcPort,
			DstPort:        opt.dstPort,
			SrcIPPrefixLen: uint8(opt.srcIPLPM.PrefixLen),
			DstIPPrefixLen: uint8(opt.dstIPLPM.PrefixLen),
			SrcIP:          opt.srcIPLPM.To4().Address,
			DstIP:          opt.dstIPLPM.To4().Address,
		},
	}}}
	_, err := getResponse[protos.SpoofReq, protos.SpoofResp](protos.RedirectTypeSpoof, &req)
	return err
}

// Server

func (s *SpoofCommand) Register(ifaceName string, resolver SpoofResolver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resolvers[ifaceName] = resolver
}

func (s *SpoofCommand) Del(ifaceName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.resolvers, ifaceName)
}

func (s *SpoofCommand) HandleReqData(client *commands.MessageClient, data []byte) error {
	var req protos.SpoofReq
	err := json.Unmarshal(data, &req)
	if err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch req.Operation {
	case protos.OperationNop:
		return ResponseRedirectData(client, []byte("{}"))
	case protos.OperationList:
		data, err = s.handleOpList(req.Interface)
	case protos.OperationListSpoofTypes:
		data, err = s.handleOpListTypes(&req)
	case protos.OperationAdd:
		data, err = s.handleReqEdit(&req, func(sr SpoofResolver, r protos.SpoofRule) error { return sr.AddSpoofRule(r) })
	case protos.OperationDel:
		data, err = s.handleReqEdit(&req, func(sr SpoofResolver, r protos.SpoofRule) error { return sr.DelSpoofRule(r) })
	}
	if err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}
	return ResponseRedirectData(client, data)
}

func (s *SpoofCommand) getResolvers(ifaceName string) (map[string]SpoofResolver, error) {
	var resolvers map[string]SpoofResolver
	if ifaceName != "" {
		resolver, ok := s.resolvers[ifaceName]
		if !ok {
			return nil, fmt.Errorf("interface %s not found", ifaceName)
		}
		resolvers = map[string]SpoofResolver{ifaceName: resolver}
	} else {
		resolvers = s.resolvers
	}
	return resolvers, nil
}

func (s *SpoofCommand) handleOpList(ifaceName string) ([]byte, error) {
	resolvers, err := s.getResolvers(ifaceName)
	if err != nil {
		return nil, err
	}

	resp := protos.SpoofResp{Interfaces: make([]protos.SpoofInterfaceRule, 0, len(resolvers))}
	for name, resolver := range resolvers {
		rules, err := resolver.GetSpoofRules()
		if err != nil {
			return nil, err
		}
		resp.Interfaces = append(resp.Interfaces, protos.SpoofInterfaceRule{
			Interface: name,
			Rules:     rules,
		})
	}
	return json.Marshal(resp)
}

func (s *SpoofCommand) handleOpListTypes(*protos.SpoofReq) ([]byte, error) {
	resp := protos.SpoofResp{Interfaces: []protos.SpoofInterfaceRule{
		{Rules: []protos.SpoofRule{
			{SpoofRuleV4: protos.SpoofRuleV4{SpoofType: protos.SpoofTypeICMPEchoReply}},
			{SpoofRuleV4: protos.SpoofRuleV4{SpoofType: protos.SpoofTypeTCPReset}},
			{SpoofRuleV4: protos.SpoofRuleV4{SpoofType: protos.SpoofTypeTCPResetSYN}},
		}},
	}}
	return json.Marshal(resp)
}

func (s *SpoofCommand) handleReqEdit(req *protos.SpoofReq, op func(SpoofResolver, protos.SpoofRule) error) ([]byte, error) {
	resolvers, err := s.getResolvers(req.Interface)
	if err != nil {
		return nil, err
	}

	for ifaceName, resolver := range resolvers {
		l := logrus.WithField("interface", ifaceName)
		for _, rule := range req.Rules {
			l.WithField("rule", rule.String()).Debug("Add spoof rule")
			err := op(resolver, rule)
			if err != nil {
				return nil, err
			}
		}
	}
	return []byte("{}"), nil
}
