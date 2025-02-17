package filters

import (
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/xdpprog"
)

var filterCmd = &cobra.Command{
	Use:   protos.TypeStr_Filter,
	Short: "Manage network traffic filters",
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()
		return filter{}.handleCommand()
	},
}

type filterOpt struct {
	ifaceName string
	showList  bool
	add       bool
	del       bool
	key       xdpprog.IPLpmKey
}

var opt filterOpt

func init() {
	commands.SetFlagsInterface(filterCmd.Flags(), &opt.ifaceName)
	filterCmd.Flags().BoolVarP(&opt.showList, "list", "l", false, "List filter ip")
	filterCmd.Flags().BoolVarP(&opt.add, "add", "a", false, "Add filter ip")
	filterCmd.Flags().BoolVarP(&opt.del, "del", "d", false, "Del filter ip")
	filterCmd.Flags().Var(&opt.key, "key", "IP key for filter")

	commands.Register(filterCmd)
}
