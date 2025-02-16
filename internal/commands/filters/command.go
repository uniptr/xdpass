package filters

import (
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
)

var filterCmd = &cobra.Command{
	Use:   protos.TypeStr_Filter,
	Short: "Manage network traffic filters",
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()
		return connectAndPostData(&opt)
	},
}

type filterOpt struct {
	ifaceName string
	show      bool
	add       string
	del       string
}

var opt filterOpt

func init() {
	commands.SetFlagsInterface(filterCmd.Flags(), &opt.ifaceName)
	filterCmd.Flags().StringVar(&opt.add, "add", "", "Add filter ip/cidr")
	filterCmd.Flags().StringVar(&opt.del, "del", "", "Del filter ip/cidr")
	filterCmd.Flags().BoolVarP(&opt.show, "list", "l", false, "List filter ip/cidr")

	commands.Register(filterCmd)
}
