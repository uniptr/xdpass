package interfaces

import (
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
)

var ifaceCmd = &cobra.Command{
	Use:   protos.TypeStr_Interface,
	Short: "Manage network interface",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var opt struct {
	show   bool
	bind   string
	unbind string
}

func init() {
	commands.SetFlagsList(ifaceCmd.Flags(), &opt.show, "List interface binding info")
	ifaceCmd.Flags().StringVar(&opt.bind, "bind", "", "Bind interface")
	ifaceCmd.Flags().StringVar(&opt.bind, "unbind", "", "Unbind interface")

	commands.Register(ifaceCmd)
}
