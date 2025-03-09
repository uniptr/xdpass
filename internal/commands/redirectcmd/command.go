package redirectcmd

import (
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
)

func init() {
	commands.SetFlagsInterface(redirectCmd.PersistentFlags(), &redirectOpt.Interface)

	// Remote
	commands.SetFlagsInterface(remoteCmd.PersistentFlags(), &remoteOpt.Interface)
	commands.SetFlagsList(remoteCmd.Flags(), &remoteOpt.ShowList, "List remote address")
	remoteCmd.Flags().StringVarP(&remoteOpt.Network, "network", "n", "tcp", "Address network (tcp|udp|unix)")
	remoteCmd.Flags().StringVar(&remoteOpt.Add, "add", "", "Add remote address")
	remoteCmd.Flags().StringVar(&remoteOpt.Del, "del", "", "Delete remote address")

	commands.Register(redirectCmd)

	redirectCmd.AddCommand(remoteCmd)
	commands.Register(remoteCmd)
}

var redirectCmd = &cobra.Command{
	Use:   protos.TypeRedirect.String(),
	Short: "Redirect network traffic",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var remoteCmd = &cobra.Command{
	Use:   protos.RedirectTypeRemote.String(),
	Short: "Redirect network traffic to remote address",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var (
	redirectOpt RedirectOpt
	remoteOpt   RemoteOpt
)

type RedirectOpt struct {
	Interface string
}

type RemoteOpt struct {
	Interface string
	ShowList  bool
	Add       string
	Del       string
	Network   string
}
