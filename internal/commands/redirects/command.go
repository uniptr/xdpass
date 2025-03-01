package redirects

import (
	"encoding/json"

	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
)

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

type remoteOpt struct {
	show    bool
	add     string
	del     string
	network string
}

var opt struct {
	ifaceName string

	tuntap tunOpt
	dump   dumpOpt
	remote remoteOpt
	spoof  spoofOpt
}

func init() {
	commands.SetFlagsInterface(redirectCmd.PersistentFlags(), &opt.ifaceName)

	// Remote
	commands.SetFlagsList(remoteCmd.Flags(), &opt.remote.show, "List remote address")
	remoteCmd.Flags().StringVarP(&opt.remote.network, "network", "n", "tcp", "Address network (tcp|udp|unix)")
	remoteCmd.Flags().StringVar(&opt.remote.add, "add", "", "Add remote address")
	remoteCmd.Flags().StringVar(&opt.remote.del, "del", "", "Delete remote address")

	redirectCmd.AddCommand(remoteCmd)

	commands.Register(redirectCmd)
}

func getResponse[Q, R any](redirectType protos.RedirectType, v *Q) (*R, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	req := protos.RedirectReq{RedirectType: redirectType, RedirectData: data}
	resp, err := commands.GetMessage[protos.RedirectReq, R](protos.TypeRedirect, "", &req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
