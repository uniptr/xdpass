package redirects

import (
	"encoding/json"

	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/commands/cmdconn"
	"github.com/zxhio/xdpass/internal/protos"
)

var redirectCmd = &cobra.Command{
	Use:   protos.TypeStr_Redirect,
	Short: "Redirect network traffic",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var tapCmd = &cobra.Command{
	Use:   protos.RedirectTypeStr_Tap,
	Short: "Redirect network traffic to tap device",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

type tapOpt struct {
	show bool
	add  string
	del  string
}

var dumpCmd = &cobra.Command{
	Use:   protos.RedirectTypeStr_Dump,
	Short: "Dump network traffic packets",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

type dumpOpt struct {
}

var remoteCmd = &cobra.Command{
	Use:   protos.RedirectTypeStr_Remote,
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

	tap    tapOpt
	dump   dumpOpt
	remote remoteOpt
	spoof  spoofOpt
}

func init() {
	commands.SetFlagsInterface(redirectCmd.PersistentFlags(), &opt.ifaceName)

	// Tap
	commands.SetFlagsList(tapCmd.Flags(), &opt.tap.show, "List tap info")
	tapCmd.Flags().StringVar(&opt.tap.add, "add", "", "Add tap device")
	tapCmd.Flags().StringVar(&opt.tap.del, "del", "", "Delete tap device")

	// Dump

	// Remote
	commands.SetFlagsList(remoteCmd.Flags(), &opt.remote.show, "List remote address")
	remoteCmd.Flags().StringVarP(&opt.remote.network, "network", "n", "tcp", "Address network (tcp|udp|unix)")
	remoteCmd.Flags().StringVar(&opt.remote.add, "add", "", "Add remote address")
	remoteCmd.Flags().StringVar(&opt.remote.del, "del", "", "Delete remote address")

	redirectCmd.AddCommand(tapCmd)
	redirectCmd.AddCommand(dumpCmd)
	redirectCmd.AddCommand(remoteCmd)

	commands.Register(redirectCmd)
}

func postRequest[Q, R any](redirectType protos.RedirectType, v *Q) (*R, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	req := protos.RedirectReq{RedirectType: redirectType, RedirectData: data}
	resp, err := cmdconn.PostRequest[protos.RedirectReq, R](protos.Type_Redirect, &req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
