package redirects

import (
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
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

var spoofCmd = &cobra.Command{
	Use:   protos.RedirectTypeStr_Spoof,
	Short: "Traffic spoof based on rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

type spoofOpt struct {
	show        bool
	add         bool
	del         bool
	showTypes   bool
	typ         string
	source      string
	destination string
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

	// Spoof
	commands.SetFlagsList(spoofCmd.Flags(), &opt.spoof.show, "List spoof rules")
	spoofCmd.Flags().BoolVar(&opt.spoof.add, "add", false, "Add spoof rule")
	spoofCmd.Flags().BoolVar(&opt.spoof.del, "del", false, "Delete spoof rule")
	spoofCmd.Flags().StringVarP(&opt.spoof.source, "source", "s", "", "Source address (ip or ip:port)")
	spoofCmd.Flags().StringVarP(&opt.spoof.destination, "dest", "d", "", "Destination address (ip or ip:port)")
	spoofCmd.Flags().BoolVar(&opt.spoof.showTypes, "list-type", false, "List supported spoof types")
	spoofCmd.Flags().StringVarP(&opt.spoof.typ, "type", "t", "", "Type for spoof rule")

	redirectCmd.AddCommand(tapCmd)
	redirectCmd.AddCommand(dumpCmd)
	redirectCmd.AddCommand(remoteCmd)
	redirectCmd.AddCommand(spoofCmd)

	commands.Register(redirectCmd)
}
