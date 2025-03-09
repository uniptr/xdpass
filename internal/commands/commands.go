package commands

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/zxhio/xdpass/pkg/builder"
)

var root cobra.Command

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Prints the build information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(builder.BuildInfo())
	},
}

var opt struct {
	verbose bool
}

func init() {
	root.PersistentFlags().BoolVarP(&opt.verbose, "verbose", "v", false, "Verbose output")
	root.AddCommand(versionCmd)
}

func GetCommand(use, short string) cobra.Command {
	root.Use = use
	root.Short = short
	return root
}

func Register(subcommand *cobra.Command) {
	root.AddCommand(subcommand)
}

func SetFlagsInterface(s *pflag.FlagSet, v *string) {
	s.StringVarP(v, "interface", "i", "", "Interface name")
}

func SetFlagsList(s *pflag.FlagSet, v *bool, usage string) {
	s.BoolVarP(v, "list", "l", false, usage)
}

func SetVerbose() {
	if opt.verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}
}
