package commands

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var root cobra.Command

var opt struct {
	verbose bool
}

func init() {
	root.PersistentFlags().BoolVarP(&opt.verbose, "verbose", "v", false, "Verbose output")
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
