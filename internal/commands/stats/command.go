package stats

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
)

var statsCommand = &cobra.Command{
	Use:   protos.TypeStats.String(),
	Short: "Display a live stream of network traffic statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var opt struct {
	stats time.Duration
}

func init() {
	statsCommand.Flags().DurationVarP(&opt.stats, "duration", "d", time.Duration(0), "Statistics duration")
	commands.Register(statsCommand)
}
