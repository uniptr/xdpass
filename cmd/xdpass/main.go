package main

import (
	"fmt"
	"os"

	_ "github.com/zxhio/xdpass/internal/bench"
	"github.com/zxhio/xdpass/internal/commands"
	_ "github.com/zxhio/xdpass/internal/commands/filters"
	_ "github.com/zxhio/xdpass/internal/commands/interfaces"
	_ "github.com/zxhio/xdpass/internal/commands/redirectcmd"
	_ "github.com/zxhio/xdpass/internal/commands/stats"
)

const (
	use   = "xdpass"
	short = "A tool for interacting with xdpassd and performing packet sending benchmark"
)

func main() {
	cmd := commands.GetCommand(use, short)
	err := cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
