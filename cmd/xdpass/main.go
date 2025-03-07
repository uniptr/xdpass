package main

import (
	"fmt"
	"os"

	_ "github.com/zxhio/xdpass/internal/bench"
	"github.com/zxhio/xdpass/internal/commands"
	_ "github.com/zxhio/xdpass/internal/commands/fwcmd"
	_ "github.com/zxhio/xdpass/internal/commands/interfaces"
	_ "github.com/zxhio/xdpass/internal/commands/redirectcmd"
	_ "github.com/zxhio/xdpass/internal/commands/statscmd"
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
