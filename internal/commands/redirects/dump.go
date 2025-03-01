package redirects

import (
	"fmt"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
)

var dumpCmd = &cobra.Command{
	Use:   protos.RedirectTypeDump.String(),
	Short: "Dump network traffic packets",
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()
		return dump{}.handleCommand(&dumpOpt{})
	},
}

type dumpOpt struct {
}

func init() {
	redirectCmd.AddCommand(dumpCmd)
}

type dump struct{}

func (dump) handleCommand(_ *dumpOpt) error {
	client, err := commands.GetMessageClient(commands.DefUnixSock, protos.TypeRedirect, "", &protos.RedirectReq{RedirectType: protos.RedirectTypeDump})
	if err != nil {
		return err
	}
	defer client.Close()

	for {
		data, err := client.Read()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if len(data) == 0 {
			continue
		}
		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Println(pkt.String())
	}
}
