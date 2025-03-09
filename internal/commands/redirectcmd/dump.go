package redirectcmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/exports"
	"github.com/zxhio/xdpass/internal/protos"
)

func init() {
	commands.SetFlagsInterface(dumpCmd.Flags(), &dumpopt.Interface)
	commands.Register(dumpCmd)
	redirectCmd.AddCommand(dumpCmd)

	registerHandle(DumpCommandHandle{})
}

var dumpCmd = &cobra.Command{
	Use:     protos.RedirectTypeDump.String(),
	Aliases: []string{"redirect dump"},
	Short:   "Dump network traffic packets",
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()
		return DumpCommandClient{}.DoReq(dumpopt)
	},
}

var dumpopt DumpOpt

type DumpOpt struct {
	Interface string
}

type DumpCommandClient struct{}

func (DumpCommandClient) DoReq(opt DumpOpt) error {
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

type DumpCommandHandle struct{}

func (DumpCommandHandle) RedirectType() protos.RedirectType {
	return protos.RedirectTypeDump
}

func (DumpCommandHandle) HandleReqData(client *commands.MessageClient, data []byte) error {
	var req protos.DumpReq
	if err := json.Unmarshal(data, &req); err != nil {
		return commands.ResponseError(client, err)
	}

	defer func() {
		client.Close()
		logrus.Info("Disconnected from dump client")
	}()
	logrus.Info("Connected from dump client")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var apis []exports.RedirectDumpAPI
	if req.Interface != "" {
		api, ok := exports.GetDumpAPI(req.Interface)
		if !ok {
			return commands.ResponseError(client, fmt.Errorf("interface %s not found", req.Interface))
		}
		apis = append(apis, api)
	} else {
		for _, api := range exports.GetAllDumpAPIs() {
			apis = append(apis, api)
		}
	}

	go func() {
		for {
			_, err := client.Read()
			if err != nil {
				break
			}
		}
		cancel()
	}()

	wg := sync.WaitGroup{}
	wg.Add(len(apis))
	for _, api := range apis {
		go func(api exports.RedirectDumpAPI) {
			defer wg.Done()
			api.KeepPacketHook(ctx, func(pkt []byte) { client.Write(pkt) })
		}(api)
	}
	wg.Wait()

	return nil
}
