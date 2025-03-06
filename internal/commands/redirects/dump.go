package redirects

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
	"github.com/zxhio/xdpass/internal/protos"
)

var dumpCmd = &cobra.Command{
	Use:   protos.RedirectTypeDump.String(),
	Short: "Dump network traffic packets",
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()
		var dump DumpCommand
		return dump.DoReq()
	},
}

func init() {
	redirectCmd.AddCommand(dumpCmd)
}

type DumpOpt struct {
}

type DumpHook interface {
	KeepPacketHook(context.Context, func([]byte))
}

type DumpCommand struct {
	mu        *sync.Mutex
	dumpHooks map[string]DumpHook
}

func NewDumpCommand() *DumpCommand {
	return &DumpCommand{
		mu:        &sync.Mutex{},
		dumpHooks: make(map[string]DumpHook),
	}
}

func (DumpCommand) RedirectType() protos.RedirectType {
	return protos.RedirectTypeDump
}

func (*DumpCommand) DoReq() error {
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

func (h *DumpCommand) HandleReqData(client *commands.MessageClient, data []byte) error {
	var req protos.DumpReq
	if err := json.Unmarshal(data, &req); err != nil {
		return commands.ResponseError(client, err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	defer func() {
		client.Close()
		logrus.Info("Disconnected from dump client")
	}()
	logrus.Info("Connected from dump client")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var hooks []DumpHook
	if req.Interface != "" {
		hook, ok := h.dumpHooks[req.Interface]
		if !ok {
			return commands.ResponseError(client, fmt.Errorf("interface %s not found", req.Interface))
		}
		hooks = append(hooks, hook)
	} else {
		for _, hook := range h.dumpHooks {
			hooks = append(hooks, hook)
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
	wg.Add(len(hooks))
	for _, hook := range hooks {
		go func(hook DumpHook) {
			defer wg.Done()
			hook.KeepPacketHook(ctx, func(pkt []byte) { client.Write(pkt) })
		}(hook)
	}
	wg.Wait()

	return nil
}

func (d *DumpCommand) Register(ifaceName string, hook DumpHook) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dumpHooks[ifaceName] = hook
}
