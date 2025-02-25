package dump

import (
	"errors"
	"io"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/handle"
)

type DumpHandle struct {
	connected uint32
	client    *commands.MessageClient // only one client
	dataCh    chan []byte
}

func NewDumpHandle() (handle.RedirectHandle, error) {
	h := &DumpHandle{dataCh: make(chan []byte, 1024)}
	go h.txLoop()
	return h, nil
}

func (DumpHandle) RedirectType() protos.RedirectType {
	return protos.RedirectType_Dump
}

func (h *DumpHandle) Close() error {
	if h.client != nil {
		h.client.Close()
	}
	return nil
}

func (h *DumpHandle) txLoop() bool {
	for data := range h.dataCh {
		if atomic.LoadUint32(&h.connected) == 1 && h.client != nil {
			h.client.Write(data)
		}
	}
	return true
}

func (h *DumpHandle) HandleReqData(client *commands.MessageClient, data []byte) error {
	if atomic.LoadUint32(&h.connected) == 0 {
		h.client = client
		atomic.StoreUint32(&h.connected, 1)
	} else {
		return commands.ResponseError(client, errors.New("already has a connected client"))
	}

	defer func() {
		logrus.Info("Disconnected from dump client")
		atomic.StoreUint32(&h.connected, 0)
		h.client = nil
		client.Close()
	}()

	logrus.Info("Connected from dump client")

	for {
		_, err := client.Read()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func (h *DumpHandle) HandlePacketData(data *handle.PacketData) {
	if atomic.LoadUint32(&h.connected) == 0 {
		return
	}
	h.dataCh <- data.Data
}
