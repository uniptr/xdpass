package dump

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/protos/packets"
	"github.com/zxhio/xdpass/internal/redirect/handle"
)

type DumpHandle struct {
	connected  uint32
	client     *commands.MessageClient // only one client
	rxDataPool *sync.Pool
	rxDataCh   chan []byte
}

func NewDumpHandle() (handle.RedirectHandle, error) {
	h := &DumpHandle{
		rxDataPool: &sync.Pool{
			New: func() any {
				return make([]byte, 2048)
			},
		},
		rxDataCh: make(chan []byte, 1024),
	}
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
	close(h.rxDataCh)
	return nil
}

func (h *DumpHandle) txLoop() bool {
	for data := range h.rxDataCh {
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

func (h *DumpHandle) HandlePacket(data *packets.Packet) {
	if atomic.LoadUint32(&h.connected) == 0 {
		return
	}
	rxData := h.rxDataPool.Get().([]byte)
	copy(rxData, data.RxData)
	h.rxDataCh <- rxData
}
