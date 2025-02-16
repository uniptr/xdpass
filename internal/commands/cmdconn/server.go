package cmdconn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/tlv"
)

const UnixSock = "/var/run/xdpass.sock"

type ReqDataHandle interface {
	CommandType() protos.Type
	HandleReqData([]byte) ([]byte, error)
}

type TLVServer struct {
	lis     net.Listener
	handles map[protos.Type]ReqDataHandle
}

// TODO: Add server listen sock
func NewTLVServer(handles ...ReqDataHandle) (*TLVServer, error) {
	err := os.RemoveAll(UnixSock)
	if err != nil {
		return nil, err
	}

	lis, err := net.Listen("unix", UnixSock)
	if err != nil {
		return nil, err
	}
	logrus.WithField("addr", lis.Addr()).Info("Listen on")

	handleMap := make(map[protos.Type]ReqDataHandle)
	for _, h := range handles {
		handleMap[h.CommandType()] = h
	}

	return &TLVServer{
		lis:     lis,
		handles: handleMap,
	}, nil
}

func (s *TLVServer) Close() error {
	return s.lis.Close()
}

func (s *TLVServer) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.lis.Close()
	}()

	for {
		conn, err := s.lis.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *TLVServer) handleConn(conn net.Conn) {
	defer conn.Close()

	for {
		data, err := tlv.DecodeFrom(conn)
		if err != nil {
			if err != io.EOF {
				logrus.WithError(err).Error("Fail to tlv.DecodeFrom")
			}
			return
		}

		data, err = s.handleReqData(data)
		if err != nil {
			logrus.WithError(err).Error("Fail to handle request")
			return
		}
		_, err = tlv.EncodeTo(conn, data)
		if err != nil {
			logrus.WithError(err).Error("Fail to response")
			return
		}
	}
}

func (s *TLVServer) handleReqData(data []byte) ([]byte, error) {
	var req protos.MessageReq
	err := json.Unmarshal(data, &req)
	if err != nil {
		return nil, err
	}

	h, ok := s.handles[req.Type]
	if ok {
		data, err = h.HandleReqData([]byte(req.Data))
	} else {
		err = errors.New("unsupported command")
	}

	resp := protos.MessageResp{Data: string(data)}
	if err != nil {
		resp.Error = err.Error()
	}
	return json.Marshal(resp)
}
