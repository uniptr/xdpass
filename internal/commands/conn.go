package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/tlv"
)

const (
	DefUnixSock = "/var/run/xdpass.sock"
)

type MessageClient struct {
	conn net.Conn
}

func NewMessageClientByConn(conn net.Conn) *MessageClient {
	return &MessageClient{conn: conn}
}

func NewMessageClientByAddr(addr string) (*MessageClient, error) {
	conn, err := net.Dial("unix", addr)
	if err != nil {
		return nil, err
	}
	return &MessageClient{conn: conn}, nil
}

func (c *MessageClient) Close() error                   { return c.conn.Close() }
func (c *MessageClient) Read() ([]byte, error)          { return tlv.DecodeFrom(c.conn) }
func (c *MessageClient) Write(data []byte) (int, error) { return tlv.EncodeTo(c.conn, data) }

func GetMessage[Q any, R any](t protos.Type, id string, v *Q) (*R, error) {
	return GetMessageByAddr[Q, R](DefUnixSock, t, id, v)
}

func GetMessageByAddr[Q any, R any](addr string, t protos.Type, id string, v *Q) (*R, error) {
	client, err := GetMessageClient(addr, t, id, v)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	data, err := client.Read()
	if err != nil {
		return nil, err
	}
	logrus.WithField("data", string(data)).Debug("Get response")

	return protos.GetMessageRespValue[R](data)
}

func GetMessageClient[Q any](addr string, t protos.Type, id string, v *Q) (*MessageClient, error) {
	client, err := NewMessageClientByAddr(addr)
	if err != nil {
		return nil, err
	}
	logrus.WithField("addr", addr).Debug("Connected to")

	data, err := protos.MakeMessageReqData(t, id, v)
	if err != nil {
		return nil, err
	}
	logrus.WithField("data", string(data)).Debug("Post request")

	_, err = client.Write(data)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func Response(client *MessageClient, resp *protos.MessageResp) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = client.Write(data)
	return err
}

func ResponseError(client *MessageClient, err error) error {
	resp := protos.MessageResp{Message: err.Error(), ErrorCode: 1}
	return Response(client, &resp)
}

func ResponseErrorCode(client *MessageClient, err error, errCode protos.ErrorCode) error {
	resp := protos.MessageResp{Message: err.Error(), ErrorCode: errCode}
	return Response(client, &resp)
}

func ResponseMessage[T any](client *MessageClient, v *T) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	resp := protos.MessageResp{Data: data, ErrorCode: 0}
	return Response(client, &resp)
}

type MessageHandle interface {
	CommandType() protos.Type
	HandleReqData(client *MessageClient, req []byte) error
}

type MessageServer struct {
	lis     net.Listener
	handles map[protos.Type]MessageHandle
}

func NewMessageServer(addr string, handles ...MessageHandle) (*MessageServer, error) {
	lis, err := net.Listen("unix", addr)
	if err != nil {
		return nil, err
	}

	hh := make(map[protos.Type]MessageHandle)
	for _, h := range handles {
		hh[h.CommandType()] = h
	}

	return &MessageServer{lis: lis, handles: hh}, nil
}

func (s *MessageServer) Close() error {
	return s.lis.Close()
}

func (s *MessageServer) Serve(ctx context.Context) error {
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

func (s *MessageServer) handleConn(conn net.Conn) {
	defer conn.Close()

	c := NewMessageClientByConn(conn)
	data, err := c.Read()
	if err != nil {
		if err == io.EOF {
			logrus.Debug("Closed by client")
		} else {
			logrus.WithError(err).Error("Fail to read message")
		}
		return
	}

	var req protos.MessageReq
	err = json.Unmarshal(data, &req)
	if err != nil {
		logrus.WithError(err).Error("Fail to unmarshal message")
		return
	}

	h, ok := s.handles[req.Type]
	if ok {
		err = h.HandleReqData(c, req.Data)
		if err != nil {
			logrus.WithError(err).Error("Fail to handle request")
		}
		return
	}

	err = ResponseErrorCode(c, fmt.Errorf("unsupported command: %s", req.Type), protos.ErrorCode_InvalidRequest)
	if err != nil {
		logrus.WithError(err).Error("Fail to response error")
	}
}
