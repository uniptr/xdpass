package cmdconn

import (
	"encoding/json"
	"errors"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/tlv"
)

type TLVClient struct {
	conn net.Conn
}

func NewTLVClient() (*TLVClient, error) {
	conn, err := net.Dial("unix", UnixSock)
	if err != nil {
		return nil, err
	}
	return &TLVClient{conn: conn}, nil
}

func (c *TLVClient) Close() error {
	return c.conn.Close()
}

func (c *TLVClient) PostData(subcommand protos.Type, data []byte) ([]byte, error) {
	req := protos.MessageReq{
		Type: subcommand,
		Data: data,
	}
	data, err := json.Marshal(&req)
	if err != nil {
		return nil, err
	}

	logrus.WithField("data", string(data)).Debug("Request")
	_, err = tlv.EncodeTo(c.conn, data)
	if err != nil {
		return nil, err
	}

	data, err = tlv.DecodeFrom(c.conn)
	if err != nil {
		return nil, err
	}
	logrus.WithField("data", string(data)).Debug("Response")

	var resp protos.MessageResp
	err = json.Unmarshal(data, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Message != "" {
		return nil, errors.New(resp.Message)
	}
	return []byte(resp.Data), nil
}

func PostData(subcommand protos.Type, data []byte) ([]byte, error) {
	client, err := NewTLVClient()
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.PostData(subcommand, data)
}

func PostRequest[Q, R any](subcommand protos.Type, v *Q) (*R, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	data, err = PostData(subcommand, data)
	if err != nil {
		return nil, err
	}

	var resp R
	err = json.Unmarshal(data, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
