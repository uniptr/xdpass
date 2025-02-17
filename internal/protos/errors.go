package protos

import "errors"

var (
	ErrNotImpl = errors.New("not implemented")
)

type ErrorCode int

const (
	ErrorCode_Success ErrorCode = iota
	ErrorCode_NotImplemented
	ErrorCode_InvalidRequest
)
