package utils

import (
	"fmt"
)

type NamedCloser struct {
	Name  string
	Close func() error
}

type NamedClosers []NamedCloser

type CloseOpt struct {
	ReverseOrder bool
	Output       func(...interface{})
	ErrorOutput  func(...interface{})
}

func (closers NamedClosers) Close(opt *CloseOpt) {
	close := func(c *NamedCloser) {
		err := c.Close()
		if err != nil {
			opt.ErrorOutput(fmt.Sprintf("Fail to close %s error=%s", c.Name, err))
		} else {
			opt.Output(fmt.Sprintf("Closed %s", c.Name))
		}
	}

	if len(closers) == 0 {
		return
	}

	if opt == nil {
		opt = &CloseOpt{}
	}
	if opt.Output == nil {
		opt.Output = func(...interface{}) {}
	}
	if opt.ErrorOutput == nil {
		opt.ErrorOutput = func(...interface{}) {}
	}

	if opt.ReverseOrder {
		for i := len(closers) - 1; i >= 0; i-- {
			close(&closers[i])
		}
	} else {
		for _, c := range closers {
			close(&c)
		}
	}
}
