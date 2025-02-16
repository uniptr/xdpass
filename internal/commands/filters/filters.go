package filters

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"github.com/zxhio/xdpass/internal/commands/cmdconn"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/xdpprog"
)

func connectAndPostData(opt *filterOpt) error {
	c, err := cmdconn.NewTLVClient()
	if err != nil {
		return err
	}
	defer c.Close()

	if opt.show {
		return showFilters(c)
	}

	if opt.add != "" {
		key, err := xdpprog.MakeIPLpmKeyFromStr(opt.add)
		if err != nil {
			return errors.Wrap(err, opt.add)
		}
		err = postFilter(c, &protos.FilterReq{AddKeys: []xdpprog.IPLpmKey{*key}})
		if err != nil {
			return err
		}
	}

	if opt.del != "" {
		key, err := xdpprog.MakeIPLpmKeyFromStr(opt.del)
		if err != nil {
			return errors.Wrap(err, opt.del)
		}
		err = postFilter(c, &protos.FilterReq{DelKeys: []xdpprog.IPLpmKey{*key}})
		if err != nil {
			return err
		}
	}
	return nil
}

func showFilters(c *cmdconn.TLVClient) error {
	data, err := json.Marshal(protos.FilterReq{Show: true})
	if err != nil {
		return err
	}

	data, err = c.PostData(protos.Type_Filter, data)
	if err != nil {
		return err
	}

	var resp protos.FilterResp
	err = json.Unmarshal(data, &resp)
	if err != nil {
		return err
	}

	// Display
	for _, ik := range resp.InterfacesKeys {
		fmt.Println(ik.Interface)
		for _, k := range ik.Keys {
			fmt.Println("  ", k)
		}
	}
	return nil
}

func postFilter(c *cmdconn.TLVClient, v *protos.FilterReq) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.PostData(protos.Type_Filter, data)
	return err
}
