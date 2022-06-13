package ct

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/advancevillage/3rd/logx"
	"github.com/advancevillage/ct/pkg/bpf"
)

type IConnTrack interface {
	ShowConn(ctx context.Context) ([]string, error)
}

//示例
//[{
//        "key": {
//            "sip": 2887661673,
//            "dip": 2887006313,
//            "sport": 35672,
//            "dport": 0,
//            "nexthdr": 1,
//            "rel": 0x0,
//            "dir": 0x1,
//            "reserved": 0x0
//        },
//        "value": {
//            "bytes": 392,
//            "pkts": 4,
//            "state": 0x7,
//            "since": 0x2016,
//            "reserved": 0x0
//        }
//    },{
//        "key": {
//            "sip": 2887006313,
//            "dip": 2887661673,
//            "sport": 0,
//            "dport": 35672,
//            "nexthdr": 1,
//            "rel": 0x0,
//            "dir": 0x0,
//            "reserved": 0x0
//        },
//        "value": {
//            "bytes": 392,
//            "pkts": 4,
//            "state": 0x7,
//            "since": 0x2016,
//            "reserved": 0x0
//        }
//    }
//]
type tuple struct {
	Sip         uint32 `json:"sip"`
	Dip         uint32 `json:"dip"`
	Sport       uint16 `json:"sport"`
	Dport       uint16 `json:"dport"`
	Nexthdr     uint8  `json:"nexthdr"`
	RelStr      string `json:"rel"`
	Rel         uint8  `json:"irel"`
	DirStr      string `json:"dir"`
	Dir         uint8  `json:"idir"`
	ReservedStr string `json:"reserved"`
	Reserved    uint8  `json:"ireserved"`
}

type entry struct {
	Bytes       uint64 `json:"bytes"`
	Pkts        uint64 `json:"pkts"`
	StateStr    string `json:"state"`
	SinceStr    string `json:"since"`
	ReservedStr string `json:"reserved"`
	State       uint16 `json:"istate"`
	Since       uint32 `json:"isince"`
	Reserved    uint16 `json:"ireserved"`
}

type elem struct {
	Formatted struct {
		Tuple *tuple `json:"key"`
		Entry *entry `json:"value"`
	} `json:"formatted"`
}

type ct struct {
	logger logx.ILogger
	api    bpf.IBpfApi
}

func NewCTCli(logger logx.ILogger) IConnTrack {
	return &ct{
		logger: logger,
		api:    bpf.NewBpfApiClient(logger),
	}
}

func (c *ct) parse(ctx context.Context, elems []*elem) ([]string, error) {
	c.logger.Infow(ctx, "dump cts", "elems", elems)
	//
	// tcp 6 431982 ESTABLISHED src=192.168.2.100 dst=123.59.27.117 sport=34846 dport=993 packets=169 bytes=14322 src=123.59.27.117 dst=192.168.2.100 sport=993 dport=34846 packets=113 bytes=34787 [ASSURED] mark=1 secmark=0 use=1
	//
	return nil, nil
}

func (c *ct) dump(ctx context.Context) ([]string, error) {
	buf, err := c.api.ShowCT(ctx)
	if err != nil {
		return nil, err
	}

	elems := make([]*elem, 0, 2)

	err = json.Unmarshal(buf, &elems)
	if err != nil {
		return nil, err
	}

	for _, v := range elems {
		rel, err := strconv.ParseUint(strings.Replace(v.Formatted.Tuple.RelStr, "0x", "", -1), 16, 64)
		if err != nil {
			return nil, err
		}
		v.Formatted.Tuple.Rel = uint8(rel)
		dir, err := strconv.ParseUint(strings.Replace(v.Formatted.Tuple.DirStr, "0x", "", -1), 16, 64)
		if err != nil {
			return nil, err
		}
		v.Formatted.Tuple.Dir = uint8(dir)
		reserved, err := strconv.ParseUint(strings.Replace(v.Formatted.Tuple.ReservedStr, "0x", "", -1), 16, 64)
		if err != nil {
			return nil, err
		}
		v.Formatted.Tuple.Reserved = uint8(reserved)
		since, err := strconv.ParseUint(strings.Replace(v.Formatted.Entry.SinceStr, "0x", "", -1), 16, 64)
		if err != nil {
			return nil, err
		}
		v.Formatted.Entry.Since = uint32(since)
		state, err := strconv.ParseUint(strings.Replace(v.Formatted.Entry.StateStr, "0x", "", -1), 16, 64)
		if err != nil {
			return nil, err
		}
		v.Formatted.Entry.State = uint16(state)
		reserved, err = strconv.ParseUint(strings.Replace(v.Formatted.Entry.ReservedStr, "0x", "", -1), 16, 64)
		if err != nil {
			return nil, err
		}
		v.Formatted.Entry.Reserved = uint16(reserved)
	}

	return c.parse(ctx, elems)
}

func (c *ct) ShowConn(ctx context.Context) ([]string, error) {
	return c.dump(ctx)
}
