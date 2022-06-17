package ct

import (
	"context"
	"encoding/json"
	"fmt"
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

type match struct {
	Nexthdr uint8
	Sip     uint32
	Dip     uint32
	Sport   uint16
	Dport   uint16
}

type stat struct {
	Bytes uint64
	Pkts  uint64
}

const (
	//net.netfilter.nf_conntrack_dccp_timeout_closereq = 64
	//net.netfilter.nf_conntrack_dccp_timeout_closing = 64
	//net.netfilter.nf_conntrack_dccp_timeout_open = 43200
	//net.netfilter.nf_conntrack_dccp_timeout_partopen = 480
	//net.netfilter.nf_conntrack_dccp_timeout_request = 240
	//net.netfilter.nf_conntrack_dccp_timeout_respond = 480
	//net.netfilter.nf_conntrack_dccp_timeout_timewait = 240
	//net.netfilter.nf_conntrack_generic_timeout = 600
	//net.netfilter.nf_conntrack_icmp_timeout = 30
	//net.netfilter.nf_conntrack_sctp_timeout_closed = 10
	//net.netfilter.nf_conntrack_sctp_timeout_cookie_echoed = 3
	//net.netfilter.nf_conntrack_sctp_timeout_cookie_wait = 3
	//net.netfilter.nf_conntrack_sctp_timeout_established = 432000
	//net.netfilter.nf_conntrack_sctp_timeout_heartbeat_acked = 210
	//net.netfilter.nf_conntrack_sctp_timeout_heartbeat_sent = 30
	//net.netfilter.nf_conntrack_sctp_timeout_shutdown_ack_sent = 3
	//net.netfilter.nf_conntrack_sctp_timeout_shutdown_recd = 0
	//net.netfilter.nf_conntrack_sctp_timeout_shutdown_sent = 0
	//net.netfilter.nf_conntrack_tcp_timeout_close = 10
	//net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
	//net.netfilter.nf_conntrack_tcp_timeout_established = 432000
	//net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120
	//net.netfilter.nf_conntrack_tcp_timeout_last_ack = 30
	//net.netfilter.nf_conntrack_tcp_timeout_max_retrans = 300
	//net.netfilter.nf_conntrack_tcp_timeout_syn_recv = 60
	//net.netfilter.nf_conntrack_tcp_timeout_syn_sent = 120
	//net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120
	//net.netfilter.nf_conntrack_tcp_timeout_unacknowledged = 300
	//net.netfilter.nf_conntrack_udp_timeout = 30
	//net.netfilter.nf_conntrack_udp_timeout_stream = 180
	genericTimeout        = uint32(600)
	icmpTimeout           = uint32(30)
	udpTimeout            = uint32(30)
	tcpSynSentTimeout     = uint32(120)
	tcpSynRecvTimeout     = uint32(60)
	tcpTimeWaitTimeout    = uint32(120)
	tcpLaskAckTimeout     = uint32(30)
	tcpFinWaitTimeout     = uint32(120)
	tcpCloseWaitTimeout   = uint32(60)
	tcpEstablishedTimeout = uint32(432000)
)

// ct state:
const (
	ct_null       = 0x0000
	ct_new        = 0x0001
	ct_rpl        = 0x0002
	ct_syn_sent   = 0x0004
	ct_syn_recv   = 0x0008
	ct_inv        = 0x0010
	ct_est        = 0x0400
	ct_fin_wait   = 0x0800
	ct_close_wait = 0x1000
	ct_last_ack   = 0x2000
	ct_time_wait  = 0x4000
	ct_rel        = 0x8000
)

type attr struct {
	State     uint16
	SysSince  uint32
	FlowSince uint32
}

type flow struct {
	Match []match `json:"match"`
	Stat  []stat  `json:"stat"`
	Attr  []attr  `json:"attr"`
}

func newFlow() *flow {
	return &flow{
		Match: make([]match, 2, 2),
		Stat:  make([]stat, 4, 4),
		Attr:  make([]attr, 2, 2),
	}
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

func (c *ct) gc(ctx context.Context, f *flow) {
	if f == nil {
		return
	}
	var (
		fk0 = make([]byte, 16)
		fk1 = make([]byte, 16)
		fk2 = make([]byte, 16)
		fk3 = make([]byte, 16)
		fk  = [][]byte{fk0, fk1, fk2, fk3}
	)
	for i := 0; i < 4; i++ {
		fk[i][0x00] = uint8(f.Match[(i&0x02)>>1].Sip)
		fk[i][0x01] = uint8(f.Match[(i&0x02)>>1].Sip >> 8)
		fk[i][0x02] = uint8(f.Match[(i&0x02)>>1].Sip >> 16)
		fk[i][0x03] = uint8(f.Match[(i&0x02)>>1].Sip >> 24)
		fk[i][0x04] = uint8(f.Match[(i&0x02)>>1].Dip)
		fk[i][0x05] = uint8(f.Match[(i&0x02)>>1].Dip >> 8)
		fk[i][0x06] = uint8(f.Match[(i&0x02)>>1].Dip >> 16)
		fk[i][0x07] = uint8(f.Match[(i&0x02)>>1].Dip >> 24)
		fk[i][0x08] = uint8(f.Match[(i&0x02)>>1].Sport)
		fk[i][0x09] = uint8(f.Match[(i&0x02)>>1].Sport >> 8)
		fk[i][0x0a] = uint8(f.Match[(i&0x02)>>1].Dport)
		fk[i][0x0b] = uint8(f.Match[(i&0x02)>>1].Dport >> 8)
		fk[i][0x0c] = uint8(f.Match[(i&0x02)>>1].Nexthdr)
		fk[i][0x0d] = uint8(i)
		fk[i][0x0e] = 0x00
		fk[i][0x0f] = 0x00
		c.api.GCCT(ctx, fk[i])
	}
}

func (c *ct) parse(ctx context.Context, elems []*elem, meta []uint64) ([]string, error) {
	//
	// tcp 6 431982 ESTABLISHED src=192.168.2.100 dst=123.59.27.117 sport=34846 dport=993 packets=169 bytes=14322 src=123.59.27.117 dst=192.168.2.100 sport=993 dport=34846 packets=113 bytes=34787 [ASSURED] mark=1 secmark=0 use=1
	//
	var (
		fs = make(map[string]*flow)
		k  string
	)

	for _, v := range elems {
		if v.Formatted.Tuple.Dir > 0 { //egress
			k = fmt.Sprintf("%d%d%d%d%d", v.Formatted.Tuple.Dip, v.Formatted.Tuple.Sip, v.Formatted.Tuple.Dport, v.Formatted.Tuple.Sport, v.Formatted.Tuple.Nexthdr)
		} else { //ingress
			k = fmt.Sprintf("%d%d%d%d%d", v.Formatted.Tuple.Sip, v.Formatted.Tuple.Dip, v.Formatted.Tuple.Sport, v.Formatted.Tuple.Dport, v.Formatted.Tuple.Nexthdr)
		}

		if _, ok := fs[k]; !ok {
			fs[k] = newFlow()
		}

		fs[k].Match[v.Formatted.Tuple.Dir%2].Sip = v.Formatted.Tuple.Sip
		fs[k].Match[v.Formatted.Tuple.Dir%2].Dip = v.Formatted.Tuple.Dip
		fs[k].Match[v.Formatted.Tuple.Dir%2].Sport = v.Formatted.Tuple.Sport
		fs[k].Match[v.Formatted.Tuple.Dir%2].Dport = v.Formatted.Tuple.Dport
		fs[k].Match[v.Formatted.Tuple.Dir%2].Nexthdr = v.Formatted.Tuple.Nexthdr
		fs[k].Stat[(v.Formatted.Tuple.Rel<<1|v.Formatted.Tuple.Dir)%4].Bytes = v.Formatted.Entry.Bytes
		fs[k].Stat[(v.Formatted.Tuple.Rel<<1|v.Formatted.Tuple.Dir)%4].Pkts = v.Formatted.Entry.Pkts
		fs[k].Attr[v.Formatted.Tuple.Dir%2].State = v.Formatted.Entry.State
		fs[k].Attr[v.Formatted.Tuple.Dir%2].FlowSince = v.Formatted.Entry.Since
		fs[k].Attr[v.Formatted.Tuple.Dir%2].SysSince = uint32(meta[0])
	}

	trks := []string{}
	for _, v := range fs {
		sstate, sstateStr := c.state(v.Attr[0].State)
		dstate, dstateStr := c.state(v.Attr[1].State)

		speriod := c.expire(v.Attr[0].SysSince, v.Attr[0].FlowSince, v.Match[0].Nexthdr, sstate)
		dperiod := c.expire(v.Attr[1].SysSince, v.Attr[1].FlowSince, v.Match[1].Nexthdr, dstate)

		trk := fmt.Sprintf("%s %s period=%d src=%s dst=%s sport=%d dport=%d rxbytes=%d rxpkts=%d rxrelbytes=%d rxrelpkts=%d %s period=%d src=%s dst=%s sport=%d dport=%d txbytes=%d txpkts=%d txrelbytes=%d txrelpkts=%d", c.proto(v.Match[0].Nexthdr), sstateStr, speriod, c.ip(v.Match[0].Sip), c.ip(v.Match[0].Dip), v.Match[0].Sport, v.Match[0].Dport, v.Stat[0].Bytes, v.Stat[0].Pkts, v.Stat[3].Bytes, v.Stat[3].Pkts, dstateStr, dperiod, c.ip(v.Match[1].Sip), c.ip(v.Match[1].Dip), v.Match[1].Sport, v.Match[1].Dport, v.Stat[1].Bytes, v.Stat[1].Pkts, v.Stat[2].Bytes, v.Stat[2].Pkts)
		trks = append(trks, trk)

		if speriod == 0 || dperiod == 0 {
			c.gc(ctx, v)
		}
	}

	return trks, nil
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

	meta, err := c.api.Metadata(ctx)
	if err != nil {
		return nil, err
	}

	return c.parse(ctx, elems, meta)
}

func (c *ct) ShowConn(ctx context.Context) ([]string, error) {
	return c.dump(ctx)
}

func (c *ct) ip(a uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", uint8(a>>24), uint8(a>>16), uint8(a>>8), uint8(a))
}

func (c *ct) expire(now uint32, last uint32, nexthdr uint8, ctstate uint32) uint32 {
	var (
		intv = uint32(0)
		cycv = genericTimeout
	)
	if now > last {
		intv = now - last
	} else {
		intv = 0
	}

	switch nexthdr {
	case 0x01:
		cycv = icmpTimeout

	case 0x11:
		cycv = udpTimeout

	case 0x06:

		switch ctstate {
		case ct_syn_sent:
			cycv = tcpSynSentTimeout

		case ct_syn_recv:
			cycv = tcpSynRecvTimeout

		case ct_est:
			cycv = tcpEstablishedTimeout

		case ct_fin_wait:
			cycv = tcpFinWaitTimeout

		case ct_close_wait:
			cycv = tcpCloseWaitTimeout

		case ct_last_ack:
			cycv = tcpLaskAckTimeout

		case ct_time_wait:
			cycv = tcpTimeWaitTimeout

		}
	}

	if cycv > intv {
		cycv -= intv
	} else {
		cycv = 0
	}

	return cycv
}

func (c *ct) state(a uint16) (uint32, string) {
	b := uint16(0x8000)

	for (b&a) == 0 && b > 0 {
		b = b >> 1
	}
	switch b {
	case ct_null:
		return ct_null, "untrack"
	case ct_new:
		return ct_new, "new"
	case ct_rpl:
		return ct_rpl, "rpl"
	case ct_syn_sent:
		return ct_syn_sent, "syn_sent"
	case ct_syn_recv:
		return ct_syn_recv, "syn_recv"
	case ct_est:
		return ct_est, "est"
	case ct_fin_wait:
		return ct_fin_wait, "fin_wait"
	case ct_close_wait:
		return ct_close_wait, "close_wait"
	case ct_last_ack:
		return ct_last_ack, "last_ack"
	case ct_time_wait:
		return ct_time_wait, "time_wait"
	case ct_rel:
		return ct_rel, "rel"
	default:
		return ct_inv, "inv"
	}
}

func (c *ct) proto(a uint8) string {
	switch a {
	case 0x01:
		return "icmp"
	case 0x11:
		return "udp"
	case 0x06:
		return "tcp"
	default:
		return "unknown"
	}
}
