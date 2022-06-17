package bpf

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/advancevillage/3rd/logx"
)

type IBpfApi interface {
	GCCT(ctx context.Context, k []byte) error
	ShowCT(ctx context.Context) ([]byte, error)
	Metadata(ctx context.Context) ([]uint64, error)
}

func NewBpfApiClient(logger logx.ILogger) IBpfApi {
	return &bpf{
		logger: logger,
		ienv:   NewEnv(logger),
	}
}

var (
	ebpfProgs = map[string]int{
		"bf_ingress": 0, //pkt in
		"bf_egress":  1, //pkt out
		"bf_prs_end": 2, //prs end
		"bf_ct":      3, //pkt ct
		//"bf_acl":      4,  //pkt acl
		//"bf_nat":      5,  //pkt nat
		"bf_prs_eth":  10, //eth 802.x
		"bf_prs_ipv4": 11, //ipv4
		"bf_prs_icmp": 12, //icmp
		"bf_prs_tcp":  13, //tcp
		"bf_prs_udp":  14, //udp
	}
)

type bpfProg struct {
	Id            int    `json:"id"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	Tag           string `json:"tag"`
	GplCompatible bool   `json:"gpl_compatible"`
	LoadedAt      int64  `json:"loaded_at"`
	Uid           int    `json:"uid"`
	BytesXlated   int    `json:"bytes_xlated"`
	Jited         bool   `json:"jited"`
	BytesJited    int    `json:"bytes_jited"`
	BytesMemLock  int    `json:"bytes_memlock"`
	MapIds        []int  `json:"map_ids"`
	BtfId         int    `json:"btf_id"`
}

type bpfMap struct {
	Id      int    `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Key     int    `json:"bytes_key"`
	Val     int    `json:"bytes_value"`
	Max     int    `json:"max_entries"`
	MemLock int    `json:"bytes_memlock"`
}

type bpf struct {
	ienv   IEnv
	logger logx.ILogger
}

func (b *bpf) Prepare(ctx context.Context) error {
	//1. 环境条件检查
	err := b.ienv.Prepare(ctx)
	if err != nil {
		return err
	}

	//2. 获取eBPF程序
	progs, err := b.listProg(ctx)
	if err != nil {
		return err
	}

	//3. 检查eBPF程序是否加载
	compile := false
	for k := range ebpfProgs {
		_, ok := progs[k]
		if ok {
			continue
		} else {
			compile = true
		}
	}

	if compile {
		err = b.compileProg(ctx, progs)
		if err != nil {
			return err
		}
	}

	//4. 检查eBPFMap是否加载
	maps, err := b.listMap(ctx)
	if err != nil {
		return err
	}

	//5. 初始化map数据
	err = b.initMaps(ctx, maps)
	if err != nil {
		return err
	}

	return nil
}

func (b *bpf) Metadata(ctx context.Context) ([]uint64, error) {
	if err := b.Prepare(ctx); err != nil {
		return nil, err
	}
	//bpftool -j map dump pinned /sys/fs/bpf/map/meta
	f := fmt.Sprintf("%s/%s", bpffsMapDir, "meta")
	buf, err := b.ienv.Execute(ctx, bpftoolCmd, "-j", "map", "dump", "pinned", f)
	if err != nil {
		return nil, err
	}
	//eg: big endian
	//
	// [{"key":["0x12","0x34","0x56","0x78"],"value":["0x87","0x65","0x43","0x21"]}]
	//
	type kv struct {
		Key   []string `json:"key"`
		Value []string `json:"value"`
	}
	type kvList []kv

	var r = new(kvList)
	err = json.Unmarshal(buf, r)
	if err != nil {
		return nil, err
	}
	var rr = make([]uint64, 8, 8) //和bpf程序统一
	for i := range *r {
		var (
			k = make([]byte, 4)
			v = make([]byte, 8)
		)
		for ii := range (*r)[i].Key {
			k[ii] = b.hex((*r)[i].Key[ii])
		}
		for ii := range (*r)[i].Value {
			v[ii] = b.hex((*r)[i].Value[ii])
		}

		kk := uint32(k[3])<<24 | uint32(k[2])<<16 | uint32(k[1])<<8 | uint32(k[0])
		vv := uint64(v[7])<<56 | uint64(v[6])<<48 | uint64(v[5])<<40 | uint64(v[4])<<32 | uint64(v[3])<<24 | uint64(v[2])<<16 | uint64(v[1])<<8 | uint64(v[0])
		rr[kk%8] = vv
	}

	return rr, nil
}

func (b *bpf) ShowCT(ctx context.Context) ([]byte, error) {
	if err := b.Prepare(ctx); err != nil {
		return nil, err
	}
	//bpftool map dump pinned /sys/fs/bpf/map/ctt
	f := fmt.Sprintf("%s/%s", bpffsMapDir, "ctt")
	return b.ienv.Execute(ctx, bpftoolCmd, "-j", "map", "dump", "pinned", f)
}

func (b *bpf) GCCT(ctx context.Context, k []byte) error {
	f := fmt.Sprintf("%s/%s", bpffsMapDir, "ctt")
	kk := make([]string, 0, len(k)+6)

	kk = append(kk, "-j")
	kk = append(kk, "map")
	kk = append(kk, "delete")
	kk = append(kk, "pinned")
	kk = append(kk, f)
	kk = append(kk, "key")

	for _, v := range k {
		kk = append(kk, fmt.Sprintf("%d", v))
	}
	_, err := b.ienv.Execute(ctx, bpftoolCmd, kk...)
	if err != nil {
		return err
	}
	return nil
}

func (b *bpf) listProg(ctx context.Context) (map[string]*bpfProg, error) {
	buf, err := b.ienv.Execute(ctx, bpftoolCmd, "-j", "prog", "show")
	if err != nil {
		return nil, err
	}
	progs := make([]*bpfProg, 0, 8)

	err = json.Unmarshal(buf, &progs)
	if err != nil {
		return nil, err
	}

	progsM := make(map[string]*bpfProg)
	for _, v := range progs {
		if v.Type == "xdp" {
			progsM[v.Name] = v
		} else {
			continue
		}
	}

	b.logger.Debugw(ctx, "prog lists", "progs", progsM)
	return progsM, nil
}

func (b *bpf) listMap(ctx context.Context) (map[string]*bpfMap, error) {
	buf, err := b.ienv.Execute(ctx, bpftoolCmd, "-j", "map", "show")
	if err != nil {
		return nil, err
	}
	maps := make([]*bpfMap, 0, 8)

	err = json.Unmarshal(buf, &maps)
	if err != nil {
		return nil, err
	}

	mapsM := make(map[string]*bpfMap)

	for _, v := range maps {
		switch v.Name {
		case "jt":
			mapsM[v.Name] = v
		case "ctt":
			mapsM[v.Name] = v
		case "meta":
			mapsM[v.Name] = v
		}
	}

	b.logger.Debugw(ctx, "maps lists", "maps", mapsM)
	return mapsM, nil
}

func (b *bpf) compileProg(ctx context.Context, progs map[string]*bpfProg) error {
	//1. unlink old progs
	for k := range progs {
		id := ebpfProgs[k]
		pin := fmt.Sprintf("%s/xdp_%d", bpffsProgDir, id)
		_, err := b.ienv.Execute(ctx, unlinkCmd, pin)
		if err != nil {
			return err
		}
	}

	//2. compile ebpf prog
	now := time.Now().Unix()
	f := fmt.Sprintf("cprog-%d.c", now)
	o := fmt.Sprintf("cprog-%d.o", now)
	fd, err := os.OpenFile(f, os.O_WRONLY|os.O_CREATE, 666)
	if err != nil {
		return err
	}
	defer os.Remove(f)
	defer fd.Close()

	w := bufio.NewWriter(fd)
	n, err := w.WriteString(cprog)
	if err != nil {
		return err
	}
	if n != len(cprog) {
		return errors.New("cprog is part")
	}
	w.Flush()

	//3. compile: clang -g -Wall -O2 -c -target bpf -D__TARGET_ARCH_x86 bpf/ct.bpf.c -I/usr/include/x86_64-linux-gnu/ -o bpf/ct.bpf.o
	_, err = b.ienv.Execute(ctx, clangCmd, "-g", "-Wall", "-O2", "-c", "-target", "bpf", "-D__TARGET_ARCH_x86", f, "-I/usr/include/x86_64-linux-gnu/", "-o", o)
	if err != nil {
		return err
	}

	//4. load ebpf: bpftool prog loadall bpf/ct.bpf.o /sys/fs/bpf/prog
	_, err = b.ienv.Execute(ctx, bpftoolCmd, "prog", "loadall", o, bpffsProgDir)
	if err != nil {
		return err
	}

	return nil
}

func (b *bpf) initMaps(ctx context.Context, maps map[string]*bpfMap) error {
	//1. pin bpffs
	for k, v := range maps {
		f := fmt.Sprintf("%s/%s", bpffsMapDir, k)
		if b.fileExist(f) {
			continue
		} else {
			// bpftool map pin id 83 /sys/fs/bpf/map/jt
			_, err := b.ienv.Execute(ctx, bpftoolCmd, "map", "pin", "id", fmt.Sprintf("%d", v.Id), f)
			if err != nil {
				return err
			}
		}
	}

	//2. init jt data
	for _, i := range ebpfProgs {
		//bpftool map update pinned /sys/fs/bpf/map/jt key $i 0 0 0 value pinned /sys/fs/bpf/prog/xdp_$i
		_, err := b.ienv.Execute(ctx, bpftoolCmd, "map", "update", "pinned", fmt.Sprintf("%s/%s", bpffsMapDir, "jt"), "key", fmt.Sprintf("%d", i), "0", "0", "0", "value", "pinned", fmt.Sprintf("%s/xdp_%d", bpffsProgDir, i))
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *bpf) fileExist(f string) bool {
	_, err := os.Stat(f)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func (b *bpf) hex(s string) byte {
	var v = byte(0)
	var vv = byte(0)
	//0x12 0xa 12
	for i := len(s) - 1; i >= 0 && s[i] != 'x'; i-- {
		switch s[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			vv = s[i] - '0'
		case 'a', 'A':
			vv = 10
		case 'b', 'B':
			vv = 11
		case 'c', 'C':
			vv = 12
		case 'd', 'D':
			vv = 13
		case 'e', 'E':
			vv = 14
		case 'f', 'F':
			vv = 15
		}
		v += vv * b.pow(0x10, len(s)-1-i)
	}
	return v
}

func (b *bpf) pow(x, n int) byte {
	switch {
	case n <= 0:
		return 0x01
	default:
		for i := 1; i < n; i++ {
			x *= x
		}
		return byte(x)
	}
}
