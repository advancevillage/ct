package bpf

import (
	"context"
	"testing"

	"github.com/advancevillage/3rd/logx"
)

func Test_check(t *testing.T) {
	logger, err := logx.NewLogger("info")
	if err != nil {
		t.Fatal(err)
		return
	}
	c := &env{logger: logger}

	var fs = []func(ctx context.Context) error{c.checkMkdir, c.checkMount, c.checkBpftool, c.checkBpffs, c.checkProgDir, c.checkMapDir, c.checkCLang, c.checkUnlink}

	for _, f := range fs {
		err = f(context.TODO())
		if err != nil {
			t.Fatal(err)
			return
		}
	}
}
