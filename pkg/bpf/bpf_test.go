package bpf

import (
	"context"
	"testing"

	"github.com/advancevillage/3rd/logx"
)

func Test_bpf(t *testing.T) {
	logger, err := logx.NewLogger("info")
	if err != nil {
		t.Fatal(err)
		return
	}
	b := &bpf{
		logger: logger,
		ienv:   NewEnv(logger),
	}

	err = b.Prepare(context.TODO())
	if err != nil {
		t.Fatal(err)
		return
	}
	rr, err := b.Metadata(context.TODO())
	if err != nil {
		t.Fatal(err)
		return
	}
	t.Log(rr)
}
