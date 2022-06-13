package ct

import (
	"context"
	"testing"

	"github.com/advancevillage/3rd/logx"
)

func Test_ct(t *testing.T) {
	logger, err := logx.NewLogger("info")
	if err != nil {
		t.Fatal(err)
		return
	}
	c := NewCTCli(logger)

	conns, err := c.ShowConn(context.TODO())
	if err != nil {
		t.Fatal(err)
		return
	}
	t.Log(conns)
}
