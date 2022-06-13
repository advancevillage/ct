package bpf

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/advancevillage/3rd/logx"
)

type IEnv interface {
	Prepare(ctx context.Context) error
	Execute(ctx context.Context, cmd string, args ...string) ([]byte, error)
}

var (
	verOpts      = "--version"
	mkdirCmd     = "mkdir"
	mountCmd     = "mount"
	clangCmd     = "clang"
	bpftoolCmd   = "bpftool"
	unlinkCmd    = "unlink"
	bpffsRoot    = "/sys/fs/bpf"
	bpffsProgDir = bpffsRoot + "/prog"
	bpffsMapDir  = bpffsRoot + "/map"
)

type env struct {
	logger logx.ILogger
}

func NewEnv(logger logx.ILogger) IEnv {
	return &env{logger: logger}
}

func (c *env) Prepare(ctx context.Context) error {
	err := c.checkMkdir(ctx)
	if err != nil {
		return err
	}

	err = c.checkMount(ctx)
	if err != nil {
		return err
	}

	err = c.checkBpftool(ctx)
	if err != nil {
		return err
	}

	err = c.checkBpffs(ctx)
	if err != nil {
		return err
	}

	err = c.checkProgDir(ctx)
	if err != nil {
		return err
	}

	err = c.checkMapDir(ctx)
	if err != nil {
		return err
	}

	err = c.checkCLang(ctx)
	if err != nil {
		return err
	}

	err = c.checkUnlink(ctx)
	if err != nil {
		return err
	}

	return err
}

func (c *env) Execute(ctx context.Context, cmd string, args ...string) ([]byte, error) {
	return c.run(ctx, cmd, args...)
}

func (c *env) run(ctx context.Context, cmd string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, cmd, args...)
	c.logger.Infow(ctx, "exec", "command", command.String())
	return command.CombinedOutput()
}

func (c *env) checkMkdir(ctx context.Context) error {
	var buf, err = c.run(ctx, mkdirCmd, verOpts)
	if err != nil {
		return err
	}
	ver := strings.Split(string(buf), "\n")
	if len(ver) > 0 {
		c.logger.Infow(ctx, "exec", mkdirCmd, ver[0])
	}
	return nil
}

func (c *env) checkMount(ctx context.Context) error {
	var buf, err = c.run(ctx, mountCmd, verOpts)
	if err != nil {
		return err
	}
	ver := strings.Split(string(buf), "\n")
	if len(ver) > 0 {
		c.logger.Infow(ctx, "exec", mountCmd, ver[0])
	}
	return nil
}

func (c *env) checkBpftool(ctx context.Context) error {
	var buf, err = c.run(ctx, bpftoolCmd, verOpts)
	if err != nil {
		return err
	}
	ver := strings.Split(string(buf), "\n")
	if len(ver) > 0 {
		c.logger.Infow(ctx, "exec", bpftoolCmd, ver[0])
	}
	return nil
}

func (c *env) checkCLang(ctx context.Context) error {
	var buf, err = c.run(ctx, clangCmd, verOpts)
	if err != nil {
		return err
	}
	ver := strings.Split(string(buf), "\n")
	if len(ver) > 0 {
		c.logger.Infow(ctx, "exec", clangCmd, ver[0])
	}
	return nil
}

func (c *env) checkUnlink(ctx context.Context) error {
	var buf, err = c.run(ctx, unlinkCmd, verOpts)
	if err != nil {
		return err
	}
	ver := strings.Split(string(buf), "\n")
	if len(ver) > 0 {
		c.logger.Infow(ctx, "exec", unlinkCmd, ver[0])
	}
	return nil
}

func (c *env) checkBpffs(ctx context.Context) error {
	if _, err := os.Stat(bpffsRoot); os.IsNotExist(err) {
		//mount bpffs /sys/fs/bpf -t bpf
		_, err = c.run(ctx, mountCmd, "bpffs", bpffsRoot, "t", "bpf")
		if err != nil {
			return err
		}
	}
	if _, err := os.Stat(bpffsRoot); os.IsNotExist(err) {
		return err
	}
	c.logger.Infow(ctx, "exec", bpffsRoot, "exist")
	return nil
}

func (c *env) checkProgDir(ctx context.Context) error {
	if _, err := os.Stat(bpffsProgDir); os.IsNotExist(err) {
		_, err = c.run(ctx, mkdirCmd, bpffsProgDir)
		if err != nil {
			return err
		}
	} else {
		return err
	}

	c.logger.Infow(ctx, "exec", bpffsProgDir, "exist")
	return nil
}

func (c *env) checkMapDir(ctx context.Context) error {
	if _, err := os.Stat(bpffsMapDir); os.IsNotExist(err) {
		_, err = c.run(ctx, mkdirCmd, bpffsMapDir)
		if err != nil {
			return err
		}
	} else {
		return err
	}
	c.logger.Infow(ctx, "exec", bpffsMapDir, "exist")
	return nil
}
