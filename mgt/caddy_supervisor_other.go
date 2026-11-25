//go:build !linux

package main

import (
	"os"
	"os/exec"
)

func setCaddySysProcAttr(cmd *exec.Cmd) {}

func signalTerminateProcess(p *os.Process) error {
	if p == nil {
		return nil
	}
	return p.Signal(os.Interrupt)
}
