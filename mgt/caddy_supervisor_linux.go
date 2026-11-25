//go:build linux

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// setCaddySysProcAttr ties the supervised Caddy child process to parent termination
// so ports 80/443/4438 are never left orphaned if vsafegate receives SIGKILL.
func setCaddySysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}
}

func signalTerminateProcess(p *os.Process) error {
	if p == nil {
		return nil
	}
	return p.Signal(syscall.SIGTERM)
}
