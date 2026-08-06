//go:build windows

package server

import (
	"os"
	"os/exec"
)

func newProcessGroup(*exec.Cmd) {}

// killProcessTree kills only the child itself; Windows has no process groups
// reachable through os/exec here.
func killProcessTree(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
