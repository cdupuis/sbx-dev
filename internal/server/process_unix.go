//go:build !windows

package server

import (
	"os/exec"
	"syscall"
)

// newProcessGroup puts the child in its own process group so killProcessTree
// can reap grandchildren. A PTY session must not use this: pty.Start already
// requests Setsid, which makes the child a group leader on its own.
func newProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killProcessTree signals the child's whole process group, falling back to the
// child alone if the group has already gone away.
func killProcessTree(pid int) error {
	if err := syscall.Kill(-pid, syscall.SIGKILL); err == nil {
		return nil
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}
