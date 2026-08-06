//go:build !windows

package client

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/cdupuis/sbx-dev/internal/protocol"
)

// watchResize reports terminal size changes to the server until the returned
// stop function is called.
func watchResize(fd int, fw *protocol.Writer) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-ch:
				cols, rows, err := term.GetSize(fd)
				if err != nil {
					continue
				}
				sendResize(fw, rows, cols)
			case <-done:
				return
			}
		}
	}()

	return func() {
		signal.Stop(ch)
		close(done)
	}
}
