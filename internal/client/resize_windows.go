//go:build windows

package client

import (
	"time"

	"golang.org/x/term"

	"github.com/cdupuis/sbx-dev/internal/protocol"
)

// resizePollInterval is how often the terminal is measured. Windows has no
// SIGWINCH equivalent, so size changes are discovered by polling.
const resizePollInterval = 500 * time.Millisecond

// watchResize reports terminal size changes to the server until the returned
// stop function is called.
func watchResize(fd int, fw *protocol.Writer) func() {
	done := make(chan struct{})

	go func() {
		ticker := time.NewTicker(resizePollInterval)
		defer ticker.Stop()

		lastCols, lastRows, _ := term.GetSize(fd)
		for {
			select {
			case <-ticker.C:
				cols, rows, err := term.GetSize(fd)
				if err != nil || (cols == lastCols && rows == lastRows) {
					continue
				}
				lastCols, lastRows = cols, rows
				sendResize(fw, rows, cols)
			case <-done:
				return
			}
		}
	}()

	return func() { close(done) }
}
