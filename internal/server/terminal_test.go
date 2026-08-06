package server

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/stretchr/testify/require"

	"github.com/cdupuis/sbx-warden/internal/client"
)

// callerTerminal returns a terminal to run a session against and a record of
// everything that appeared on it, which is what the user of that terminal saw.
func callerTerminal(t *testing.T) (*os.File, *watchWriter) {
	t.Helper()

	screen, terminal, err := pty.Open()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = terminal.Close()
		_ = screen.Close()
	})

	shown := newWatchWriter()
	go func() { _, _ = io.Copy(shown, screen) }()
	return terminal, shown
}

// requireLinesStartAtTheMargin checks the property a terminal needs: a line feed
// with no carriage return moves down a row without returning to the first
// column, so everything printed after it is indented by the length of the line
// before it.
func requireLinesStartAtTheMargin(t *testing.T, shown string) {
	t.Helper()
	for i := 0; i < len(shown); i++ {
		if shown[i] != '\n' {
			continue
		}
		require.True(t, i > 0 && shown[i-1] == '\r',
			"a line feed with no carriage return indents whatever prints next: %q", shown)
	}
}

func waitForText(t *testing.T, shown *watchWriter, want string) {
	t.Helper()
	require.Eventually(t, func() bool {
		return strings.Contains(shown.String(), want)
	}, 10*time.Second, 20*time.Millisecond, "never saw %q, only %q", want, shown.String())
}

func TestWithheldNoticeDoesNotIndentWhatFollowsOnATerminal(t *testing.T) {
	addr := startWithheldServer(t, &recordingApprover{allow: false})
	terminal, shown := callerTerminal(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := client.Run(ctx, client.Config{
		Addr:   addr,
		Token:  testToken,
		Args:   []string{"rm", "worker-2"},
		Stdout: terminal,
		Stderr: terminal,
		TTYFd:  int(terminal.Fd()),
	})
	require.ErrorContains(t, err, "an operator refused")

	waitForText(t, shown, "waiting for an operator")
	requireLinesStartAtTheMargin(t, shown.String())
}

func TestRevocationNoticeDoesNotIndentWhatFollowsOnATerminal(t *testing.T) {
	reg, path := liveRegistry(t)
	addr := startServer(t, Config{Generations: reg, RevocationInterval: 20 * time.Millisecond})
	terminal, shown := callerTerminal(t)

	stdin, keystrokes := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := client.Run(ctx, client.Config{
			Addr:   addr,
			Token:  testToken,
			Args:   []string{"echo-stdin"},
			Stdin:  stdin,
			Stdout: terminal,
			Stderr: terminal,
			TTYFd:  int(terminal.Fd()),
		})
		done <- err
	}()

	// Echoed output means the session is running, which is also when the caller's
	// terminal is in raw mode and the server must return the carriage itself.
	_, err := keystrokes.Write([]byte("live\n"))
	require.NoError(t, err)
	waitForText(t, shown, "live")

	revoke(t, path, testSandbox)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a session outlived the token that opened it")
	}

	waitForText(t, shown, "token has been retired")
	requireLinesStartAtTheMargin(t, shown.String())
}
