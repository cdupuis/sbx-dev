package client

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

func TestCRLFWriterReturnsTheCarriage(t *testing.T) {
	var out bytes.Buffer

	n, err := io.WriteString(crlfWriter{w: &out}, "\nsbx: waiting\n")
	require.NoError(t, err)
	require.Equal(t, len("\nsbx: waiting\n"), n, "the count reports what was consumed, not what was written")
	require.Equal(t, "\r\nsbx: waiting\r\n", out.String())
}

func TestCRLFWriterLeavesAnExistingCarriageAlone(t *testing.T) {
	var out bytes.Buffer

	_, err := io.WriteString(crlfWriter{w: &out}, "already\r\nbare\n")
	require.NoError(t, err)
	require.Equal(t, "already\r\nbare\r\n", out.String())
}

func TestForTerminalTranslatesForATerminal(t *testing.T) {
	screen, terminal, err := pty.Open()
	require.NoError(t, err)
	defer screen.Close()
	defer terminal.Close()

	// Raw, as a session with a PTY leaves it: a cooked terminal returns the
	// carriage itself, which is why the translation is confined to this state.
	state, err := term.MakeRaw(int(terminal.Fd()))
	require.NoError(t, err)
	defer func() { _ = term.Restore(int(terminal.Fd()), state) }()

	shown := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := screen.Read(buf)
		shown <- string(buf[:n])
	}()

	_, err = io.WriteString(forTerminal(terminal), "sbx: waiting\n")
	require.NoError(t, err)
	require.Equal(t, "sbx: waiting\r\n", <-shown)
}

func TestForTerminalLeavesARedirectedStreamAlone(t *testing.T) {
	// A caller that redirected stderr gets a file, and its line discipline is not
	// the terminal's.
	path := filepath.Join(t.TempDir(), "stderr.log")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	_, err = io.WriteString(forTerminal(f), "sbx: waiting\n")
	require.NoError(t, err)
	require.NoError(t, f.Sync())

	written, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "sbx: waiting\n", string(written))
}

func TestForTerminalLeavesAPlainWriterAlone(t *testing.T) {
	var out bytes.Buffer

	_, err := io.WriteString(forTerminal(&out), "sbx: waiting\n")
	require.NoError(t, err)
	require.Equal(t, "sbx: waiting\n", out.String())
}
