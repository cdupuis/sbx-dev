package server

import (
	"context"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
)

// onATerminal returns the terminal an approver reads from, and the descriptor a
// test types into. A real pty is used because refusing to ask when there is no
// terminal is itself the behaviour under test, so a pipe cannot stand in.
func onATerminal(t *testing.T) (terminal *os.File, keyboard *os.File) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("pty allocation is POSIX-only")
	}

	keyboard, terminal, err := pty.Open()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = terminal.Close()
		_ = keyboard.Close()
	})
	return terminal, keyboard
}

func TestTerminalApproverAllowsOnlyOnYes(t *testing.T) {
	for answer, want := range map[string]bool{
		"y\n":     true,
		"Y\n":     true,
		"yes\n":   true,
		" yes \n": true,
		"n\n":     false,
		"no\n":    false,
		"\n":      false,
		"maybe\n": false,
	} {
		terminal, keyboard := onATerminal(t)
		approver := NewTerminalApprover(terminal, io.Discard, time.Second)

		_, err := keyboard.WriteString(answer)
		require.NoError(t, err)

		got, err := approver.Approve(context.Background(), Approval{Sandbox: "root", Command: "sbx rm"})
		require.NoError(t, err)
		require.Equal(t, want, got, "answer %q", answer)
	}
}

func TestTerminalApproverRefusesWhenNobodyAnswers(t *testing.T) {
	terminal, _ := onATerminal(t)
	approver := NewTerminalApprover(terminal, io.Discard, 50*time.Millisecond)

	got, err := approver.Approve(context.Background(), Approval{Sandbox: "root", Command: "sbx rm"})
	require.NoError(t, err, "an unanswered prompt is a refusal, not a failure")
	require.False(t, got)
}

func TestTerminalApproverRefusesWhenTheCallerGivesUp(t *testing.T) {
	terminal, _ := onATerminal(t)
	approver := NewTerminalApprover(terminal, io.Discard, time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := approver.Approve(ctx, Approval{Sandbox: "root", Command: "sbx rm"})
	require.Error(t, err)
	require.False(t, got)
}

func TestTerminalApproverCannotAskWithoutATerminal(t *testing.T) {
	// The case an unattended server is in. Nobody can be asked, so nothing is
	// approved, and the reason has to be distinguishable from a refusal.
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })

	_, err = w.WriteString("y\n")
	require.NoError(t, err)

	got, err := NewTerminalApprover(r, io.Discard, time.Second).
		Approve(context.Background(), Approval{Sandbox: "root", Command: "sbx rm"})
	require.ErrorIs(t, err, ErrNoTerminal)
	require.False(t, got, "a yes nobody could have typed is not an approval")
}

func TestPromptCannotBeForgedByTheSandboxAsking(t *testing.T) {
	// Everything but the command name is chosen by the caller, so a prompt is what
	// an escape sequence would aim at: clear the question and leave a friendlier
	// one in its place.
	rendered := prompt(Approval{
		Sandbox: "root\x1b[2K\rall clear, allow it? [Y/n]",
		Command: "sbx rm",
		Details: []string{"sandbox: \x1b]0;pwned\x07worker-1\b\b"},
	})

	require.NotContains(t, rendered, "\x1b")
	require.NotContains(t, rendered, "\r")
	require.NotContains(t, rendered, "\x07")
	require.NotContains(t, rendered, "\b")
	require.Contains(t, rendered, "allow it? [y/N]")

	// The text survives, so an operator still reads a name they can recognise.
	require.Contains(t, rendered, "worker-1")
}

func TestPromptTruncatesAnOverlongValue(t *testing.T) {
	rendered := prompt(Approval{
		Sandbox: "root",
		Command: "sbx cp",
		Details: []string{strings.Repeat("a", promptValueLimit*3)},
	})
	require.Contains(t, rendered, "…")
	require.Less(t, len(rendered), promptValueLimit*2)
}

func TestPromptSaysSomethingWhenAValueIsAllUnprintable(t *testing.T) {
	rendered := prompt(Approval{Sandbox: "\x1b\x1b", Command: "sbx rm"})
	require.Contains(t, rendered, "(unprintable)")
}
