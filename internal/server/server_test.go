package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cdupuis/sbx-dev/internal/client"
	"github.com/cdupuis/sbx-dev/internal/protocol"
)

const testToken = "0123456789abcdef"

// fakeSbx stands in for the real sbx CLI, exposing just enough subcommands to
// observe argument passing, stdio wiring, environment, exit codes and TTY
// allocation.
const fakeSbx = `#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -*) shift ;;
    *) break ;;
  esac
done
cmd="$1"
[ $# -gt 0 ] && shift
case "$cmd" in
  echo-args) printf 'args:%s\n' "$*" ;;
  echo-stdin) cat ;;
  both) printf 'to-stdout\n'; printf 'to-stderr\n' >&2 ;;
  fail) exit "${1:-3}" ;;
  show-env) printenv "$1" ;;
  tty) if [ -t 1 ]; then printf 'tty\n'; else printf 'notty\n'; fi ;;
  winsize) stty size ;;
  workdir) pwd ;;
  *) printf 'unknown:%s\n' "$cmd" >&2; exit 9 ;;
esac
`

func writeFakeSbx(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sbx")
	require.NoError(t, os.WriteFile(path, []byte(fakeSbx), 0o700))
	return path
}

// startServer runs a server on an ephemeral loopback port and returns its address.
func startServer(t *testing.T, cfg Config) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in sbx binary is a POSIX shell script")
	}

	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:0"
	}
	if cfg.SbxPath == "" {
		cfg.SbxPath = writeFakeSbx(t)
	}
	if cfg.Token == "" {
		cfg.Token = testToken
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}

	srv, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, srv.Listen())

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx) }()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-served:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down")
		}
	})

	return srv.Addr().String()
}

type result struct {
	code   int
	err    error
	stdout string
	stderr string
}

func runClient(t *testing.T, addr, token string, stdin io.Reader, args ...string) result {
	t.Helper()

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code, err := client.Run(ctx, client.Config{
		Addr:   addr,
		Token:  token,
		Args:   args,
		Stdin:  stdin,
		Stdout: &stdout,
		Stderr: &stderr,
		TTYFd:  client.NoTTY,
	})
	return result{code: code, err: err, stdout: stdout.String(), stderr: stderr.String()}
}

func TestSessionPassesArgumentsThrough(t *testing.T) {
	addr := startServer(t, Config{})

	got := runClient(t, addr, testToken, nil, "echo-args", "--flag", "value with spaces")
	require.NoError(t, got.err)
	require.Equal(t, 0, got.code)
	require.Equal(t, "args:--flag value with spaces\n", got.stdout)
}

func TestSessionSeparatesStdoutAndStderr(t *testing.T) {
	addr := startServer(t, Config{})

	got := runClient(t, addr, testToken, nil, "both")
	require.NoError(t, got.err)
	require.Equal(t, "to-stdout\n", got.stdout)
	require.Equal(t, "to-stderr\n", got.stderr)
}

func TestSessionPropagatesExitCode(t *testing.T) {
	addr := startServer(t, Config{})

	got := runClient(t, addr, testToken, nil, "fail", "42")
	require.NoError(t, got.err)
	require.Equal(t, 42, got.code)
}

func TestSessionForwardsStdin(t *testing.T) {
	addr := startServer(t, Config{})

	got := runClient(t, addr, testToken, strings.NewReader("piped input\n"), "echo-stdin")
	require.NoError(t, got.err)
	require.Equal(t, 0, got.code)
	require.Equal(t, "piped input\n", got.stdout)
}

func TestSessionRunsInConfiguredWorkdir(t *testing.T) {
	workdir := t.TempDir()
	addr := startServer(t, Config{Workdir: workdir})

	got := runClient(t, addr, testToken, nil, "workdir")
	require.NoError(t, got.err)
	// macOS resolves TMPDIR through a symlink, so compare resolved paths.
	want, err := filepath.EvalSymlinks(workdir)
	require.NoError(t, err)
	require.Equal(t, want, strings.TrimSpace(got.stdout))
}

func TestSessionRejectsWrongToken(t *testing.T) {
	addr := startServer(t, Config{})

	got := runClient(t, addr, "wrong-token", nil, "echo-args")
	require.Error(t, got.err)
	require.Contains(t, got.err.Error(), "invalid token")
	require.Equal(t, protocol.ExitProtocol, got.code)
	require.Empty(t, got.stdout, "a rejected session must not run the command")
}

// A refusal by a live server must not be reported as unreachable, so the client
// does not print connectivity advice for a working connection.
func TestRefusedSessionIsNotUnreachable(t *testing.T) {
	addr := startServer(t, Config{})

	got := runClient(t, addr, "wrong-token", nil, "echo-args")
	require.Error(t, got.err)
	require.NotErrorIs(t, got.err, client.ErrUnreachable)
}

func TestAbsentServerIsUnreachable(t *testing.T) {
	// Bind and immediately release a port to get one nothing is listening on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	got := runClient(t, addr, testToken, nil, "echo-args")
	require.ErrorIs(t, got.err, client.ErrUnreachable)
}

// A server that accepts and then drops the connection is what a sandbox sees
// when its egress proxy accepts on behalf of a host that never answers.
func TestSilentPeerIsUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}()

	got := runClient(t, ln.Addr().String(), testToken, nil, "echo-args")
	require.ErrorIs(t, got.err, client.ErrUnreachable)
}

func TestSessionRejectsDisallowedSubcommand(t *testing.T) {
	addr := startServer(t, Config{AllowCommands: []string{"ls"}})

	got := runClient(t, addr, testToken, nil, "echo-args")
	require.Error(t, got.err)
	require.Contains(t, got.err.Error(), "not allowed")
	require.Equal(t, protocol.ExitNoExec, got.code)
	require.Empty(t, got.stdout)
}

func TestSessionAllowsListedSubcommandAfterFlags(t *testing.T) {
	addr := startServer(t, Config{AllowCommands: []string{"echo-args"}})

	got := runClient(t, addr, testToken, nil, "--debug", "echo-args", "ok")
	require.NoError(t, got.err)
	require.Equal(t, "args:ok\n", got.stdout)
}

func TestSessionForwardsRequestedEnv(t *testing.T) {
	addr := startServer(t, Config{})

	var stdout, stderr bytes.Buffer
	code, err := client.Run(context.Background(), client.Config{
		Addr:   addr,
		Token:  testToken,
		Args:   []string{"show-env", "SBX_DEV_TEST_VAR"},
		Env:    map[string]string{"SBX_DEV_TEST_VAR": "forwarded"},
		Stdout: &stdout,
		Stderr: &stderr,
		TTYFd:  client.NoTTY,
	})
	require.NoError(t, err)
	require.Equal(t, 0, code)
	require.Equal(t, "forwarded\n", stdout.String())
}

func TestSessionAllocatesTTYWhenRequested(t *testing.T) {
	addr := startServer(t, Config{})

	// client.Run only negotiates a PTY when its own stdin is a terminal, which
	// a test process has no reason to own, so drive the protocol directly.
	stdout, exit := rawSession(t, addr, protocol.Start{
		Token: testToken,
		Args:  []string{"tty"},
		TTY:   true,
		Term:  "xterm-256color",
		Rows:  24,
		Cols:  80,
	})
	require.Equal(t, 0, exit.Code, exit.Message)
	require.Contains(t, stdout, "tty", "the child should see a terminal on stdout")
}

func TestSessionAppliesRequestedWindowSize(t *testing.T) {
	addr := startServer(t, Config{})

	stdout, exit := rawSession(t, addr, protocol.Start{
		Token: testToken,
		Args:  []string{"winsize"},
		TTY:   true,
		Rows:  40,
		Cols:  132,
	})
	require.Equal(t, 0, exit.Code, exit.Message)
	require.Contains(t, stdout, "40 132")
}

func TestSessionFallsBackToConventionalWindowSize(t *testing.T) {
	addr := startServer(t, Config{})

	stdout, exit := rawSession(t, addr, protocol.Start{
		Token: testToken,
		Args:  []string{"winsize"},
		TTY:   true,
	})
	require.Equal(t, 0, exit.Code, exit.Message)
	require.Contains(t, stdout, "24 80", "a client that reports no size must not get a 0x0 terminal")
}

func TestSessionSetsTermForTTY(t *testing.T) {
	addr := startServer(t, Config{})

	stdout, exit := rawSession(t, addr, protocol.Start{
		Token: testToken,
		Args:  []string{"show-env", "TERM"},
		TTY:   true,
		Term:  "vt220",
	})
	require.Equal(t, 0, exit.Code, exit.Message)
	require.Contains(t, stdout, "vt220")
}

// rawSession speaks the protocol directly, returning everything the server sent
// on stdout together with the final exit frame.
func rawSession(t *testing.T, addr string, start protocol.Start) (string, protocol.Exit) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	require.NoError(t, protocol.WriteHandshake(conn))
	fw := protocol.NewWriter(conn)
	require.NoError(t, fw.WriteJSON(protocol.KindStart, start))

	fr := protocol.NewReader(conn)
	var stdout strings.Builder
	for {
		frame, err := fr.ReadFrame()
		require.NoError(t, err)
		switch frame.Kind {
		case protocol.KindReady:
		case protocol.KindStdout, protocol.KindStderr:
			stdout.Write(frame.Payload)
		case protocol.KindExit:
			var exit protocol.Exit
			require.NoError(t, protocol.DecodeJSON(frame, &exit))
			return stdout.String(), exit
		}
	}
}

func TestNewRejectsMissingToken(t *testing.T) {
	_, err := New(Config{SbxPath: "sh"})
	require.ErrorContains(t, err, "token is required")
}

func TestNewRejectsUnknownSbxBinary(t *testing.T) {
	_, err := New(Config{Token: testToken, SbxPath: filepath.Join(t.TempDir(), "absent")})
	require.ErrorContains(t, err, "locate sbx binary")
}

func TestServeRequiresListenFirst(t *testing.T) {
	srv, err := New(Config{Token: testToken, SbxPath: "sh"})
	require.NoError(t, err)
	require.ErrorContains(t, srv.Serve(context.Background()), "Listen must be called")
}

func TestHandshakeTimeoutClosesIdleConnection(t *testing.T) {
	addr := startServer(t, Config{HandshakeTimeout: 200 * time.Millisecond})

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Never send a handshake; the server must not hold the session open.
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = io.ReadAll(conn)
	require.NoError(t, err)
}

func TestDescribeCommand(t *testing.T) {
	require.Equal(t, "sbx ls --all", describeCommand(protocol.Start{Args: []string{"ls", "--all"}}))
	require.Equal(t, "sbx ls on a terminal", describeCommand(protocol.Start{Args: []string{"ls"}, TTY: true}))
	require.Equal(t, "sbx", describeCommand(protocol.Start{}))
}

func TestDescribeResultPrefersTheFailureMessage(t *testing.T) {
	require.Equal(t, "succeeded", describeResult(protocol.Exit{}))
	require.Equal(t, "exited with code 2", describeResult(protocol.Exit{Code: 2}))
	require.Equal(t,
		"failed: no such command",
		describeResult(protocol.Exit{Code: protocol.ExitNoExec, Message: "no such command"}),
	)
}
