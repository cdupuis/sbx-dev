package server

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cdupuis/sbx-warden/internal/client"
	"github.com/cdupuis/sbx-warden/internal/identity"
)

// liveRegistry returns a registry holding the generation testToken carries,
// alongside its path so a test can revoke through a second handle the way a
// separate command does.
func liveRegistry(t *testing.T) (*identity.Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "generations.json")
	reg, err := identity.OpenRegistry(path)
	require.NoError(t, err)
	require.NoError(t, reg.Record(testSandbox, 1))
	return reg, path
}

func revoke(t *testing.T, path, sandbox string) {
	t.Helper()
	// Through its own handle, because the point is that the process enforcing a
	// revocation is never the one recording it.
	reg, err := identity.OpenRegistry(path)
	require.NoError(t, err)
	_, err = reg.Revoke(sandbox)
	require.NoError(t, err)
}

// watchWriter records what a session produced and signals the first write, so a
// test can wait until the session is certainly running rather than sleeping.
type watchWriter struct {
	started chan struct{}
	once    sync.Once

	mu  sync.Mutex
	buf bytes.Buffer
}

func newWatchWriter() *watchWriter {
	return &watchWriter{started: make(chan struct{})}
}

func (w *watchWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buf.Write(p)
	w.mu.Unlock()
	if n > 0 {
		w.once.Do(func() { close(w.started) })
	}
	return n, err
}

func (w *watchWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// liveClient is a session that stays open until its stdin closes or something
// ends it.
type liveClient struct {
	stdin  *io.PipeWriter
	stdout *watchWriter
	stderr *watchWriter
	done   chan result
}

// startLiveSession opens a session that echoes stdin and returns once it has
// echoed, so the server has authenticated and started tracking it.
func startLiveSession(t *testing.T, addr, token string) *liveClient {
	t.Helper()

	pr, pw := io.Pipe()
	live := &liveClient{
		stdin:  pw,
		stdout: newWatchWriter(),
		stderr: newWatchWriter(),
		done:   make(chan result, 1),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	go func() {
		code, err := client.Run(ctx, client.Config{
			Addr:   addr,
			Token:  token,
			Args:   []string{"echo-stdin"},
			Stdin:  pr,
			Stdout: live.stdout,
			Stderr: live.stderr,
			TTYFd:  client.NoTTY,
		})
		live.done <- result{code: code, err: err, stdout: live.stdout.String(), stderr: live.stderr.String()}
	}()

	_, err := pw.Write([]byte("live\n"))
	require.NoError(t, err)

	select {
	case <-live.stdout.started:
	case got := <-live.done:
		t.Fatalf("the session ended before it was running: %+v", got)
	case <-time.After(10 * time.Second):
		t.Fatal("the session never started")
	}
	return live
}

func TestRevokingTakesEffectWithoutRestartingTheServer(t *testing.T) {
	// The bug this pins down: the server used to answer from the registry it read
	// at start-up, so a token stayed usable until someone restarted it.
	reg, path := liveRegistry(t)
	addr := startServer(t, Config{Generations: reg})

	got := runClient(t, addr, testToken, nil, "version")
	require.NoError(t, got.err)

	revoke(t, path, testSandbox)

	got = runClient(t, addr, testToken, nil, "version")
	require.ErrorContains(t, got.err, "has been retired")
}

func TestRunningSessionEndsWhenItsTokenIsRevoked(t *testing.T) {
	reg, path := liveRegistry(t)
	addr := startServer(t, Config{Generations: reg, RevocationInterval: 20 * time.Millisecond})
	live := startLiveSession(t, addr, testToken)

	revoke(t, path, testSandbox)

	select {
	case got := <-live.done:
		require.Contains(t, got.stderr, "token has been retired",
			"the caller should learn why its session ended")
	case <-time.After(10 * time.Second):
		t.Fatal("a session outlived the token that opened it")
	}
}

func TestRunningSessionSurvivesARegistryItCannotRead(t *testing.T) {
	reg, path := liveRegistry(t)
	addr := startServer(t, Config{Generations: reg, RevocationInterval: 20 * time.Millisecond})
	live := startLiveSession(t, addr, testToken)

	require.NoError(t, os.WriteFile(path, []byte("{truncated"), 0o600))

	// Several checks fail in this window. Ending sessions on a fault that says
	// nothing about whether a token was retired would make a corrupt file an
	// outage.
	select {
	case got := <-live.done:
		t.Fatalf("an unreadable registry ended a running session: %+v", got)
	case <-time.After(500 * time.Millisecond):
	}

	require.NoError(t, live.stdin.Close())
	got := <-live.done
	require.NoError(t, got.err)
	require.Equal(t, 0, got.code)
	require.Equal(t, "live\n", got.stdout)
}

func TestSessionIsRefusedWhileTheRegistryCannotBeRead(t *testing.T) {
	reg, path := liveRegistry(t)
	addr := startServer(t, Config{Generations: reg})
	require.NoError(t, os.WriteFile(path, []byte("{truncated"), 0o600))

	// A registry that exists but cannot be read is not evidence that a token is
	// still current, and starting a session is the last point that can refuse.
	got := runClient(t, addr, testToken, nil, "version")
	require.ErrorContains(t, got.err, "cannot check whether your token is current")
}

func TestSessionsAreUntrackedWhenTheyEnd(t *testing.T) {
	reg, _ := liveRegistry(t)
	srv := startServerInstance(t, Config{Generations: reg})

	got := runClient(t, srv.Addr().String(), testToken, nil, "version")
	require.NoError(t, got.err)

	// A tracker that only ever grows would keep a cancel function and a writer
	// per session for the life of the server.
	require.Eventually(t, func() bool {
		return len(srv.live.snapshot()) == 0
	}, 5*time.Second, 20*time.Millisecond)
}
