package server

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

// defaultRevocationInterval is how often running sessions are rechecked against
// the registry. It bounds how long a retired token keeps a session it already
// opened, so it trades promptness against reading a small file that often.
const defaultRevocationInterval = 5 * time.Second

// liveSession is a running session a revocation may have to end.
type liveSession struct {
	caller caller
	// stop ends the session by cancelling the context its command runs under,
	// which kills the process tree.
	stop context.CancelFunc
	// notify carries a line back to the caller. The frame writer serializes its
	// own writes, so this is safe alongside the command's output.
	notify io.Writer
}

// liveSessions tracks sessions that have authenticated and not yet ended.
type liveSessions struct {
	mu   sync.Mutex
	next uint64
	open map[uint64]liveSession
}

func newLiveSessions() *liveSessions {
	return &liveSessions{open: map[uint64]liveSession{}}
}

func (l *liveSessions) add(sess liveSession) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.next++
	l.open[l.next] = sess
	return l.next
}

func (l *liveSessions) remove(id uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.open, id)
}

// snapshot copies the open sessions so they can be examined without holding the
// lock, since ending one runs arbitrary teardown.
func (l *liveSessions) snapshot() []liveSession {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]liveSession, 0, len(l.open))
	for _, sess := range l.open {
		out = append(out, sess)
	}
	return out
}

// watchRevocations ends sessions whose token stops being current while they run.
//
// A session authenticates once, at its start, so a command that stays open — a
// shell under "sbx exec" — would otherwise outlive the token that opened it and
// keep working for as long as somebody left it running.
func (s *Server) watchRevocations(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.RevocationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.endRetiredSessions()
		}
	}
}

func (s *Server) endRetiredSessions() {
	for _, sess := range s.live.snapshot() {
		current, err := s.cfg.Generations.Accepts(sess.caller.sandbox)
		if err != nil {
			// Ending every running session because the registry could not be read
			// for a moment would turn a transient fault into an outage, and new
			// sessions are already refused for as long as it lasts.
			s.log.Error(fmt.Sprintf("could not check running sessions against the registry: %v", err))
			return
		}
		if current {
			continue
		}

		s.log.Warn(fmt.Sprintf("ending the session for %s: its token has been retired", sess.caller))
		if sess.notify != nil {
			fmt.Fprintln(sess.notify, "\nsbx: this sandbox's token has been retired, so this session is ending")
		}
		sess.stop()
	}
}
