package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ticketPrefix marks a session ticket. It keeps tickets distinguishable from the
// identity and shared tokens that may arrive in the same field, so a credential
// is only ever checked against the one scheme it belongs to.
const ticketPrefix = "t1."

// defaultTicketTTL bounds how long a ticket stays redeemable. It has to cover
// only the gap between the handshake and the session that follows it.
const defaultTicketTTL = 30 * time.Second

// maxLiveTickets caps outstanding tickets so a caller that requests them without
// ever redeeming one cannot grow the map without bound.
const maxLiveTickets = 1024

// tickets hands out single-use credentials that carry an authenticated caller
// across the two connections a session needs.
//
// A sandbox's identity token travels in an HTTP header, because that is the only
// place the egress proxy can substitute it. The session itself needs a
// bidirectional stream, which an HTTP request through that proxy would buffer.
// A ticket bridges the two: the sandbox holds it only between the handshake and
// the session, and redeeming it consumes it, so a copy left behind authenticates
// nothing.
type tickets struct {
	ttl time.Duration
	now func() time.Time

	mu     sync.Mutex
	issued map[string]issuedTicket
}

type issuedTicket struct {
	caller  caller
	expires time.Time
}

func newTickets(ttl time.Duration, now func() time.Time) *tickets {
	if ttl <= 0 {
		ttl = defaultTicketTTL
	}
	if now == nil {
		now = time.Now
	}
	return &tickets{ttl: ttl, now: now, issued: make(map[string]issuedTicket)}
}

// issue returns a ticket that redeems to c once, and how long it lasts.
func (t *tickets) issue(c caller) (string, time.Duration, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", 0, fmt.Errorf("generate ticket: %w", err)
	}
	ticket := ticketPrefix + base64.RawURLEncoding.EncodeToString(raw[:])

	t.mu.Lock()
	defer t.mu.Unlock()
	t.dropExpiredLocked()
	if len(t.issued) >= maxLiveTickets {
		return "", 0, fmt.Errorf("too many session handshakes are already outstanding")
	}
	t.issued[ticket] = issuedTicket{caller: c, expires: t.now().Add(t.ttl)}
	return ticket, t.ttl, nil
}

// redeem consumes a ticket and reports the caller it was issued to. A ticket that
// is unknown, already redeemed, or expired reports false.
func (t *tickets) redeem(ticket string) (caller, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	issued, ok := t.issued[ticket]
	if !ok {
		return caller{}, false
	}
	delete(t.issued, ticket)
	if t.now().After(issued.expires) {
		return caller{}, false
	}
	return issued.caller, true
}

func (t *tickets) dropExpiredLocked() {
	now := t.now()
	for ticket, issued := range t.issued {
		if now.After(issued.expires) {
			delete(t.issued, ticket)
		}
	}
}

func isTicket(token string) bool { return strings.HasPrefix(token, ticketPrefix) }
