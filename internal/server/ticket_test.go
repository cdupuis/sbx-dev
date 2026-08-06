package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cdupuis/sbx-dev/internal/identity"
)

func testCaller(sandbox string) caller {
	return caller{peer: "127.0.0.1:1", sandbox: identity.Identity{Sandbox: sandbox, Generation: 1}}
}

func TestTicketRedeemsToTheCallerItWasIssuedTo(t *testing.T) {
	tickets := newTickets(time.Minute, nil)

	ticket, ttl, err := tickets.issue(testCaller("worker-1"))
	require.NoError(t, err)
	require.Equal(t, time.Minute, ttl)
	require.True(t, isTicket(ticket), "a ticket must be recognisable as one: %q", ticket)

	got, ok := tickets.redeem(ticket)
	require.True(t, ok)
	require.Equal(t, "worker-1", got.sandbox.Sandbox)
}

func TestTicketIsRefusedTheSecondTime(t *testing.T) {
	// Single use is what bounds a ticket that was left behind in a sandbox.
	tickets := newTickets(time.Minute, nil)
	ticket, _, err := tickets.issue(testCaller("worker-1"))
	require.NoError(t, err)

	_, ok := tickets.redeem(ticket)
	require.True(t, ok)

	_, ok = tickets.redeem(ticket)
	require.False(t, ok, "a redeemed ticket must not work again")
}

func TestTicketExpires(t *testing.T) {
	now := time.Now()
	tickets := newTickets(30*time.Second, func() time.Time { return now })

	ticket, _, err := tickets.issue(testCaller("worker-1"))
	require.NoError(t, err)

	now = now.Add(31 * time.Second)
	_, ok := tickets.redeem(ticket)
	require.False(t, ok)
}

func TestUnknownTicketIsRefused(t *testing.T) {
	tickets := newTickets(time.Minute, nil)

	_, ok := tickets.redeem(ticketPrefix + "not-a-ticket")
	require.False(t, ok)
}

func TestExpiredTicketsDoNotAccumulate(t *testing.T) {
	now := time.Now()
	tickets := newTickets(time.Second, func() time.Time { return now })

	for range maxLiveTickets {
		_, _, err := tickets.issue(testCaller("worker-1"))
		require.NoError(t, err)
	}

	// At the cap, an unredeemed backlog would otherwise refuse every later
	// handshake; expiry has to make room.
	now = now.Add(2 * time.Second)
	_, _, err := tickets.issue(testCaller("worker-1"))
	require.NoError(t, err)
}
