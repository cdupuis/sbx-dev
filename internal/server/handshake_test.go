package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cdupuis/sbx-warden/internal/protocol"
)

// handshake performs the HTTP exchange a client makes before opening a session.
// It bypasses any ambient proxy: the substitution a proxy performs is not what
// these tests are about.
func handshake(t *testing.T, addr, token string) (int, []byte) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, "http://"+addr+protocol.SessionPath, http.NoBody)
	require.NoError(t, err)
	req.Header.Set(protocol.TokenHeader, token)

	resp, err := (&http.Client{Transport: &http.Transport{}}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

func ticketFor(t *testing.T, addr, token string) string {
	t.Helper()

	status, body := handshake(t, addr, token)
	require.Equal(t, http.StatusOK, status, "handshake refused: %s", body)

	var session protocol.SessionResponse
	require.NoError(t, json.Unmarshal(body, &session))
	require.NotEmpty(t, session.Ticket)
	require.Positive(t, session.ExpiresIn)
	return session.Ticket
}

// The point of the handshake: a session authenticated by a ticket is authorized
// as the sandbox that presented the token, so the token itself never has to
// travel on the session.
func TestTicketCarriesTheSandboxIdentityIntoTheSession(t *testing.T) {
	ps := startPolicyServer(t)

	ticket := ticketFor(t, ps.addr, ps.token(t, "orchestrator", 1))
	stdout, exit := rawSession(t, ps.addr, protocol.Start{Token: ticket, Args: []string{"rm", "worker-2"}})
	require.Equal(t, 0, exit.Code, exit.Message)
	require.Contains(t, stdout, "removed:worker-2")

	// The same command from a worker's ticket is refused, so the ticket is
	// carrying identity rather than merely proving the handshake happened.
	workerTicket := ticketFor(t, ps.addr, ps.token(t, "worker-1", 1))
	_, refused := rawSession(t, ps.addr, protocol.Start{Token: workerTicket, Args: []string{"rm", "worker-2"}})
	require.Contains(t, refused.Message, "policy does not allow sbx rm")
}

func TestSessionRefusesAReusedTicket(t *testing.T) {
	ps := startPolicyServer(t)
	ticket := ticketFor(t, ps.addr, ps.token(t, "worker-1", 1))

	_, exit := rawSession(t, ps.addr, protocol.Start{Token: ticket, Args: []string{"version"}})
	require.Equal(t, 0, exit.Code, exit.Message)

	_, reused := rawSession(t, ps.addr, protocol.Start{Token: ticket, Args: []string{"version"}})
	require.Contains(t, reused.Message, "already used")
}

func TestHandshakeRefusesAForgedToken(t *testing.T) {
	ps := startPolicyServer(t)

	status, body := handshake(t, ps.addr, "v1.orchestrator.1.notasignature")
	require.Equal(t, http.StatusUnauthorized, status)
	require.Contains(t, string(body), "invalid token")
}

// A ticket is not a credential the handshake accepts, so one cannot be spent to
// mint another and outlive its single use.
func TestHandshakeRefusesATicket(t *testing.T) {
	ps := startPolicyServer(t)
	ticket := ticketFor(t, ps.addr, ps.token(t, "worker-1", 1))

	status, _ := handshake(t, ps.addr, ticket)
	require.Equal(t, http.StatusUnauthorized, status)
}

func TestHandshakeRefusesATokenSignedByAnotherKey(t *testing.T) {
	ps := startPolicyServer(t)

	// testToken is well-formed and names a sandbox, but it is signed by the
	// package's fixed key rather than this server's.
	status, body := handshake(t, ps.addr, testToken)
	require.Equal(t, http.StatusUnauthorized, status)
	require.Contains(t, string(body), "invalid token")
}

func TestHandshakeAnswersOnlyItsOwnRoute(t *testing.T) {
	addr := startServer(t, Config{})

	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/", http.NoBody)
	require.NoError(t, err)
	resp, err := (&http.Client{Transport: &http.Transport{}}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHandshakeRequiresPost(t *testing.T) {
	addr := startServer(t, Config{})

	req, err := http.NewRequest(http.MethodGet, "http://"+addr+protocol.SessionPath, http.NoBody)
	require.NoError(t, err)
	resp, err := (&http.Client{Transport: &http.Transport{}}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

// Every session goes through the handshake, so a token on the session itself is
// refused. That keeps a token to the one request a sandbox's egress proxy can
// substitute it into, and leaves the session carrying only a single-use ticket.
func TestFramedSessionRefusesAToken(t *testing.T) {
	addr := startServer(t, Config{})

	_, exit := rawSession(t, addr, protocol.Start{Token: testToken, Args: []string{"version"}})
	require.NotEqual(t, 0, exit.Code)
	require.Contains(t, exit.Message, "opens with a ticket from the handshake")
}
