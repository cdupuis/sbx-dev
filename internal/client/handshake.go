package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cdupuis/sbx-dev/internal/protocol"
)

// maxHandshakeResponse bounds what is read from a handshake reply, which is a
// ticket or a short refusal.
const maxHandshakeResponse = 8 << 10

// acquireTicket trades the configured token for the single-use ticket that opens
// a session. Every session begins here, so the token is only ever presented to
// the handshake and never on the session itself.
//
// The request deliberately honours the ambient proxy configuration. Inside a
// sandbox that means it travels through the egress proxy, which substitutes the
// real token into the token header — so the sandbox can hold a placeholder and
// never the token itself. That substitution reaches headers only, which is why
// the handshake is an HTTP request and not a frame on the session. Outside a
// sandbox there is no proxy and the token goes as it stands.
func acquireTicket(ctx context.Context, cfg Config) (string, error) {
	endpoint := "http://" + cfg.Addr + protocol.SessionPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set(protocol.TokenHeader, cfg.Token)

	httpClient := &http.Client{
		Timeout:   cfg.DialTimeout,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// The handshake is the first thing to touch the network, so this is
		// where an absent server or a missing network policy rule surfaces.
		return "", fmt.Errorf("%w: handshake with %s: %w", ErrUnreachable, cfg.Addr, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHandshakeResponse))

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(refusal(body, resp.Status))
	}

	var session protocol.SessionResponse
	if err := json.Unmarshal(body, &session); err != nil || session.Ticket == "" {
		return "", errors.New("the sbx-dev server answered the handshake without a ticket")
	}
	return session.Ticket, nil
}

// refusal prefers the server's own explanation, falling back to the status line
// when it sent none.
func refusal(body []byte, status string) string {
	if message := strings.TrimSpace(string(body)); message != "" {
		return message
	}
	return status
}
