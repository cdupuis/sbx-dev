package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/cdupuis/sbx-warden/internal/protocol"
)

// maxHandshakeBody bounds what is drained from a handshake request. The request
// carries its credential in a header and needs no body, so anything sent is
// read only far enough to keep the connection in a sane state before replying.
const maxHandshakeBody = 4 << 10

// peekedConn restores bytes already read from a connection while deciding which
// protocol it speaks, so the chosen handler sees the stream from the start.
type peekedConn struct {
	net.Conn
	r io.Reader
}

func (c peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// serveHandshake answers the HTTP request that trades a caller's token for a
// session ticket.
//
// The token arrives in a header because that is the only part of a request the
// sandbox's egress proxy will substitute a secret into: a sandbox can hold a
// placeholder and never the token itself. The ticket that comes back opens the
// framed session on a second connection.
func (s *Server) serveHandshake(conn net.Conn, br *bufio.Reader) {
	peer := conn.RemoteAddr().String()

	req, err := http.ReadRequest(br)
	if err != nil {
		s.log.Warn(fmt.Sprintf("rejected %s: could not read its handshake request: %v", peer, err))
		writeHandshakeError(conn, http.StatusBadRequest, "malformed request")
		return
	}
	defer req.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, maxHandshakeBody))

	if req.URL.Path != protocol.SessionPath {
		writeHandshakeError(conn, http.StatusNotFound, "not an sbx-warden handshake endpoint")
		return
	}
	if req.Method != http.MethodPost {
		writeHandshakeError(conn, http.StatusMethodNotAllowed, "the handshake is a POST")
		return
	}

	c, err := s.authenticate(peer, req.Header.Get(protocol.TokenHeader))
	if err != nil {
		s.log.Warn(fmt.Sprintf("rejected the handshake from %s: %v", peer, err))
		writeHandshakeError(conn, http.StatusUnauthorized, err.Error())
		return
	}

	ticket, ttl, err := s.tickets.issue(c)
	if err != nil {
		s.log.Error(fmt.Sprintf("could not issue a ticket to %s: %v", c, err))
		writeHandshakeError(conn, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.log.Debug(fmt.Sprintf("%s authenticated and holds a ticket", c))

	body, err := json.Marshal(protocol.SessionResponse{
		Ticket:    ticket,
		ExpiresIn: int(ttl.Seconds()),
	})
	if err != nil {
		writeHandshakeError(conn, http.StatusInternalServerError, "could not encode the ticket")
		return
	}
	writeHandshakeResponse(conn, http.StatusOK, "application/json", body)
}

func writeHandshakeError(conn net.Conn, status int, message string) {
	writeHandshakeResponse(conn, status, "text/plain; charset=utf-8", []byte(message+"\n"))
}

// writeHandshakeResponse writes one response and asks for the connection to be
// closed: the session that follows needs its own connection anyway, so there is
// nothing to gain from keeping this one alive.
func writeHandshakeResponse(conn net.Conn, status int, contentType string, body []byte) {
	resp := http.Response{
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{contentType}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
	}
	_ = resp.Write(conn)
}
