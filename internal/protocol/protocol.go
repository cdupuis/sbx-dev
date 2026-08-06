// Package protocol implements the framed TCP wire format spoken between the
// sbx client and the sbx-warden server.
package protocol

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	magic   = "SBXW"
	version = 1

	// MaxPayload bounds one frame's payload so a corrupt or hostile length
	// prefix cannot force an unbounded allocation.
	MaxPayload = 1 << 20

	headerLen = 5
)

// Exit codes with meanings the client relies on, following shell convention
// for the two "could not execute" cases.
const (
	ExitProtocol = 1
	ExitNoExec   = 126
	ExitNotFound = 127
)

var (
	// ErrVersionMismatch reports a peer speaking an incompatible protocol.
	ErrVersionMismatch = errors.New("protocol version mismatch")
	// ErrNotSbxWarden reports a peer that is not an sbx-warden endpoint.
	ErrNotSbxWarden = errors.New("not an sbx-warden endpoint")
	// ErrPayloadTooLarge reports a frame whose length prefix exceeds MaxPayload.
	ErrPayloadTooLarge = errors.New("frame payload too large")
)

// Kind identifies a frame's type.
type Kind uint8

const (
	KindStart Kind = iota + 1
	KindReady
	KindStdin
	KindStdinClose
	KindStdout
	KindStderr
	KindResize
	KindSignal
	KindExit
)

func (k Kind) String() string {
	switch k {
	case KindStart:
		return "start"
	case KindReady:
		return "ready"
	case KindStdin:
		return "stdin"
	case KindStdinClose:
		return "stdin-close"
	case KindStdout:
		return "stdout"
	case KindStderr:
		return "stderr"
	case KindResize:
		return "resize"
	case KindSignal:
		return "signal"
	case KindExit:
		return "exit"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(k))
	}
}

// The session handshake is HTTP rather than a frame, because a sandbox's egress
// proxy can only substitute a secret that travels in an HTTP header. It trades
// the caller's token for a single-use ticket, which then opens the framed
// session below. The two share a port; LooksLikeHandshake tells them apart.
const (
	// SessionPath is the route that issues a session ticket.
	SessionPath = "/v1/session"
	// TokenHeader carries the caller's token on that request.
	TokenHeader = "Sbx-Warden-Token"
)

// SessionResponse answers a successful handshake. ExpiresIn is in seconds.
type SessionResponse struct {
	Ticket    string `json:"ticket"`
	ExpiresIn int    `json:"expires_in"`
}

// MagicLen is the number of leading bytes LooksLikeHandshake examines.
const MagicLen = len(magic)

// LooksLikeHandshake reports whether b opens a framed session, so a server
// sharing one port between this protocol and the HTTP handshake can dispatch on
// the first bytes of a connection.
func LooksLikeHandshake(b []byte) bool {
	return len(b) >= len(magic) && string(b[:len(magic)]) == magic
}

// Start opens a session. It is the first frame the client sends and carries
// the command line to run verbatim as arguments to the server's sbx binary.
type Start struct {
	Token string            `json:"token"`
	Args  []string          `json:"args"`
	Env   map[string]string `json:"env,omitempty"`
	Cwd   string            `json:"cwd,omitempty"`
	TTY   bool              `json:"tty"`
	Term  string            `json:"term,omitempty"`
	Rows  uint16            `json:"rows,omitempty"`
	Cols  uint16            `json:"cols,omitempty"`
}

// Resize carries a new terminal size for a TTY session.
type Resize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

// Signal asks the server to deliver a signal to the child process. Name is an
// unprefixed signal name such as "INT" or "TERM".
type Signal struct {
	Name string `json:"name"`
}

// Exit is the final frame of every session. A non-empty Message describes a
// failure that happened before or instead of the child running.
type Exit struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

// Frame is a decoded protocol frame. Payload is owned by the caller.
type Frame struct {
	Kind    Kind
	Payload []byte
}

// WriteHandshake announces the protocol magic and version.
func WriteHandshake(w io.Writer) error {
	buf := append([]byte(magic), version)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write handshake: %w", err)
	}
	return nil
}

// ReadHandshake validates a peer's magic and version.
func ReadHandshake(r io.Reader) error {
	buf := make([]byte, len(magic)+1)
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}
	if string(buf[:len(magic)]) != magic {
		return ErrNotSbxWarden
	}
	if buf[len(magic)] != version {
		return fmt.Errorf("%w: peer speaks %d, want %d", ErrVersionMismatch, buf[len(magic)], version)
	}
	return nil
}

// Writer serializes frames onto a connection. It is safe for concurrent use so
// that stdout and stderr can be streamed from separate goroutines.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// WriteFrame writes a single frame. Payloads longer than MaxPayload are
// rejected; use Stream to send arbitrarily long byte streams.
func (fw *Writer) WriteFrame(kind Kind, payload []byte) error {
	if len(payload) > MaxPayload {
		return ErrPayloadTooLarge
	}
	var header [headerLen]byte
	header[0] = byte(kind)
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))

	fw.mu.Lock()
	defer fw.mu.Unlock()
	if _, err := fw.w.Write(header[:]); err != nil {
		return fmt.Errorf("write %s header: %w", kind, err)
	}
	if len(payload) == 0 {
		return nil
	}
	if _, err := fw.w.Write(payload); err != nil {
		return fmt.Errorf("write %s payload: %w", kind, err)
	}
	return nil
}

// WriteJSON encodes v as a frame payload.
func (fw *Writer) WriteJSON(kind Kind, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", kind, err)
	}
	return fw.WriteFrame(kind, payload)
}

// Stream adapts a frame kind to an io.Writer, splitting writes that exceed
// MaxPayload across frames.
func (fw *Writer) Stream(kind Kind) io.Writer {
	return &streamWriter{fw: fw, kind: kind}
}

type streamWriter struct {
	fw   *Writer
	kind Kind
}

func (sw *streamWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxPayload {
			chunk = chunk[:MaxPayload]
		}
		if err := sw.fw.WriteFrame(sw.kind, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// Reader deserializes frames from a connection. It is not safe for concurrent
// use; a session should read frames from a single goroutine.
type Reader struct {
	r *bufio.Reader
}

func NewReader(r io.Reader) *Reader {
	return &Reader{r: bufio.NewReader(r)}
}

// ReadFrame reads the next frame, returning io.EOF at a clean end of stream.
func (fr *Reader) ReadFrame() (Frame, error) {
	var header [headerLen]byte
	if _, err := io.ReadFull(fr.r, header[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return Frame{}, fmt.Errorf("read frame header: %w", err)
		}
		return Frame{}, err
	}
	kind := Kind(header[0])
	length := binary.BigEndian.Uint32(header[1:])
	if length > MaxPayload {
		return Frame{}, fmt.Errorf("%w: %s frame declares %d bytes", ErrPayloadTooLarge, kind, length)
	}
	if length == 0 {
		return Frame{Kind: kind}, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(fr.r, payload); err != nil {
		return Frame{}, fmt.Errorf("read %s payload: %w", kind, err)
	}
	return Frame{Kind: kind, Payload: payload}, nil
}

// DecodeJSON unmarshals a frame payload into v.
func DecodeJSON(f Frame, v any) error {
	if err := json.Unmarshal(f.Payload, v); err != nil {
		return fmt.Errorf("decode %s: %w", f.Kind, err)
	}
	return nil
}
