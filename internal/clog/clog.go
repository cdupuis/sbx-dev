// Package clog provides a console slog handler for a foreground process.
package clog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// timeFormat omits the date because the server is watched in a terminal while
// it runs, where a wall-clock time is enough to correlate with a request.
const timeFormat = "15:04:05"

// Handler writes each record as "15:04:05 LEVEL message".
//
// Attributes are appended as parenthesised values with their keys omitted, so
// that lines read as sentences rather than as logfmt. That makes the message
// the only place a reader learns what a value means: name things in the message
// rather than passing attributes.
type Handler struct {
	// mu is shared with handlers derived through WithAttrs so that concurrent
	// sessions cannot interleave partial lines.
	mu    *sync.Mutex
	out   io.Writer
	level slog.Leveler
	attrs []slog.Attr
}

// New returns a Handler writing to out, discarding records below level.
func New(out io.Writer, level slog.Leveler) *Handler {
	if level == nil {
		level = slog.LevelInfo
	}
	return &Handler{mu: &sync.Mutex{}, out: out, level: level}
}

func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *Handler) Handle(_ context.Context, record slog.Record) error {
	stamp := record.Time
	if stamp.IsZero() {
		stamp = time.Now()
	}

	var line strings.Builder
	line.WriteString(stamp.Format(timeFormat))
	fmt.Fprintf(&line, " %-5s ", record.Level.String())
	line.WriteString(record.Message)

	values := make([]string, 0, len(h.attrs)+record.NumAttrs())
	for _, attr := range h.attrs {
		values = appendValue(values, attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		values = appendValue(values, attr)
		return true
	})
	if len(values) > 0 {
		line.WriteString(" (")
		line.WriteString(strings.Join(values, ", "))
		line.WriteString(")")
	}
	line.WriteString("\n")

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.out, line.String())
	return err
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	derived := *h
	derived.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &derived
}

// WithGroup returns the handler unchanged: group names qualify attribute keys,
// which this handler does not print.
func (h *Handler) WithGroup(string) slog.Handler { return h }

func appendValue(dst []string, attr slog.Attr) []string {
	attr.Value = attr.Value.Resolve()
	if attr.Equal(slog.Attr{}) {
		return dst
	}
	rendered := attr.Value.String()
	if rendered == "" {
		return dst
	}
	return append(dst, rendered)
}
