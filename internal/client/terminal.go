package client

import (
	"bytes"
	"io"
	"os"

	"golang.org/x/term"
)

// forTerminal prepares the stream the server says things to the caller on, as
// distinct from the command's own output.
//
// While a session with a PTY runs, the caller's terminal is raw, and a line feed
// there moves down a row without returning to the first column. The command's
// output needs nothing: it comes through the server's PTY, which returns the
// carriage already. What the server writes itself does not, and one such line
// leaves everything printed afterwards indented by its length.
//
// The translation is applied to a terminal only. Redirected stderr is a file that
// should not collect stray carriage returns, and its line discipline is not the
// terminal's.
func forTerminal(w io.Writer) io.Writer {
	f, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return w
	}
	return crlfWriter{w: w}
}

// crlfWriter returns the carriage on every line feed that is not already
// preceded by one.
type crlfWriter struct{ w io.Writer }

func (c crlfWriter) Write(p []byte) (int, error) {
	var out bytes.Buffer
	out.Grow(len(p) + bytes.Count(p, []byte("\n")))
	for i, b := range p {
		if b == '\n' && (i == 0 || p[i-1] != '\r') {
			out.WriteByte('\r')
		}
		out.WriteByte(b)
	}
	if _, err := c.w.Write(out.Bytes()); err != nil {
		return 0, err
	}
	// The count reports what was consumed from p, not what delivering it cost, so
	// a short write of the translation is reported as no progress at all.
	return len(p), nil
}
