// Package client dials an sbx-warden server and runs one command over the
// connection, relaying stdio and returning the remote exit code.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/cdupuis/sbx-warden/internal/protocol"
)

// NoTTY disables terminal handling when used as Config.TTYFd.
const NoTTY = -1

// ErrUnreachable reports that no session could be established, as opposed to a
// command that ran and failed or a server that deliberately refused the
// request. Callers use it to decide whether connectivity advice is warranted.
//
// It covers more than dial failures: a sandbox's egress proxy accepts the
// connection before it dials the host, so an absent server or a missing network
// policy rule both surface as a closed connection rather than a refused dial.
var ErrUnreachable = errors.New("could not start a session")

// Config describes a single remote command invocation.
type Config struct {
	Addr        string
	Token       string
	Args        []string
	Env         map[string]string
	DialTimeout time.Duration

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// TTYFd is the descriptor to negotiate a remote PTY against. Set it to
	// NoTTY, or to a descriptor that is not a terminal, to run without one.
	TTYFd int
}

// Run executes cfg.Args on the server and returns the command's exit code. A
// non-nil error means the command never ran or the session broke down, in which
// case the returned code is still safe to exit with.
func Run(ctx context.Context, cfg Config) (int, error) {
	if cfg.Addr == "" {
		return protocol.ExitProtocol, errors.New("no server address configured")
	}
	if cfg.Token == "" {
		return protocol.ExitProtocol, errors.New("no token configured")
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}

	// Authenticate before dialing, so the session presents a ticket rather than
	// the token it was configured with.
	ticket, err := acquireTicket(ctx, cfg)
	if err != nil {
		return protocol.ExitProtocol, err
	}
	cfg.Token = ticket

	dialer := net.Dialer{Timeout: cfg.DialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		return protocol.ExitProtocol, fmt.Errorf("%w: connect to %s: %w", ErrUnreachable, cfg.Addr, err)
	}
	defer conn.Close()

	useTTY := cfg.TTYFd != NoTTY && term.IsTerminal(cfg.TTYFd)

	var restore func()
	if useTTY {
		state, err := term.MakeRaw(cfg.TTYFd)
		if err != nil {
			return protocol.ExitProtocol, fmt.Errorf("switch terminal to raw mode: %w", err)
		}
		restore = func() { _ = term.Restore(cfg.TTYFd, state) }
		// Restore before returning so a later error message is not printed
		// into a raw terminal.
		defer restore()
	}

	code, err := run(ctx, conn, cfg, useTTY, restore)
	return code, err
}

func run(ctx context.Context, conn net.Conn, cfg Config, useTTY bool, restore func()) (int, error) {
	if err := protocol.WriteHandshake(conn); err != nil {
		return protocol.ExitProtocol, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}

	fw := protocol.NewWriter(conn)
	fr := protocol.NewReader(conn)

	start := protocol.Start{
		Token: cfg.Token,
		Args:  cfg.Args,
		Env:   cfg.Env,
		TTY:   useTTY,
	}
	if useTTY {
		start.Term = os.Getenv("TERM")
		if cols, rows, err := term.GetSize(cfg.TTYFd); err == nil {
			start.Cols, start.Rows = uint16(cols), uint16(rows)
		}
	}
	if err := fw.WriteJSON(protocol.KindStart, start); err != nil {
		return protocol.ExitProtocol, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}

	// The server replies Ready once authenticated, or Exit to refuse.
	frame, err := fr.ReadFrame()
	if err != nil {
		return protocol.ExitProtocol, fmt.Errorf("%w: awaiting server ready: %w", ErrUnreachable, err)
	}
	switch frame.Kind {
	case protocol.KindReady:
	case protocol.KindExit:
		var exit protocol.Exit
		if err := protocol.DecodeJSON(frame, &exit); err != nil {
			return protocol.ExitProtocol, err
		}
		if exit.Message != "" {
			return exit.Code, errors.New(exit.Message)
		}
		return exit.Code, nil
	default:
		return protocol.ExitProtocol, fmt.Errorf("%w: expected ready frame, got %s", ErrUnreachable, frame.Kind)
	}

	go forwardStdin(cfg.Stdin, fw)

	if useTTY {
		stopResize := watchResize(cfg.TTYFd, fw)
		defer stopResize()
	} else {
		stopSignals := forwardSignals(fw)
		defer stopSignals()
	}

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	return relayOutput(fr, cfg, restore)
}

func relayOutput(fr *protocol.Reader, cfg Config, restore func()) (int, error) {
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return protocol.ExitProtocol, errors.New("server closed the connection before reporting an exit code")
			}
			return protocol.ExitProtocol, fmt.Errorf("read from server: %w", err)
		}

		switch frame.Kind {
		case protocol.KindStdout:
			if _, err := cfg.Stdout.Write(frame.Payload); err != nil {
				return protocol.ExitProtocol, fmt.Errorf("write stdout: %w", err)
			}
		case protocol.KindStderr:
			if _, err := cfg.Stderr.Write(frame.Payload); err != nil {
				return protocol.ExitProtocol, fmt.Errorf("write stderr: %w", err)
			}
		case protocol.KindExit:
			var exit protocol.Exit
			if err := protocol.DecodeJSON(frame, &exit); err != nil {
				return protocol.ExitProtocol, err
			}
			if restore != nil {
				restore()
			}
			if exit.Message != "" {
				return exit.Code, errors.New(exit.Message)
			}
			return exit.Code, nil
		}
	}
}

// forwardStdin streams local input to the server. It may stay blocked in Read
// after the session ends; callers are expected to be short-lived processes.
func forwardStdin(stdin io.Reader, fw *protocol.Writer) {
	if stdin == nil {
		_ = fw.WriteFrame(protocol.KindStdinClose, nil)
		return
	}
	if _, err := io.Copy(fw.Stream(protocol.KindStdin), stdin); err != nil {
		return
	}
	_ = fw.WriteFrame(protocol.KindStdinClose, nil)
}

func sendResize(fw *protocol.Writer, rows, cols int) {
	_ = fw.WriteJSON(protocol.KindResize, protocol.Resize{
		Rows: uint16(rows),
		Cols: uint16(cols),
	})
}

// forwardSignals relays interrupts to the remote process instead of killing the
// client, so the server-side command controls when the session ends.
func forwardSignals(fw *protocol.Writer) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})

	go func() {
		for {
			select {
			case sig := <-ch:
				name := "INT"
				if sig == syscall.SIGTERM {
					name = "TERM"
				}
				_ = fw.WriteJSON(protocol.KindSignal, protocol.Signal{Name: name})
			case <-done:
				return
			}
		}
	}()

	return func() {
		signal.Stop(ch)
		close(done)
	}
}
