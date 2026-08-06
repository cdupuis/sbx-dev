// Package server accepts sbx client connections over TCP and runs the
// requested command against the host's real sbx CLI.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"

	"github.com/cdupuis/sbx-dev/internal/authtoken"
	"github.com/cdupuis/sbx-dev/internal/protocol"
)

// defaultHandshakeTimeout bounds how long an unauthenticated connection may
// occupy a session slot before it must produce a valid Start frame.
const defaultHandshakeTimeout = 10 * time.Second

const (
	defaultRows = 24
	defaultCols = 80
)

// Config configures a Server. Token and SbxPath are required.
type Config struct {
	// Addr is the TCP address to bind. Keep it on loopback: sandboxd dials the
	// host's loopback on the sandbox's behalf when resolving
	// host.docker.internal, so a loopback bind is both reachable from
	// sandboxes and unreachable from the LAN.
	Addr string
	// SbxPath is the sbx binary every session executes.
	SbxPath string
	// Token is the shared secret a client must present.
	Token string
	// Workdir is the working directory for sessions that do not request one.
	Workdir string
	// AllowCommands optionally restricts which sbx subcommands may run. Empty
	// allows every subcommand.
	AllowCommands []string
	// HandshakeTimeout bounds the wait for an authenticated Start frame.
	HandshakeTimeout time.Duration
	Logger           *slog.Logger
}

// Server serves the sbx-dev protocol on a TCP listener.
type Server struct {
	cfg   Config
	allow map[string]struct{}
	log   *slog.Logger

	mu sync.Mutex
	ln net.Listener
}

// New validates cfg and resolves the sbx binary to an absolute path.
func New(cfg Config) (*Server, error) {
	if cfg.Token == "" {
		return nil, errors.New("server: token is required")
	}
	if cfg.SbxPath == "" {
		return nil, errors.New("server: sbx path is required")
	}
	resolved, err := exec.LookPath(cfg.SbxPath)
	if err != nil {
		return nil, fmt.Errorf("server: locate sbx binary %q: %w", cfg.SbxPath, err)
	}
	cfg.SbxPath = resolved

	if cfg.Workdir == "" {
		cfg.Workdir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("server: determine working directory: %w", err)
		}
	}
	info, err := os.Stat(cfg.Workdir)
	if err != nil {
		return nil, fmt.Errorf("server: stat workdir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("server: workdir %s is not a directory", cfg.Workdir)
	}

	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}

	allow := make(map[string]struct{}, len(cfg.AllowCommands))
	for _, cmd := range cfg.AllowCommands {
		if cmd = strings.TrimSpace(cmd); cmd != "" {
			allow[cmd] = struct{}{}
		}
	}

	return &Server{cfg: cfg, allow: allow, log: cfg.Logger}, nil
}

// SbxPath returns the resolved sbx binary.
func (s *Server) SbxPath() string { return s.cfg.SbxPath }

// Workdir returns the resolved default working directory.
func (s *Server) Workdir() string { return s.cfg.Workdir }

// Listen binds the configured address without accepting connections, so a
// caller can read back the chosen port before serving.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.Addr, err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	return nil
}

// Addr returns the bound address, or nil before Listen succeeds.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Close stops the listener. In-flight sessions end when their connections drop.
func (s *Server) Close() error {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln == nil {
		return nil
	}
	return ln.Close()
}

// Serve accepts connections until ctx is cancelled or the listener closes.
// Listen must have succeeded first.
func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	if ln == nil {
		return errors.New("server: Listen must be called before Serve")
	}

	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	peer := conn.RemoteAddr().String()
	fw := protocol.NewWriter(conn)

	_ = conn.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	start, err := readStart(conn)
	if err != nil {
		s.log.Warn(fmt.Sprintf("rejected %s: %v", peer, err))
		_ = fw.WriteJSON(protocol.KindExit, protocol.Exit{
			Code:    protocol.ExitProtocol,
			Message: err.Error(),
		})
		return
	}
	if !authtoken.Equal(start.Token, s.cfg.Token) {
		s.log.Warn(fmt.Sprintf("rejected %s: invalid token", peer))
		_ = fw.WriteJSON(protocol.KindExit, protocol.Exit{
			Code:    protocol.ExitProtocol,
			Message: "invalid token",
		})
		return
	}
	if err := s.checkAllowed(start.Args); err != nil {
		s.log.Warn(fmt.Sprintf("rejected %s: %v", peer, err))
		_ = fw.WriteJSON(protocol.KindExit, protocol.Exit{
			Code:    protocol.ExitNoExec,
			Message: err.Error(),
		})
		return
	}
	_ = conn.SetDeadline(time.Time{})

	if err := fw.WriteFrame(protocol.KindReady, nil); err != nil {
		s.log.Warn(fmt.Sprintf("%s went away before its command started: %v", peer, err))
		return
	}

	s.log.Info(fmt.Sprintf("%s runs %s", peer, describeCommand(start)))
	result := s.runSession(ctx, start, protocol.NewReader(conn), fw)
	s.log.Info(fmt.Sprintf("%s %s", peer, describeResult(result)))

	if err := fw.WriteJSON(protocol.KindExit, result); err != nil {
		s.log.Debug(fmt.Sprintf("could not report the exit code to %s: %v", peer, err))
	}
}

// describeCommand renders a session's command the way it was asked for, so a
// log line can be read back as the sbx invocation it ran.
func describeCommand(start protocol.Start) string {
	rendered := "sbx"
	if len(start.Args) > 0 {
		rendered += " " + strings.Join(start.Args, " ")
	}
	if start.TTY {
		rendered += " on a terminal"
	}
	return rendered
}

func describeResult(result protocol.Exit) string {
	switch {
	case result.Message != "":
		return fmt.Sprintf("failed: %s", result.Message)
	case result.Code == 0:
		return "succeeded"
	default:
		return fmt.Sprintf("exited with code %d", result.Code)
	}
}

// readStart consumes the handshake and the opening Start frame. The reader is
// intentionally local: the buffered frame reader used for the rest of the
// session is created only after the client authenticates.
func readStart(conn net.Conn) (protocol.Start, error) {
	if err := protocol.ReadHandshake(conn); err != nil {
		return protocol.Start{}, err
	}
	frame, err := protocol.NewReader(conn).ReadFrame()
	if err != nil {
		return protocol.Start{}, fmt.Errorf("read start frame: %w", err)
	}
	if frame.Kind != protocol.KindStart {
		return protocol.Start{}, fmt.Errorf("expected start frame, got %s", frame.Kind)
	}
	var start protocol.Start
	if err := protocol.DecodeJSON(frame, &start); err != nil {
		return protocol.Start{}, err
	}
	return start, nil
}

func (s *Server) checkAllowed(args []string) error {
	if len(s.allow) == 0 {
		return nil
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if _, ok := s.allow[arg]; ok {
			return nil
		}
		return fmt.Errorf("subcommand %q is not allowed by this server", arg)
	}
	return errors.New("no subcommand found in arguments")
}

func (s *Server) runSession(ctx context.Context, start protocol.Start, fr *protocol.Reader, fw *protocol.Writer) protocol.Exit {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.cfg.SbxPath, start.Args...)
	cmd.Env = s.childEnv(start)
	cmd.Dir = s.cfg.Workdir
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return killProcessTree(cmd.Process.Pid)
	}

	if start.TTY {
		return s.runTTY(cancel, cmd, start, fr, fw)
	}
	return s.runPipes(cancel, cmd, fr, fw)
}

func (s *Server) childEnv(start protocol.Start) []string {
	env := os.Environ()
	for name, value := range start.Env {
		env = append(env, name+"="+value)
	}
	if start.TTY {
		term := start.Term
		if term == "" {
			term = "xterm-256color"
		}
		env = append(env, "TERM="+term)
	}
	return env
}

func (s *Server) runTTY(cancel context.CancelFunc, cmd *exec.Cmd, start protocol.Start, fr *protocol.Reader, fw *protocol.Writer) protocol.Exit {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return execFailure(err)
	}
	defer ptmx.Close()

	// A PTY defaults to 0x0, which breaks full-screen programs, so fall back to
	// a conventional size when the client cannot report its own.
	rows, cols := start.Rows, start.Cols
	if rows == 0 || cols == 0 {
		rows, cols = defaultRows, defaultCols
	}
	_ = pty.Setsize(ptmx, &pty.Winsize{Rows: rows, Cols: cols})

	sess := &session{log: s.log, fr: fr, stdin: ptmx, ptmx: ptmx, cmd: cmd, cancel: cancel}
	go sess.pump()

	// A PTY read fails with EIO once the child closes the slave side, which is
	// the normal end of a TTY session rather than an error worth reporting.
	_, _ = io.Copy(fw.Stream(protocol.KindStdout), ptmx)

	return waitResult(cmd)
}

func (s *Server) runPipes(cancel context.CancelFunc, cmd *exec.Cmd, fr *protocol.Reader, fw *protocol.Writer) protocol.Exit {
	newProcessGroup(cmd)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return execFailure(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return execFailure(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return execFailure(err)
	}
	if err := cmd.Start(); err != nil {
		return execFailure(err)
	}

	sess := &session{log: s.log, fr: fr, stdin: stdin, cmd: cmd, cancel: cancel}
	go sess.pump()

	// Both pipes must drain before Wait, which closes them.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(fw.Stream(protocol.KindStdout), stdout)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(fw.Stream(protocol.KindStderr), stderr)
	}()
	wg.Wait()

	return waitResult(cmd)
}

// session forwards client frames into a running child process.
type session struct {
	log    *slog.Logger
	fr     *protocol.Reader
	stdin  io.WriteCloser
	ptmx   *os.File
	cmd    *exec.Cmd
	cancel context.CancelFunc
}

// pump dispatches inbound frames until the client stops sending. Any read
// failure means the client is gone, so the child is cancelled rather than left
// running without anyone to read its output.
func (sess *session) pump() {
	defer sess.cancel()

	for {
		frame, err := sess.fr.ReadFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				sess.log.Debug(fmt.Sprintf("client stream ended: %v", err))
			}
			return
		}

		switch frame.Kind {
		case protocol.KindStdin:
			if _, err := sess.stdin.Write(frame.Payload); err != nil {
				sess.log.Debug(fmt.Sprintf("could not write to the child's stdin: %v", err))
				return
			}
		case protocol.KindStdinClose:
			// A TTY session's stdin is a terminal that stays open for the
			// child's lifetime; closing the PTY master here would tear the
			// session down, and injecting EOT would echo a stray ^D.
			if sess.ptmx != nil {
				continue
			}
			_ = sess.stdin.Close()
		case protocol.KindResize:
			var resize protocol.Resize
			if err := protocol.DecodeJSON(frame, &resize); err != nil {
				sess.log.Debug(fmt.Sprintf("ignoring a malformed resize frame: %v", err))
				continue
			}
			if sess.ptmx != nil && resize.Rows > 0 && resize.Cols > 0 {
				_ = pty.Setsize(sess.ptmx, &pty.Winsize{Rows: resize.Rows, Cols: resize.Cols})
			}
		case protocol.KindSignal:
			var sig protocol.Signal
			if err := protocol.DecodeJSON(frame, &sig); err != nil {
				sess.log.Debug(fmt.Sprintf("ignoring a malformed signal frame: %v", err))
				continue
			}
			sess.deliver(sig.Name)
		default:
			sess.log.Debug(fmt.Sprintf("ignoring an unexpected %s frame", frame.Kind))
		}
	}
}

func (sess *session) deliver(name string) {
	if sess.cmd.Process == nil {
		return
	}
	sig, ok := signalsByName[strings.ToUpper(strings.TrimPrefix(name, "SIG"))]
	if !ok {
		sess.log.Debug(fmt.Sprintf("ignoring unknown signal %s", name))
		return
	}
	if err := sess.cmd.Process.Signal(sig); err != nil {
		sess.log.Debug(fmt.Sprintf("could not deliver %s: %v", name, err))
	}
}

var signalsByName = map[string]os.Signal{
	"INT":  syscall.SIGINT,
	"TERM": syscall.SIGTERM,
	"HUP":  syscall.SIGHUP,
	"QUIT": syscall.SIGQUIT,
	"KILL": syscall.SIGKILL,
}

func waitResult(cmd *exec.Cmd) protocol.Exit {
	err := cmd.Wait()
	if err == nil {
		return protocol.Exit{Code: 0}
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return protocol.Exit{Code: exitErr.ExitCode()}
	}
	return protocol.Exit{Code: protocol.ExitNoExec, Message: err.Error()}
}

func execFailure(err error) protocol.Exit {
	code := protocol.ExitNoExec
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
		code = protocol.ExitNotFound
	}
	return protocol.Exit{Code: code, Message: fmt.Sprintf("run sbx: %v", err)}
}
