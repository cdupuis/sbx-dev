package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/term"
)

// defaultApprovalTimeout bounds the wait for an answer. A caller is blocked for
// the whole of it, so an unattended prompt has to end in a refusal rather than
// hold a sandbox open indefinitely.
const defaultApprovalTimeout = 2 * time.Minute

// promptValueLimit bounds each line of a prompt, since the values in one come
// from the caller.
const promptValueLimit = 200

// ErrNoTerminal reports that there is nobody to ask: the server's input is not a
// terminal, so a withheld command cannot be put to anyone.
var ErrNoTerminal = errors.New("this server has no terminal to ask for approval on")

// Approval is a command a policy withheld until an operator confirms it.
type Approval struct {
	// Sandbox is the calling sandbox, as its identity token named it.
	Sandbox string
	// Command is the resolved command, such as "sbx policy allow network".
	Command string
	// Details are the specifics worth seeing before answering: what the command
	// acts on, and what it carries.
	Details []string
}

// Approver decides a withheld command by asking a person.
type Approver interface {
	// Approve blocks until the request is answered. False denies it, and so does
	// an error: a question nobody could be asked has not been answered yes.
	Approve(ctx context.Context, req Approval) (bool, error)
}

// terminalApprover asks on the terminal the server was started from.
type terminalApprover struct {
	in      *os.File
	out     io.Writer
	timeout time.Duration

	// mu serializes prompts. There is one terminal, so two questions asked at
	// once would interleave and one answer could settle the other question.
	mu sync.Mutex

	started sync.Once
	lines   chan string
}

// NewTerminalApprover reads answers from in and prompts on out. A zero timeout
// takes the default.
func NewTerminalApprover(in *os.File, out io.Writer, timeout time.Duration) Approver {
	if timeout <= 0 {
		timeout = defaultApprovalTimeout
	}
	return &terminalApprover{in: in, out: out, timeout: timeout, lines: make(chan string, 1)}
}

// readLines feeds typed lines to whichever prompt is waiting.
//
// One goroutine owns the descriptor for the server's lifetime because a reader
// started per prompt would still be blocked in Read after that prompt timed out,
// and would then consume the answer meant for the next one.
func (a *terminalApprover) readLines() {
	go func() {
		defer close(a.lines)
		scanner := bufio.NewScanner(a.in)
		for scanner.Scan() {
			a.lines <- scanner.Text()
		}
	}()
}

func (a *terminalApprover) Approve(ctx context.Context, req Approval) (bool, error) {
	if !term.IsTerminal(int(a.in.Fd())) {
		return false, ErrNoTerminal
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.started.Do(a.readLines)

	if err := a.discardTyped(); err != nil {
		return false, err
	}
	if _, err := fmt.Fprint(a.out, prompt(req)); err != nil {
		return false, fmt.Errorf("ask for approval: %w", err)
	}

	timer := time.NewTimer(a.timeout)
	defer timer.Stop()

	select {
	case line, ok := <-a.lines:
		if !ok {
			return false, ErrNoTerminal
		}
		return isYes(line), nil
	case <-timer.C:
		fmt.Fprintf(a.out, "  unanswered after %s, refused\n", a.timeout)
		return false, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// discardTyped drops lines already read but not yet claimed, so an answer to an
// earlier prompt, or an idle keystroke between two, cannot settle this one. It
// cannot reach what the terminal itself is still holding: input racing the
// prompt is indistinguishable from an answer to it.
func (a *terminalApprover) discardTyped() error {
	for {
		select {
		case _, ok := <-a.lines:
			if !ok {
				return ErrNoTerminal
			}
		default:
			return nil
		}
	}
}

// isYes reads an answer. Only an explicit yes allows, so a stray newline refuses.
func isYes(line string) bool {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

func prompt(req Approval) string {
	var b strings.Builder
	b.WriteString("\n")
	fmt.Fprintf(&b, "%s asks to run %s\n", display(req.Sandbox), display(req.Command))
	for _, detail := range req.Details {
		fmt.Fprintf(&b, "  %s\n", display(detail))
	}
	b.WriteString("allow it? [y/N] ")
	return b.String()
}

// display makes a value safe to print on a terminal.
//
// Most of what a prompt shows was chosen by the sandbox asking, and an approval
// prompt is precisely what an escape sequence would want to forge: a cleared
// line and a friendlier question for the operator to agree to. Dropping
// unprintable runes leaves the text readable and inert.
func display(value string) string {
	kept := make([]rune, 0, len(value))
	for _, r := range value {
		if unicode.IsPrint(r) {
			kept = append(kept, r)
		}
	}
	if len(kept) == 0 {
		return "(unprintable)"
	}
	if len(kept) > promptValueLimit {
		return string(kept[:promptValueLimit]) + "…"
	}
	return string(kept)
}
