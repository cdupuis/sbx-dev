package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cdupuis/sbx-warden/internal/authz"
	"github.com/cdupuis/sbx-warden/internal/identity"
	"github.com/cdupuis/sbx-warden/internal/resolve"
)

// caller is the sandbox a connection turned out to belong to.
type caller struct {
	peer    string
	sandbox identity.Identity
}

func (c caller) String() string {
	return fmt.Sprintf("sandbox %s at %s", c.sandbox.Sandbox, c.peer)
}

// authenticateSession resolves the credential opening a framed session, which is
// only ever a ticket. The handshake that issued it already authenticated the
// caller, and redeeming it here consumes it.
//
// Refusing a token here is what keeps the two connections to their own jobs: a
// token is presented to the handshake, where a sandbox's egress proxy can
// substitute it into a header, and a session carries only the short-lived ticket
// that came back.
func (s *Server) authenticateSession(peer, token string) (caller, error) {
	if !isTicket(token) {
		return caller{}, errors.New("a session opens with a ticket from the handshake, not a token")
	}
	c, ok := s.tickets.redeem(token)
	if !ok {
		return caller{}, errors.New("this session ticket has expired or was already used")
	}
	c.peer = peer
	return c, nil
}

// authenticate resolves a presented token into the sandbox it names.
//
// An identity token is the only credential the server accepts, so every session
// belongs to a sandbox an operator granted by name and can be revoked on its
// own. Nothing distinguishes a malformed token from a forged one here: both are
// refused the same way, because telling them apart only helps the forger.
func (s *Server) authenticate(peer, token string) (caller, error) {
	id, err := s.cfg.IdentityKey.Verify(token)
	if err != nil {
		return caller{}, errors.New("invalid token")
	}
	if s.cfg.Generations != nil && !s.cfg.Generations.Accepts(id) {
		return caller{}, fmt.Errorf("the token for %s has been replaced", id.Sandbox)
	}
	return caller{peer: peer, sandbox: id}, nil
}

// authorize resolves the argv and asks the policy about it. A server with no
// policy authorizes nothing here, leaving the subcommand allowlist as the only
// restriction.
//
// It blocks while a withheld command is put to an operator, so notify carries a
// line back to the caller: from inside a sandbox an unannounced wait on a person
// is indistinguishable from a hung server.
func (s *Server) authorize(ctx context.Context, c caller, args []string, notify io.Writer) error {
	if s.cfg.Authorizer == nil {
		return nil
	}

	inv, err := resolve.Argv(s.cfg.Catalog, args)
	if err != nil {
		// A command line the server cannot resolve exactly is a command line it
		// cannot describe to a policy, so it does not run.
		return err
	}

	decision := s.cfg.Authorizer.Authorize(authz.Request{
		Caller:     c.sandbox,
		Invocation: inv,
		Workdir:    s.cfg.Workdir,
	})
	s.logDecision(c, inv, decision)

	if decision.NeedsApproval {
		return s.seekApproval(ctx, c, inv, notify)
	}
	if !decision.Allowed {
		return errors.New(decision.Reason(inv.Name()))
	}
	return nil
}

// seekApproval puts a withheld command to an operator and reports what they said.
// Every outcome other than a yes denies, including having nobody to ask.
func (s *Server) seekApproval(ctx context.Context, c caller, inv *resolve.Invocation, notify io.Writer) error {
	s.log.Info(fmt.Sprintf("%s asks to run %s", c, inv.Name()))
	if notify != nil {
		fmt.Fprintf(notify, "sbx: %s is waiting for an operator to approve it\n", inv.Name())
	}

	approved, err := s.cfg.Approver.Approve(ctx, Approval{
		Sandbox: c.sandbox.Sandbox,
		Command: inv.Name(),
		Details: approvalDetails(inv),
	})
	switch {
	case errors.Is(err, ErrNoTerminal):
		s.log.Warn(fmt.Sprintf("could not ask anyone about %s for %s: %v", inv.Name(), c, err))
		return fmt.Errorf("%s needs an operator's approval, and %w", inv.Name(), err)
	case err != nil:
		s.log.Warn(fmt.Sprintf("approval for %s failed for %s: %v", inv.Name(), c, err))
		return fmt.Errorf("%s was not approved", inv.Name())
	case !approved:
		s.log.Info(fmt.Sprintf("refused %s for %s", inv.Name(), c))
		return fmt.Errorf("an operator refused %s", inv.Name())
	}

	s.log.Info(fmt.Sprintf("approved %s for %s", inv.Name(), c))
	return nil
}

// approvalDetails describes what an operator is being asked to allow. The values
// come from the caller and are sanitized where the prompt is rendered.
func approvalDetails(inv *resolve.Invocation) []string {
	var details []string
	for _, slot := range inv.Slots {
		details = append(details, slot.Name+": "+slot.Value)
	}
	if flags := inv.FlagNames(); len(flags) > 0 {
		details = append(details, "flags: --"+strings.Join(flags, " --"))
	}
	if len(inv.PassThrough) > 0 {
		details = append(details, "runs: "+strings.Join(inv.PassThrough, " "))
	}
	return details
}

func (s *Server) logDecision(c caller, inv *resolve.Invocation, decision authz.Decision) {
	for _, err := range decision.Errors {
		s.log.Error(fmt.Sprintf("policy failed to evaluate %s for %s: %s", inv.Name(), c, err))
	}
	if len(decision.Policies) == 0 {
		return
	}
	s.log.Debug(fmt.Sprintf("%s for %s matched %v", inv.Name(), c, decision.Policies))
}
