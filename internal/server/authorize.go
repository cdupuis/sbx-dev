package server

import (
	"errors"
	"fmt"

	"github.com/cdupuis/sbx-dev/internal/authtoken"
	"github.com/cdupuis/sbx-dev/internal/authz"
	"github.com/cdupuis/sbx-dev/internal/identity"
	"github.com/cdupuis/sbx-dev/internal/resolve"
)

// caller is who a connection turned out to belong to.
type caller struct {
	peer string
	// sandbox is set when the caller presented an identity token.
	sandbox identity.Identity
	// operator is set when the caller presented the server's shared token, which
	// names no sandbox.
	operator bool
}

func (c caller) String() string {
	if c.operator {
		return fmt.Sprintf("the operator at %s", c.peer)
	}
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

// authenticate resolves a presented token into a caller.
//
// An identity token is tried first so that a sandbox is always recognised as
// itself. The shared token names no sandbox and is how a host-side operator
// connects; it is refused outright once a policy is configured, because no rule
// could describe its holder and accepting it would leave a way past every rule.
func (s *Server) authenticate(peer, token string) (caller, error) {
	if len(s.cfg.IdentityKey) > 0 {
		id, err := s.cfg.IdentityKey.Verify(token)
		switch {
		case err == nil:
			if s.cfg.Generations != nil && !s.cfg.Generations.Accepts(id) {
				return caller{}, fmt.Errorf("the token for %s has been replaced", id.Sandbox)
			}
			return caller{peer: peer, sandbox: id}, nil
		case errors.Is(err, identity.ErrUnauthenticated):
			// A token that names a sandbox but carries the wrong signature is a
			// forgery attempt, not a shared token, so it never falls through.
			return caller{}, errors.New("invalid token")
		}
	}

	if !authtoken.Equal(token, s.cfg.Token) {
		return caller{}, errors.New("invalid token")
	}
	if s.cfg.Authorizer != nil {
		return caller{}, errors.New("this server requires a sandbox identity token; run \"sbx-dev grant\" for the sandbox")
	}
	return caller{peer: peer, operator: true}, nil
}

// authorize resolves the argv and asks the policy about it. A server with no
// policy authorizes nothing here, leaving the subcommand allowlist as the only
// restriction.
func (s *Server) authorize(c caller, args []string) error {
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

	if !decision.Allowed {
		return errors.New(decision.Reason(inv.Name()))
	}
	return nil
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
