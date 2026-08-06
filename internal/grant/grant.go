// Package grant issues a sandbox the identity token an sbx-warden server
// recognises it by.
//
// The token names its sandbox and is signed, so a sandbox cannot claim another's
// identity. Registering it as a sandbox-scoped secret keeps it out of the
// sandbox entirely: the sandbox holds a placeholder, and the egress proxy
// substitutes the real token into the header the session handshake carries it in.
// Printing the token instead leaves the sandbox holding it, which is still enough
// for identity but no longer a secret.
package grant

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/cdupuis/sbx-warden/internal/identity"
)

// EnvName is the variable sbx sets inside the sandbox to the token's
// placeholder, and the one the client reads when it authenticates.
const EnvName = "SBX_WARDEN_TOKEN"

// Config describes one grant.
type Config struct {
	// Sandbox is the sandbox to issue a token to.
	Sandbox string
	// SbxPath is the sbx binary used to register the secret.
	SbxPath string
	// Key signs the token.
	Key identity.Key
	// Registry tracks generations so a reissued token retires the last one.
	Registry *identity.Registry
	// Host is the target the proxy substitutes the token for, when ViaProxy is
	// set.
	Host string
	// Generation overrides the generation to mint. Zero takes the next one.
	Generation int
	// ViaProxy registers the token as a sandbox-scoped custom secret instead of
	// printing it, so the sandbox holds only a placeholder.
	ViaProxy bool
}

// Run mints the sandbox's token and delivers it.
func Run(ctx context.Context, out io.Writer, cfg Config) error {
	if cfg.Sandbox == "" {
		return errors.New("grant: sandbox name is required")
	}
	if cfg.Registry == nil {
		return errors.New("grant: registry is required")
	}
	if cfg.ViaProxy && cfg.SbxPath == "" {
		return errors.New("grant: sbx path is required to register a secret")
	}
	host := cfg.Host
	if host == "" {
		host = "localhost"
	}

	generation := cfg.Generation
	if generation == 0 {
		generation = cfg.Registry.Next(cfg.Sandbox)
	}

	token, err := cfg.Key.Mint(cfg.Sandbox, generation)
	if err != nil {
		return fmt.Errorf("grant: %w", err)
	}

	if cfg.ViaProxy {
		if err := registerSecret(ctx, cfg.SbxPath, cfg.Sandbox, host, token); err != nil {
			return err
		}
	}

	// Recorded only once delivery succeeded: a grant that failed must not
	// retire the generation the sandbox is still using.
	if err := cfg.Registry.Record(cfg.Sandbox, generation); err != nil {
		return fmt.Errorf("grant: record generation: %w", err)
	}

	report(out, cfg, host, token, generation)
	return nil
}

func report(out io.Writer, cfg Config, host, token string, generation int) {
	fmt.Fprintf(out, "Granted %s an sbx-warden identity (generation %d).\n", cfg.Sandbox, generation)
	if generation > 1 {
		fmt.Fprintln(out, "Its earlier tokens no longer authenticate.")
	}

	if cfg.ViaProxy {
		fmt.Fprintf(out, `
sbx now sets %s inside %s to a placeholder, and the egress proxy substitutes the
real token into the sandbox's handshake with %s, so the sandbox never sees it.

A sandbox reads the placeholder at creation, so grant before "sbx create" or
recreate the sandbox afterwards. Granting again later rotates the token under the
same placeholder and takes effect without recreating anything.
`, EnvName, cfg.Sandbox, host)
		return
	}

	fmt.Fprintf(out, `
Give the token to the sandbox at creation:

  sbx create <agent> <path> --name %s --env %s=%s

The sandbox can read its own token, which is enough for identity: the token
names %s and is signed, so it cannot be altered into another sandbox's. Drop
--print-token to register the token as a secret instead, and the sandbox holds
only a placeholder.
`, cfg.Sandbox, EnvName, token, cfg.Sandbox)
}

// placeholderFor derives the value the sandbox holds in place of its token.
//
// It is derived from the sandbox name rather than random so that regranting
// updates the secret in place: sbx refuses to change a custom secret's
// placeholder, and a sandbox reads the placeholder once at creation, so a fresh
// one would both be rejected here and leave a running sandbox holding a value
// that no longer resolves. The placeholder is a sentinel, not a secret — the
// proxy substitutes it only for the sandbox the secret is scoped to, so knowing
// another sandbox's placeholder gains nothing.
func placeholderFor(sandbox string) string { return "sbx-warden-" + sandbox }

// registerSecret hands the token to sbx on stdin rather than in argv, so it does
// not appear in the host's process list.
func registerSecret(ctx context.Context, sbxPath, sandbox, host, token string) error {
	// Attached --flag=value form throughout: a value that began with "-" would
	// otherwise be parsed as a flag of its own.
	cmd := exec.CommandContext(ctx, sbxPath,
		"secret", "set-custom",
		"--sandbox="+sandbox,
		"--host="+host,
		"--env="+EnvName,
		"--placeholder="+placeholderFor(sandbox),
	)
	cmd.Stdin = strings.NewReader(token + "\n")

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("grant: register the token with sbx: %w\n%s", err, strings.TrimSpace(output.String()))
	}
	return nil
}
