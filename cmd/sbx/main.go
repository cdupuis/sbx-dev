// Command sbx forwards its arguments to an sbx-warden server, which runs them
// against the host's real sbx CLI.
//
// Every argument is passed through untouched so that all sbx commands and flags
// work; this binary is configured entirely through the environment:
//
//	SBX_WARDEN_ADDR         server address (default host.docker.internal:7391)
//	SBX_WARDEN_TOKEN        identity token naming this sandbox, from "sbx-warden grant"
//	SBX_WARDEN_FORWARD_ENV  comma-separated env var names to send to the server
//	SBX_WARDEN_NO_TTY       set to disable remote PTY allocation
//	SBX_WARDEN_PRINT_VERSION  print this client's version and exit
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cdupuis/sbx-warden/internal/client"
	"github.com/cdupuis/sbx-warden/internal/protocol"
)

const defaultAddr = "host.docker.internal:7391"

// version is overwritten at link time by the release build.
var version = "dev"

func main() {
	// Arguments belong to the remote CLI, so this binary's own version is
	// reported through the environment. Installers also use the "sbx-warden
	// client" prefix to recognise their own binary before replacing an sbx on
	// PATH.
	if os.Getenv("SBX_WARDEN_PRINT_VERSION") != "" {
		fmt.Printf("sbx-warden client %s\n", version)
		return
	}

	addr := envOr("SBX_WARDEN_ADDR", defaultAddr)

	token := os.Getenv("SBX_WARDEN_TOKEN")
	if token == "" {
		fmt.Fprint(os.Stderr, ungrantedHint())
		os.Exit(protocol.ExitProtocol)
	}

	ttyFd := int(os.Stdin.Fd())
	if os.Getenv("SBX_WARDEN_NO_TTY") != "" {
		ttyFd = client.NoTTY
	}

	code, err := client.Run(context.Background(), client.Config{
		Addr:   addr,
		Token:  token,
		Args:   os.Args[1:],
		Env:    forwardedEnv(),
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		TTYFd:  ttyFd,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbx: %v\n", err)
		if errors.Is(err, client.ErrUnreachable) {
			fmt.Fprint(os.Stderr, unreachableHint(addr))
		}
	}
	os.Exit(code)
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// ungrantedHint explains an empty SBX_WARDEN_TOKEN. The variable is set when the
// sandbox is created, so a sandbox that was never granted cannot fix this from
// the inside, and the instructions are for whoever is on the host.
func ungrantedHint() string {
	return `sbx: this sandbox has no sbx-warden token, so it cannot be identified to the server.

On the host, grant it and recreate it:

  sbx-warden grant SANDBOX

A sandbox's environment is fixed when it is created, so a sandbox that was
already running when it was granted has to be recreated to pick up the token.
`
}

func forwardedEnv() map[string]string {
	names := os.Getenv("SBX_WARDEN_FORWARD_ENV")
	if names == "" {
		return nil
	}
	env := make(map[string]string)
	for _, name := range strings.Split(names, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if value, ok := os.LookupEnv(name); ok {
			env[name] = value
		}
	}
	if len(env) == 0 {
		return nil
	}
	return env
}

func unreachableHint(addr string) string {
	port := "7391"
	if _, p, err := net.SplitHostPort(addr); err == nil && p != "" {
		port = p
	}
	return fmt.Sprintf(`
No sbx-warden server answered at %s.

The two usual causes look identical from here, because a sandbox's egress proxy
accepts the connection before it dials the host:

  1. the server is not running on the host
         sbx-warden --addr 127.0.0.1:%s
  2. the network policy does not allow the port
         sbx policy allow network localhost:%s

The rule must name localhost, not host.docker.internal: the proxy rewrites the
request host to localhost before evaluating policy, while rules match verbatim.
Run "sbx policy log" on the host to see whether the connection was blocked.
`, addr, port, port)
}
