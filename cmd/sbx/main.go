// Command sbx forwards its arguments to an sbx-dev server, which runs them
// against the host's real sbx CLI.
//
// Every argument is passed through untouched so that all sbx commands and flags
// work; this binary is configured entirely through the environment:
//
//	SBX_DEV_ADDR         server address (default host.docker.internal:7391)
//	SBX_DEV_TOKEN        shared token, otherwise read from SBX_DEV_TOKEN_FILE
//	SBX_DEV_TOKEN_FILE   token file (default ~/.sbx-dev/token)
//	SBX_DEV_FORWARD_ENV  comma-separated env var names to send to the server
//	SBX_DEV_NO_TTY       set to disable remote PTY allocation
//	SBX_DEV_PRINT_VERSION  print this client's version and exit
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cdupuis/sbx-dev/internal/authtoken"
	"github.com/cdupuis/sbx-dev/internal/client"
	"github.com/cdupuis/sbx-dev/internal/protocol"
)

const defaultAddr = "host.docker.internal:7391"

// version is overwritten at link time by the release build.
var version = "dev"

func main() {
	// Arguments belong to the remote CLI, so this binary's own version is
	// reported through the environment. Installers also use the "sbx-dev
	// client" prefix to recognise their own binary before replacing an sbx on
	// PATH.
	if os.Getenv("SBX_DEV_PRINT_VERSION") != "" {
		fmt.Printf("sbx-dev client %s\n", version)
		return
	}

	addr := envOr("SBX_DEV_ADDR", defaultAddr)

	token, err := resolveToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbx: %v\n", err)
		os.Exit(protocol.ExitProtocol)
	}

	ttyFd := int(os.Stdin.Fd())
	if os.Getenv("SBX_DEV_NO_TTY") != "" {
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

func resolveToken() (string, error) {
	if token := os.Getenv("SBX_DEV_TOKEN"); token != "" {
		return token, nil
	}
	path, err := authtoken.DefaultPath()
	if err != nil {
		return "", errors.New("no token available: set SBX_DEV_TOKEN")
	}
	token, err := authtoken.Load(path)
	if err != nil {
		return "", fmt.Errorf("no token available: set SBX_DEV_TOKEN or create %s", path)
	}
	return token, nil
}

func forwardedEnv() map[string]string {
	names := os.Getenv("SBX_DEV_FORWARD_ENV")
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
No sbx-dev server answered at %s.

The two usual causes look identical from here, because a sandbox's egress proxy
accepts the connection before it dials the host:

  1. the server is not running on the host
         sbx-dev --addr 127.0.0.1:%s
  2. the network policy does not allow the port
         sbx policy allow network localhost:%s

The rule must name localhost, not host.docker.internal: the proxy rewrites the
request host to localhost before evaluating policy, while rules match verbatim.
Run "sbx policy log" on the host to see whether the connection was blocked.
`, addr, port, port)
}
