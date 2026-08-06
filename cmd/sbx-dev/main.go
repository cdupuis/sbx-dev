// Command sbx-dev serves the host's sbx CLI over TCP to sbx clients running
// inside sandboxes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cdupuis/sbx-dev/internal/authtoken"
	"github.com/cdupuis/sbx-dev/internal/clog"
	"github.com/cdupuis/sbx-dev/internal/server"
)

// DefaultPort is the port both binaries assume when none is configured.
const DefaultPort = "7391"

// version is overwritten at link time by the release build.
var version = "dev"

type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sbx-dev: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	defaultTokenPath, tokenPathErr := authtoken.DefaultPath()

	var (
		addr      = flag.String("addr", "127.0.0.1:"+DefaultPort, "TCP address to listen on")
		sbxPath   = flag.String("sbx", "sbx", "path to the real sbx binary")
		tokenPath = flag.String("token-file", defaultTokenPath, "file holding the shared token, created if absent")
		workdir   = flag.String("workdir", "", "working directory for remote commands (default: current directory)")
		verbose   = flag.Bool("verbose", false, "log at debug level")
		allowAny  = flag.Bool("allow-any-bind", false, "permit binding a non-loopback address")
		showVer   = flag.Bool("version", false, "print the version and exit")
		allow     stringList
	)
	flag.Var(&allow, "allow-command", "restrict to these sbx subcommands (repeatable, comma-separated); default allows all")

	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintf(out, "Usage: sbx-dev [flags]\n\nServes the host's sbx CLI over TCP for sbx clients in sandboxes.\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVer {
		fmt.Printf("sbx-dev server %s\n", version)
		return nil
	}
	if flag.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flag.Arg(0))
	}
	if tokenPathErr != nil && *tokenPath == "" {
		return tokenPathErr
	}
	if err := checkBind(*addr, *allowAny); err != nil {
		return err
	}

	token, err := authtoken.LoadOrCreate(*tokenPath)
	if err != nil {
		return err
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(clog.New(os.Stderr, level))

	srv, err := server.New(server.Config{
		Addr:          *addr,
		SbxPath:       *sbxPath,
		Token:         token,
		Workdir:       *workdir,
		AllowCommands: allow,
		Logger:        log,
	})
	if err != nil {
		return err
	}
	if err := srv.Listen(); err != nil {
		return err
	}

	_, port, err := net.SplitHostPort(srv.Addr().String())
	if err != nil {
		port = DefaultPort
	}

	log.Info(fmt.Sprintf("listening on %s", srv.Addr()))
	log.Info(fmt.Sprintf("running %s in %s", srv.SbxPath(), srv.Workdir()))
	if len(allow) > 0 {
		log.Info(fmt.Sprintf("restricted to these subcommands: %s", strings.Join(allow, ", ")))
	}
	fmt.Fprint(os.Stderr, connectHint(port, *tokenPath, token))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return srv.Serve(ctx)
}

func checkBind(addr string, allowAny bool) error {
	if allowAny {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse --addr %q: %w", addr, err)
	}
	if host == "" {
		return errors.New("--addr must include an explicit host; use 127.0.0.1 to stay on loopback")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if host == "localhost" {
			return nil
		}
		return fmt.Errorf("--addr host %q is not a loopback address; pass --allow-any-bind to override", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("--addr %s binds beyond loopback, exposing the sbx CLI to the network; pass --allow-any-bind to override", host)
	}
	return nil
}

func connectHint(port, tokenPath, token string) string {
	var b strings.Builder
	b.WriteString("\nTo use the sbx client from inside a sandbox:\n\n")
	fmt.Fprintf(&b, "  sbx policy allow network localhost:%s\n", port)
	fmt.Fprintf(&b, "  export SBX_DEV_ADDR=host.docker.internal:%s\n", port)
	fmt.Fprintf(&b, "  export SBX_DEV_TOKEN=%s\n\n", token)
	fmt.Fprintf(&b, "Token file: %s\n\n", tokenPath)
	return b.String()
}
