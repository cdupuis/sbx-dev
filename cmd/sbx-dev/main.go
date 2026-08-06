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
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cdupuis/sbx-dev/internal/authtoken"
	"github.com/cdupuis/sbx-dev/internal/authz"
	"github.com/cdupuis/sbx-dev/internal/catalog"
	"github.com/cdupuis/sbx-dev/internal/clog"
	"github.com/cdupuis/sbx-dev/internal/grant"
	"github.com/cdupuis/sbx-dev/internal/identity"
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
	run := run
	if len(os.Args) > 1 && os.Args[1] == "grant" {
		run = func() error { return runGrant(os.Args[2:]) }
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sbx-dev: %v\n", err)
		os.Exit(1)
	}
}

func runGrant(args []string) error {
	defaultKeyPath, keyPathErr := identity.DefaultKeyPath()
	defaultRegistryPath, registryPathErr := identity.DefaultRegistryPath()

	fs := flag.NewFlagSet("sbx-dev grant", flag.ContinueOnError)
	var (
		sbxPath      = fs.String("sbx", "sbx", "path to the real sbx binary")
		keyPath      = fs.String("key-file", defaultKeyPath, "file holding the identity key, created if absent")
		registryPath = fs.String("registry-file", defaultRegistryPath, "file recording which token generations are current")
		host         = fs.String("host", "localhost", "secret target the proxy substitutes the token for")
		generation   = fs.Int("generation", 0, "generation to mint (default: the next one, retiring the current token)")
		printToken   = fs.Bool("print-token", false, "print the token for \"sbx create --env\" instead of registering it as a sandbox-scoped secret, which leaves the sandbox holding the token itself")
	)
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "Usage: sbx-dev grant [flags] SANDBOX\n\nIssues a sandbox the signed identity token an sbx-dev server recognises it by,\nso a policy can say what that sandbox in particular may do.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("grant takes exactly one sandbox name")
	}
	if keyPathErr != nil && *keyPath == "" {
		return keyPathErr
	}
	if registryPathErr != nil && *registryPath == "" {
		return registryPathErr
	}

	key, err := identity.LoadOrCreateKey(*keyPath)
	if err != nil {
		return err
	}
	registry, err := identity.OpenRegistry(*registryPath)
	if err != nil {
		return err
	}

	viaProxy := !*printToken
	var resolvedSbx string
	if viaProxy {
		resolvedSbx, err = exec.LookPath(*sbxPath)
		if err != nil {
			return fmt.Errorf("locate sbx binary %q: %w", *sbxPath, err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return grant.Run(ctx, os.Stdout, grant.Config{
		Sandbox:    fs.Arg(0),
		SbxPath:    resolvedSbx,
		Key:        key,
		Registry:   registry,
		Host:       *host,
		Generation: *generation,
		ViaProxy:   viaProxy,
	})
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
		policyMap = flag.String("policy-map", "", "policy map binding Cedar policy files to sandbox names and patterns; enabling it requires every session to present an identity token")
		keyPath   = flag.String("key-file", "", "file holding the identity key that verifies session tokens (default: the same file sbx-dev grant uses)")
		allow     stringList
		allowEnv  stringList
	)
	flag.Var(&allow, "allow-command", "restrict to these sbx subcommands (repeatable, comma-separated); default allows all")
	flag.Var(&allowEnv, "allow-env", "let sessions set these environment variables on the sbx process (repeatable, comma-separated); default accepts none")

	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintf(out, "Usage: sbx-dev [flags]\n       sbx-dev grant [flags] SANDBOX\n\nServes the host's sbx CLI over TCP for sbx clients in sandboxes.\n\nThe grant subcommand issues a sandbox an identity token; run \"sbx-dev grant -h\"\nfor its flags.\n\nFlags:\n")
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

	cfg := server.Config{
		Addr:          *addr,
		SbxPath:       *sbxPath,
		Token:         token,
		Workdir:       *workdir,
		AllowCommands: allow,
		AllowEnv:      allowEnv,
		Logger:        log,
	}
	if *policyMap != "" {
		if err := configurePolicy(&cfg, *policyMap, *keyPath); err != nil {
			return err
		}
	}

	srv, err := server.New(cfg)
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
	if len(allowEnv) > 0 {
		log.Info(fmt.Sprintf("sessions may set these variables: %s", strings.Join(allowEnv, ", ")))
	}
	if cfg.Authorizer != nil {
		log.Info(fmt.Sprintf("authorizing every command against %s", *policyMap))
		log.Info(fmt.Sprintf("resolving commands against the catalog for sbx %s", cfg.Catalog.SbxVersion))
	}
	fmt.Fprint(os.Stderr, connectHint(port, *tokenPath, token))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return srv.Serve(ctx)
}

// configurePolicy loads everything a policy decision needs. It resolves the
// catalog here rather than leaving it to the server, so that the version it
// describes can be reported at startup.
func configurePolicy(cfg *server.Config, mapPath, keyPath string) error {
	authorizer, err := authz.NewFromPolicyMap(mapPath)
	if err != nil {
		return err
	}

	if keyPath == "" {
		if keyPath, err = identity.DefaultKeyPath(); err != nil {
			return err
		}
	}
	key, err := identity.LoadOrCreateKey(keyPath)
	if err != nil {
		return err
	}

	registryPath, err := identity.DefaultRegistryPath()
	if err != nil {
		return err
	}
	registry, err := identity.OpenRegistry(registryPath)
	if err != nil {
		return err
	}

	cat, err := catalog.Embedded()
	if err != nil {
		return err
	}

	cfg.Authorizer = authorizer
	cfg.IdentityKey = key
	cfg.Generations = registry
	cfg.Catalog = cat
	return nil
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
