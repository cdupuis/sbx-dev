// Command sbx-warden serves the host's sbx CLI over TCP to sbx clients running
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
	"regexp"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/cdupuis/sbx-warden/internal/authz"
	"github.com/cdupuis/sbx-warden/internal/catalog"
	"github.com/cdupuis/sbx-warden/internal/clog"
	"github.com/cdupuis/sbx-warden/internal/grant"
	"github.com/cdupuis/sbx-warden/internal/identity"
	"github.com/cdupuis/sbx-warden/internal/server"
)

// DefaultPort is the port both binaries assume when none is configured.
const DefaultPort = "7391"

// shippedPolicyMap is where this repository keeps the policy map, both on disk
// and in the tree served from GitHub.
const shippedPolicyMap = "policies/policy-map.yaml"

// defaultPolicyMap is the policy map a server authorizes against when none is
// named: the one this repository ships, read from its main branch.
//
// A default that grants nothing beyond reading, and refuses the credential store
// and the daemon outright, is the right starting point for a service that hands a
// sandbox the host's control plane. It costs a network read at startup; pass a
// path to avoid that, or an empty value to run with no policy at all.
//
// The repository is derived from the module path rather than written out, so a
// fork defaults to the policies it ships rather than silently trusting the ones
// upstream might change. A module that is not a GitHub repository falls back to
// the path, which fails audibly when absent instead of starting unrestricted.
func defaultPolicyMap() string {
	if url, ok := gitHubRaw(modulePath(), "main", shippedPolicyMap); ok {
		return url
	}
	return shippedPolicyMap
}

// modulePath reports the module this binary was built from.
func modulePath() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.Main.Path
	}
	return ""
}

// majorVersionSuffix matches the "/v2" a module path carries from v2 onwards. It
// is part of the module path but not of the repository, so it is dropped when
// naming files in that repository.
var majorVersionSuffix = regexp.MustCompile(`^v[0-9]+$`)

// gitHubRaw returns the URL a file in a module's repository is served from,
// reporting false for a module GitHub does not host.
func gitHubRaw(module, ref, file string) (string, bool) {
	rest, ok := strings.CutPrefix(module, "github.com/")
	if !ok {
		return "", false
	}
	segments := strings.Split(rest, "/")
	if len(segments) > 2 && majorVersionSuffix.MatchString(segments[len(segments)-1]) {
		segments = segments[:len(segments)-1]
	}
	if len(segments) != 2 || segments[0] == "" || segments[1] == "" {
		return "", false
	}
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", segments[0], segments[1], ref, file), true
}

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
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "grant":
			run = func() error { return runGrant(os.Args[2:]) }
		case "revoke":
			run = func() error { return runRevoke(os.Args[2:]) }
		}
	}
	if err := run(); err != nil {
		// A subcommand parses with ContinueOnError so that a usage error stays in
		// its own flag set, which also surfaces an answered -h as a failure.
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "sbx-warden: %v\n", err)
		os.Exit(1)
	}
}

func runRevoke(args []string) error {
	defaultRegistryPath, registryPathErr := identity.DefaultRegistryPath()

	fs := flag.NewFlagSet("sbx-warden revoke", flag.ContinueOnError)
	registryPath := fs.String("registry-file", defaultRegistryPath, "file recording which token generations are current")
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "Usage: sbx-warden revoke [flags] SANDBOX\n\nRetires every token a sandbox holds, without issuing one to replace them, so the\nsandbox has no identity until it is granted a new one.\n\nA running server picks this up on its own: it takes effect on the sandbox's next\ncommand, and ends any session it already had open.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("revoke takes exactly one sandbox name")
	}
	if registryPathErr != nil && *registryPath == "" {
		return registryPathErr
	}

	registry, err := identity.OpenRegistry(*registryPath)
	if err != nil {
		return err
	}
	// Read for the report only. The revocation itself re-reads and is atomic, so
	// this racing another grant costs accurate wording, not a missed revocation.
	sandbox := fs.Arg(0)
	granted, err := registry.Minimum(sandbox)
	if err != nil {
		return fmt.Errorf("revoke %s: %w", sandbox, err)
	}
	if _, err := registry.Revoke(sandbox); err != nil {
		return fmt.Errorf("revoke %s: %w", sandbox, err)
	}

	if granted == 0 {
		fmt.Printf("%s held no sbx-warden token, so nothing was retired.\n", sandbox)
		fmt.Printf("\nCheck the name if you expected otherwise: a sandbox that was never granted\nlooks the same here as one that does not exist.\n")
		return nil
	}

	fmt.Printf("Revoked every sbx-warden token for %s.\n", sandbox)
	fmt.Printf(`
A running server needs no restart: it reads the registry for every command and
rechecks the sessions it is already running.

%s keeps whatever placeholder it was created with, which no longer resolves to a
usable token. Run "sbx-warden grant %s" to give it a working identity again.
`, sandbox, sandbox)
	return nil
}

func runGrant(args []string) error {
	defaultKeyPath, keyPathErr := identity.DefaultKeyPath()
	defaultRegistryPath, registryPathErr := identity.DefaultRegistryPath()

	fs := flag.NewFlagSet("sbx-warden grant", flag.ContinueOnError)
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
		fmt.Fprintf(out, "Usage: sbx-warden grant [flags] SANDBOX\n\nIssues a sandbox the signed identity token an sbx-warden server recognises it by,\nso a policy can say what that sandbox in particular may do.\n\nFlags:\n")
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
	defaultMap := defaultPolicyMap()

	var (
		addr      = flag.String("addr", "127.0.0.1:"+DefaultPort, "TCP address to listen on")
		sbxPath   = flag.String("sbx", "sbx", "path to the real sbx binary")
		workdir   = flag.String("workdir", "", "working directory for remote commands (default: current directory)")
		verbose   = flag.Bool("verbose", false, "log at debug level")
		allowAny  = flag.Bool("allow-any-bind", false, "permit binding a non-loopback address")
		showVer   = flag.Bool("version", false, "print the version and exit")
		policyMap = flag.String("policy-map", defaultMap, "path or URL of the policy map binding Cedar policies to sandbox names and patterns; empty runs with no policy, letting every granted sandbox run any allowed subcommand")
		keyPath   = flag.String("key-file", "", "file holding the identity key that verifies session tokens (default: the same file sbx-warden grant uses)")
		regPath   = flag.String("registry-file", "", "file recording which token generations are current, reread for every command so revoking takes effect without a restart (default: the same file sbx-warden grant and revoke use)")
		allow     stringList
		allowEnv  stringList
	)
	flag.Var(&allow, "allow-command", "restrict to these sbx subcommands (repeatable, comma-separated); default allows all")
	flag.Var(&allowEnv, "allow-env", "let sessions set these environment variables on the sbx process (repeatable, comma-separated); default accepts none")

	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintf(out, "Usage: sbx-warden [flags]\n       sbx-warden grant [flags] SANDBOX\n       sbx-warden revoke [flags] SANDBOX\n\nServes the host's sbx CLI over TCP for sbx clients in sandboxes.\n\nThe grant subcommand issues a sandbox an identity token and revoke retires the\nones it holds; run \"sbx-warden grant -h\" or \"sbx-warden revoke -h\" for their\nflags.\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVer {
		fmt.Printf("sbx-warden server %s\n", version)
		return nil
	}
	if flag.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flag.Arg(0))
	}
	if err := checkBind(*addr, *allowAny); err != nil {
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
		Workdir:       *workdir,
		AllowCommands: allow,
		AllowEnv:      allowEnv,
		Logger:        log,
	}
	if err := configureIdentity(&cfg, *keyPath, *regPath); err != nil {
		return err
	}
	if *policyMap != "" {
		if err := configurePolicy(&cfg, *policyMap); err != nil {
			if *policyMap == defaultMap {
				// The operator did not choose this map, so the error alone would
				// not explain why starting a server reached the network at all.
				return fmt.Errorf("%w\n\nThis is the default policy map, read from the repository sbx-warden was built\nfrom. Pass --policy-map with a path to use your own, or --policy-map=\"\" to\nrun with no policy", err)
			}
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
	fmt.Fprint(os.Stderr, connectHint(port, cfg.Authorizer != nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return srv.Serve(ctx)
}

// configureIdentity loads the key that verifies session tokens and the registry
// that retires reissued ones. Both are needed whether or not a policy is
// configured, because a session's credential is always an identity token.
//
// The key is created when absent so that starting the server and granting a
// sandbox work in either order, and both reach the same file.
func configureIdentity(cfg *server.Config, keyPath, registryPath string) error {
	var err error
	if keyPath == "" {
		if keyPath, err = identity.DefaultKeyPath(); err != nil {
			return err
		}
	}
	if cfg.IdentityKey, err = identity.LoadOrCreateKey(keyPath); err != nil {
		return err
	}

	if registryPath == "" {
		if registryPath, err = identity.DefaultRegistryPath(); err != nil {
			return err
		}
	}
	cfg.Generations, err = identity.OpenRegistry(registryPath)
	return err
}

// configurePolicy loads everything a policy decision needs. It resolves the
// catalog here rather than leaving it to the server, so that the version it
// describes can be reported at startup.
//
// A map that cannot be read fails startup. That matters most when the map is
// remote: a server that came up without the rules it was told to enforce would
// be granting more than its operator asked for.
func configurePolicy(cfg *server.Config, mapRef string) error {
	bindings, err := authz.LoadPolicyMap(mapRef)
	if err != nil {
		return err
	}
	if plaintext := authz.PlaintextRefs(mapRef, bindings); len(plaintext) > 0 {
		cfg.Logger.Warn("policy is read over plaintext http, so whoever can answer or intercept these requests decides what every sandbox may do",
			"documents", strings.Join(plaintext, " "))
	}

	authorizer, err := authz.New(bindings)
	if err != nil {
		return err
	}
	cat, err := catalog.Embedded()
	if err != nil {
		return err
	}

	cfg.Authorizer = authorizer
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

// connectHint tells an operator how to let one sandbox in. Granting comes first
// because a sandbox reads its token at creation, so the order the steps are
// printed in is the order they have to happen.
func connectHint(port string, restricted bool) string {
	var b strings.Builder
	b.WriteString("\nTo let a sandbox use the sbx client, on the host:\n\n")
	fmt.Fprintf(&b, "  sbx-warden grant SANDBOX\n")
	fmt.Fprintf(&b, "  sbx policy allow network localhost:%s --sandbox SANDBOX\n\n", port)
	b.WriteString("Then in the sandbox:\n\n")
	fmt.Fprintf(&b, "  export SBX_WARDEN_ADDR=host.docker.internal:%s\n\n", port)
	b.WriteString("Granting sets SBX_WARDEN_TOKEN inside the sandbox to a placeholder that the\n")
	b.WriteString("egress proxy substitutes, so the sandbox never holds the token itself.\n")
	if !restricted {
		b.WriteString("\nPolicy is switched off, so every granted sandbox may run any subcommand.\n")
		b.WriteString("Drop the empty --policy-map to authorize against the default policy again.\n")
	}
	b.WriteString("\n")
	return b.String()
}
