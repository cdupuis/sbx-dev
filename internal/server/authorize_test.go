package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cdupuis/sbx-warden/internal/authz"
	"github.com/cdupuis/sbx-warden/internal/identity"
)

// testPolicy lets any sandbox read, and lets only the orchestrator remove one.
const testPolicy = `
permit (
    principal,
    action in SBX::Action::"read",
    resource
);

permit (
    principal == SBX::Sandbox::"orchestrator",
    action in SBX::Action::"destroySandbox",
    resource
);
`

type policyServer struct {
	addr     string
	key      identity.Key
	registry *identity.Registry
}

// testAuthorizer binds testPolicy to every sandbox.
func testAuthorizer(t *testing.T) *authz.Authorizer {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.cedar"), []byte(testPolicy), 0o600))

	mapPath := filepath.Join(dir, "policy-map.yaml")
	require.NoError(t, os.WriteFile(mapPath, []byte("bindings:\n  - sandboxes: \"*\"\n    policies: test.cedar\n"), 0o600))

	authorizer, err := authz.NewFromPolicyMap(mapPath)
	require.NoError(t, err)
	return authorizer
}

func startPolicyServer(t *testing.T) policyServer {
	t.Helper()

	key, err := identity.NewKey()
	require.NoError(t, err)
	registry, err := identity.OpenRegistry(filepath.Join(t.TempDir(), "generations.json"))
	require.NoError(t, err)
	authorizer := testAuthorizer(t)

	addr := startServer(t, Config{
		Authorizer:  authorizer,
		IdentityKey: key,
		Generations: registry,
	})
	return policyServer{addr: addr, key: key, registry: registry}
}

func (ps policyServer) token(t *testing.T, sandbox string, generation int) string {
	t.Helper()
	token, err := ps.key.Mint(sandbox, generation)
	require.NoError(t, err)
	return token
}

func TestSessionRunsACommandThePolicyAllows(t *testing.T) {
	ps := startPolicyServer(t)

	got := runClient(t, ps.addr, ps.token(t, "worker-1", 1), nil, "version")
	require.NoError(t, got.err)
	require.Equal(t, 0, got.code)
	require.Contains(t, got.stdout, "sbx version")
}

func TestSessionRefusesACommandThePolicyDoesNotAllow(t *testing.T) {
	ps := startPolicyServer(t)

	got := runClient(t, ps.addr, ps.token(t, "worker-1", 1), nil, "rm", "worker-2")
	require.ErrorContains(t, got.err, "policy does not allow sbx rm")
	require.NotEqual(t, 0, got.code)
}

func TestSessionAuthorizesEachSandboxSeparately(t *testing.T) {
	ps := startPolicyServer(t)

	allowed := runClient(t, ps.addr, ps.token(t, "orchestrator", 1), nil, "rm", "worker-2")
	require.NoError(t, allowed.err, "the orchestrator may remove a sandbox")

	refused := runClient(t, ps.addr, ps.token(t, "worker-1", 1), nil, "rm", "worker-2")
	require.Error(t, refused.err, "a worker may not")
}

func TestSessionRefusesASecretThatNamesNoSandbox(t *testing.T) {
	ps := startPolicyServer(t)

	// A bare secret is not a credential here. Every session names the sandbox it
	// belongs to, because a rule can only describe a caller it can identify.
	got := runClient(t, ps.addr, "0123456789abcdef", nil, "version")
	require.ErrorContains(t, got.err, "invalid token")
}

func TestSessionRefusesAForgedToken(t *testing.T) {
	ps := startPolicyServer(t)

	other, err := identity.NewKey()
	require.NoError(t, err)
	forged, err := other.Mint("orchestrator", 1)
	require.NoError(t, err)

	got := runClient(t, ps.addr, forged, nil, "version")
	require.ErrorContains(t, got.err, "invalid token")
}

func TestSessionRefusesARenamedToken(t *testing.T) {
	ps := startPolicyServer(t)
	token := ps.token(t, "worker-1", 1)

	// Editing the sandbox name out of a valid token must not promote it: the MAC
	// covers the name, so the signature no longer matches what the token claims.
	got := runClient(t, ps.addr, "v1.orchestrator.1."+token[len("v1.worker-1.1."):], nil, "rm", "worker-2")
	require.ErrorContains(t, got.err, "invalid token")
}

func TestSessionRefusesARetiredToken(t *testing.T) {
	ps := startPolicyServer(t)
	retired := ps.token(t, "worker-1", 1)
	require.NoError(t, ps.registry.Record("worker-1", 2))

	got := runClient(t, ps.addr, retired, nil, "version")
	require.ErrorContains(t, got.err, "has been replaced")

	current := runClient(t, ps.addr, ps.token(t, "worker-1", 2), nil, "version")
	require.NoError(t, current.err)
}

func TestSessionRefusesACommandLineItCannotResolve(t *testing.T) {
	ps := startPolicyServer(t)

	// A command line the server cannot parse exactly is one it cannot describe
	// to a policy, so it does not run.
	got := runClient(t, ps.addr, ps.token(t, "worker-1", 1), nil, "version", "--nonesuch")
	require.ErrorContains(t, got.err, "has no --nonesuch")

	hidden := runClient(t, ps.addr, ps.token(t, "worker-1", 1), nil, "--app-name", "other", "version")
	require.ErrorContains(t, hidden.err, "has no --app-name")
}

// Without a policy the server still authenticates every caller; it just does
// not restrict what a granted sandbox may then do.
func TestSessionWithoutAPolicyRunsAnyCommand(t *testing.T) {
	addr := startServer(t, Config{})

	got := runClient(t, addr, testToken, nil, "rm", "worker-2")
	require.NoError(t, got.err)
	require.Contains(t, got.stdout, "removed:worker-2")
}
