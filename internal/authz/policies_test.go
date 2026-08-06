package authz

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cdupuis/sbx-warden/internal/catalog"
	"github.com/cdupuis/sbx-warden/internal/identity"
	"github.com/cdupuis/sbx-warden/internal/resolve"
)

// These tests are written against the policy files the repository ships, so the
// behaviour those files describe in prose is the behaviour they actually have.

func shippedMapPath() string {
	return filepath.Join("..", "..", "policies", "policy-map.yaml")
}

func shipped(t *testing.T) *Authorizer {
	t.Helper()
	a, err := NewFromPolicyMap(shippedMapPath())
	require.NoError(t, err)
	return a
}

// ask decides one command against the shipped policies, with the server's
// working directory at /work so the confinement rules have something to compare.
func ask(t *testing.T, caller string, argv ...string) Decision {
	t.Helper()

	cat, err := catalog.Embedded()
	require.NoError(t, err)
	inv, err := resolve.Argv(cat, argv)
	require.NoError(t, err, "argv must resolve before it can be authorized")

	return shipped(t).Authorize(Request{
		Caller:     identity.Identity{Sandbox: caller, Generation: 1},
		Invocation: inv,
		Workdir:    "/work",
	})
}

func allow(t *testing.T, caller string, argv ...string) {
	t.Helper()
	d := ask(t, caller, argv...)
	require.True(t, d.Allowed, "expected %s to be allowed %v: %+v", caller, argv, d)
	require.Empty(t, d.Errors)
}

func deny(t *testing.T, caller string, argv ...string) {
	t.Helper()
	d := ask(t, caller, argv...)
	require.False(t, d.Allowed, "expected %s to be denied %v: %+v", caller, argv, d)
}

func TestShippedMapGivesEverySandboxReadOnlyAccess(t *testing.T) {
	// The "*" binding, so a name matching no role still gets the floor.
	for _, caller := range []string{"worker-1", "orchestrator", "unnamed-thing"} {
		allow(t, caller, "ls")
		allow(t, caller, "version")
		allow(t, caller, "policy", "ls")
	}
}

func TestShippedBaselineForbidsWhatNoRoleRestores(t *testing.T) {
	// The orchestrator is the most capable role this map binds; if the guardrails
	// hold for it they hold for every sandbox the map describes. The root group,
	// which the guardrails exempt, is deliberately bound to nothing here.
	deny(t, "orchestrator", "secret", "ls")
	deny(t, "orchestrator", "secret", "rm", "github")
	deny(t, "orchestrator", "login")
	deny(t, "orchestrator", "daemon", "stop")
	deny(t, "orchestrator", "kit", "push", "/work/kit", "example.com/kit:1")
}

func TestShippedBaselineRefusesPrivilegedExec(t *testing.T) {
	allow(t, "orchestrator", "exec", "worker-1", "sh")
	deny(t, "orchestrator", "exec", "--privileged", "worker-1", "sh")
}

func TestShippedWorkerActsOnItselfOnly(t *testing.T) {
	allow(t, "worker-1", "exec", "worker-1", "ls")

	deny(t, "worker-1", "exec", "worker-2", "ls")
	deny(t, "worker-1", "rm", "worker-2")
	deny(t, "worker-1", "rm", "worker-1")
	deny(t, "worker-1", "create", "shell", "/work/new")
}

func TestShippedWorkerCopiesOnlyUnderTheWorkingDirectory(t *testing.T) {
	// cp names its sandbox inside a path, which is the case a positional-only
	// lookup would miss.
	allow(t, "worker-1", "cp", "worker-1:/etc/hostname", "/work/copy")

	deny(t, "worker-1", "cp", "worker-1:/etc/hostname", "/etc/passwd")
	deny(t, "worker-1", "cp", "worker-2:/etc/hostname", "/work/copy")
}

func TestShippedWorkerCannotActOnASiblingAlongsideItself(t *testing.T) {
	// A variadic command that names a sibling too is not acting on "itself".
	deny(t, "worker-1", "exec", "worker-2", "ls")
	deny(t, "worker-1", "cp", "worker-1:/a", "worker-2:/b")
}

func TestShippedOrchestratorManagesSandboxesUnderTheWorkingDirectory(t *testing.T) {
	allow(t, "orchestrator", "create", "shell", "/work/project")
	allow(t, "orchestrator", "create", "shell", "project")
	allow(t, "orchestrator", "rm", "worker-1")
	allow(t, "orchestrator", "exec", "worker-1", "ls")
}

func TestShippedOrchestratorCannotMountOutsideTheWorkingDirectory(t *testing.T) {
	deny(t, "orchestrator", "create", "shell", "/etc")
	deny(t, "orchestrator", "create", "shell", "/work/../etc")
	deny(t, "orchestrator", "create", "shell", "../etc")

	// One path outside is enough, even alongside a permitted one.
	deny(t, "orchestrator", "create", "shell", "/work/ok", "/etc")
}

func TestShippedOrchestratorDoesNotWidenNetworkPolicy(t *testing.T) {
	deny(t, "orchestrator", "policy", "allow", "network", "--sandbox", "worker-1", "example.com:443")
}

func TestPolicyMapPatternsSelectRoles(t *testing.T) {
	// worker-* reaches worker-1 but not a name that merely contains it.
	allow(t, "worker-1", "exec", "worker-1", "ls")
	deny(t, "not-worker-1", "exec", "not-worker-1", "ls")
}

func TestGroupsComeFromTheMatchingBindings(t *testing.T) {
	a := shipped(t)
	require.Equal(t, []string{"workers"}, a.groupsFor("worker-1"))
	require.Equal(t, []string{"orchestrators"}, a.groupsFor("orchestrator"))
	require.Empty(t, a.groupsFor("unnamed-thing"))
}

// withRoot binds the shipped policies the way the map's commented-out root entry
// does. The shipped map leaves root unbound, so the role has to be assembled here
// to be tested at all.
func withRoot(t *testing.T) *Authorizer {
	t.Helper()

	dir, err := filepath.Abs(filepath.Join("..", "..", "policies"))
	require.NoError(t, err)
	at := func(name string) string { return filepath.Join(dir, name) }

	mapPath := filepath.Join(t.TempDir(), "policy-map.yaml")
	source := "bindings:\n" +
		"  - sandboxes: \"*\"\n" +
		"    policies: [" + at("baseline.cedar") + ", " + at("readonly.cedar") + "]\n" +
		"  - sandboxes: root\n" +
		"    policies: " + at("root.cedar") + "\n" +
		"    groups: root\n"
	require.NoError(t, os.WriteFile(mapPath, []byte(source), 0o600))

	a, err := NewFromPolicyMap(mapPath)
	require.NoError(t, err)
	return a
}

func askAsRoot(t *testing.T, argv ...string) Decision {
	t.Helper()

	cat, err := catalog.Embedded()
	require.NoError(t, err)
	inv, err := resolve.Argv(cat, argv)
	require.NoError(t, err, "argv must resolve before it can be authorized")

	return withRoot(t).Authorize(Request{
		Caller:     identity.Identity{Sandbox: "root", Generation: 1},
		Invocation: inv,
		Workdir:    "/work",
	})
}

func TestShippedRootReadsWithoutAsking(t *testing.T) {
	for _, argv := range [][]string{
		{"ls"},
		{"version"},
		{"policy", "ls"},
		{"daemon", "status"},
		{"kit", "inspect", "example.com/kit:1"},
	} {
		d := askAsRoot(t, argv...)
		require.True(t, d.Allowed, "expected root to be allowed %v: %+v", argv, d)
		require.False(t, d.NeedsApproval, "reading must not need approval: %v", argv)
		require.Empty(t, d.Errors)
	}
}

func TestShippedRootWithholdsEverythingElseForApproval(t *testing.T) {
	// Spot-checks across every capability group, including the four the baseline
	// forbids and the confinement the roles impose, plus a command belonging to no
	// group at all, which only an unconstrained action reaches.
	//
	// None of these is refused and none is granted: each is withheld, which is the
	// whole shape of this role.
	for _, argv := range [][]string{
		{"secret", "ls"},
		{"secret", "rm", "github"},
		{"login"},
		{"daemon", "stop"},
		{"kit", "push", "/work/kit", "example.com/kit:1"},
		{"policy", "allow", "network", "--sandbox", "worker-1", "example.com:443"},
		{"create", "shell", "/etc"},
		{"cp", "worker-1:/etc/hostname", "/etc/passwd"},
		{"exec", "worker-1", "sh"},
		{"exec", "--privileged", "worker-1", "sh"},
		{"rm", "worker-1"},
		{"completion", "bash"},
	} {
		d := askAsRoot(t, argv...)
		require.True(t, d.NeedsApproval, "expected %v to need approval: %+v", argv, d)
		require.False(t, d.Allowed, "a withheld command has not been approved: %v", argv)
		require.Empty(t, d.Errors)
	}
}

func TestShippedMapDoesNotMakeTheNameRootPrivileged(t *testing.T) {
	// root.cedar ships unbound, so a sandbox called "root" must get the read-only
	// floor and nothing else. Otherwise the default map would turn a name into an
	// escalation.
	require.Empty(t, shipped(t).groupsFor("root"))

	allow(t, "root", "ls")
	deny(t, "root", "secret", "ls")
	deny(t, "root", "daemon", "stop")
	deny(t, "root", "exec", "root", "sh")
	deny(t, "root", "exec", "--privileged", "root", "sh")
}
