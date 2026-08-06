package authz

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cdupuis/sbx-dev/internal/catalog"
	"github.com/cdupuis/sbx-dev/internal/identity"
	"github.com/cdupuis/sbx-dev/internal/resolve"
)

// examplePolicy is the policy the tests are written against. It is also the
// worked example of the model: capabilities are granted to groups, confinement
// is expressed against the arguments the server parsed, and the guardrails are
// forbid rules that a later permit cannot undo.
const examplePolicy = `
// Anyone may look.
permit (
    principal,
    action in SBX::Action::"read",
    resource
);

// A worker may run commands in itself, and nowhere else.
permit (
    principal in SBX::Group::"workers",
    action in SBX::Action::"runInSandbox",
    resource
)
when { context.targetsSelf };

// The orchestrator manages the fleet.
permit (
    principal in SBX::Group::"orchestrators",
    action in [SBX::Action::"createSandbox", SBX::Action::"destroySandbox"],
    resource
);

// Widening a sandbox's reach is the orchestrator's call, and worth confirming.
@requireApproval("a new network rule changes what a sandbox can reach")
permit (
    principal in SBX::Group::"orchestrators",
    action in SBX::Action::"writePolicy",
    resource
);

// Whatever else a policy permits, a command may only reach host files under
// /work.
forbid (
    principal,
    action in SBX::Action::"touchHostFiles",
    resource
)
unless {
    context.hostPaths.isEmpty() ||
    context.hostPathsRoot == "/work" ||
    context.hostPathsRoot like "/work/*"
};

// A sandbox may never hand itself extended privileges.
forbid (
    principal,
    action == SBX::Action::"exec",
    resource
)
when { context.flags.contains("privileged") };

// Nothing may rewrite the host's stored credentials.
forbid (
    principal,
    action in SBX::Action::"writeSecrets",
    resource
);
`

// exampleMap binds the worked example to every caller and hands out the group
// membership its rules are written in terms of.
const exampleMap = `
bindings:
  - sandboxes: "*"
    policies: example.cedar
  - sandboxes: orchestrator
    groups: orchestrators
  - sandboxes: "worker-*"
    groups: workers
`

func authorizer(t *testing.T) *Authorizer {
	t.Helper()
	a, err := NewFromPolicyMap(writeMap(t, exampleMap, map[string]string{"example.cedar": examplePolicy}))
	require.NoError(t, err)
	return a
}

func decide(t *testing.T, caller string, argv ...string) Decision {
	t.Helper()

	cat, err := catalog.Embedded()
	require.NoError(t, err)
	inv, err := resolve.Argv(cat, argv)
	require.NoError(t, err, "argv must resolve before it can be authorized")

	return authorizer(t).Authorize(Request{
		Caller:     identity.Identity{Sandbox: caller, Generation: 1},
		Invocation: inv,
		Workdir:    "/work",
	})
}

func requireAllowed(t *testing.T, d Decision, argv ...string) {
	t.Helper()
	require.True(t, d.Allowed, "expected %v to be allowed: %+v", argv, d)
	require.Empty(t, d.Errors)
}

func TestReadingIsAllowedForEveryone(t *testing.T) {
	requireAllowed(t, decide(t, "worker-1", "ls"), "ls")
	requireAllowed(t, decide(t, "worker-1", "policy", "ls"))
	requireAllowed(t, decide(t, "worker-1", "ports", "worker-2"))
}

func TestAWorkerRunsCommandsOnlyInItself(t *testing.T) {
	own := decide(t, "worker-1", "exec", "worker-1", "ls")
	requireAllowed(t, own, "exec worker-1")

	other := decide(t, "worker-1", "exec", "worker-2", "ls")
	require.False(t, other.Allowed, "a worker must not reach into a sibling")
	require.Contains(t, other.Reason("sbx exec"), "policy does not allow")
}

func TestOnlyTheOrchestratorManagesTheFleet(t *testing.T) {
	requireAllowed(t, decide(t, "orchestrator", "rm", "worker-2"))
	require.False(t, decide(t, "worker-1", "rm", "worker-2").Allowed)
	require.False(t, decide(t, "worker-1", "create", "claude", "/work/new").Allowed)
}

func TestConfinementAppliesToEveryPathACommandNames(t *testing.T) {
	inside := decide(t, "orchestrator", "create", "claude", "/work/a", "/work/b")
	requireAllowed(t, inside, "create under /work")

	// One path outside the allowed tree is enough to forbid the command, which
	// is what the common ancestor buys: a policy cannot be slipped past by
	// adding a second path.
	outside := decide(t, "orchestrator", "create", "claude", "/work/a", "/etc")
	require.False(t, outside.Allowed)

	require.False(t, decide(t, "orchestrator", "create", "claude", "/etc").Allowed)
}

func TestConfinementResolvesRelativeAndTraversingPaths(t *testing.T) {
	// The server runs commands in /work, so "sub" is /work/sub.
	requireAllowed(t, decide(t, "orchestrator", "create", "claude", "sub"), "relative path")

	// ".." must not walk out of the confined tree.
	require.False(t, decide(t, "orchestrator", "create", "claude", "/work/../etc").Allowed)
	require.False(t, decide(t, "orchestrator", "create", "claude", "../etc").Allowed)
}

func TestAForbidBeatsAPermit(t *testing.T) {
	// The orchestrator may run commands in sandboxes, but not with extended
	// privileges, and no permit can restore that.
	require.False(t, decide(t, "orchestrator", "exec", "--privileged", "worker-1", "sh").Allowed)
	require.False(t, decide(t, "worker-1", "exec", "--privileged", "worker-1", "sh").Allowed)

	// Only --privileged is forbidden; an ordinary interactive shell still runs.
	requireAllowed(t, decide(t, "worker-1", "exec", "-it", "worker-1", "sh"), "exec -it")
}

func TestSecretWritesAreForbiddenOutright(t *testing.T) {
	require.False(t, decide(t, "orchestrator", "secret", "rm", "github").Allowed)
	require.False(t, decide(t, "orchestrator", "login").Allowed)
}

func TestApprovalWithholdsAPermit(t *testing.T) {
	d := decide(t, "orchestrator", "policy", "allow", "network", "--sandbox", "worker-1", "example.com:443")

	require.False(t, d.Allowed, "an unconfirmed request has not been approved")
	require.True(t, d.NeedsApproval)
	require.Contains(t, d.Reason("sbx policy allow network"), "needs an operator's approval")
}

func TestAnUnidentifiedCallerIsDeniedBeforeAnyPolicyRuns(t *testing.T) {
	cat, err := catalog.Embedded()
	require.NoError(t, err)
	inv, err := resolve.Argv(cat, []string{"ls"})
	require.NoError(t, err)

	d := authorizer(t).Authorize(Request{Invocation: inv, Workdir: "/work"})

	require.False(t, d.Allowed)
	require.Contains(t, d.Errors[0], "no sandbox identity")
}

func TestAnEmptyPolicyGrantsNothing(t *testing.T) {
	a, err := New(nil)
	require.NoError(t, err)

	cat, err := catalog.Embedded()
	require.NoError(t, err)
	inv, err := resolve.Argv(cat, []string{"ls"})
	require.NoError(t, err)

	d := a.Authorize(Request{
		Caller:     identity.Identity{Sandbox: "worker-1", Generation: 1},
		Invocation: inv,
	})
	require.False(t, d.Allowed, "a server with no rules grants nothing")
	require.True(t, d.Unassigned)
}

func TestAnUnclassifiedCommandBelongsToNoGroup(t *testing.T) {
	// "sbx completion bash" is in no capability group, so a policy written in
	// terms of groups does not reach it.
	require.False(t, decide(t, "worker-1", "completion", "bash").Allowed)
}

func TestNewRejectsAMalformedPolicy(t *testing.T) {
	path := writeMap(t, `
bindings:
  - sandboxes: "*"
    policies: broken.cedar
`, map[string]string{"broken.cedar": "permit (this is not cedar);"})

	_, err := NewFromPolicyMap(path)
	require.ErrorContains(t, err, "broken.cedar")
}

func TestTargetOfPrefersTheSandboxFlag(t *testing.T) {
	cat, err := catalog.Embedded()
	require.NoError(t, err)

	flagged, err := resolve.Argv(cat, []string{"policy", "allow", "network", "--sandbox", "worker-2", "example.com:443"})
	require.NoError(t, err)
	require.Equal(t, Target{Kind: TargetSandbox, Name: "worker-2"}, TargetOf(flagged))

	positional, err := resolve.Argv(cat, []string{"exec", "worker-1", "ls"})
	require.NoError(t, err)
	require.Equal(t, Target{Kind: TargetSandbox, Name: "worker-1"}, TargetOf(positional))

	host, err := resolve.Argv(cat, []string{"ls"})
	require.NoError(t, err)
	require.Equal(t, Target{Kind: TargetHost}, TargetOf(host))
}

func TestCommonAncestor(t *testing.T) {
	require.Equal(t, "", commonAncestor(nil))
	require.Equal(t, "/work/a", commonAncestor([]string{"/work/a"}))
	require.Equal(t, "/work", commonAncestor([]string{"/work/a", "/work/b"}))
	require.Equal(t, "/work", commonAncestor([]string{"/work/a/deep", "/work"}))
	require.Equal(t, "/", commonAncestor([]string{"/work/a", "/etc"}))
}
