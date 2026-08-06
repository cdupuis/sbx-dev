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

// writeMap lays out a policy map and its policy files in a temporary directory
// and returns the path to the map.
func writeMap(t *testing.T, policyMap string, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	for name, source := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(source), 0o600))
	}
	path := filepath.Join(dir, "policy-map.yaml")
	require.NoError(t, os.WriteFile(path, []byte(policyMap), 0o600))
	return path
}

func decideWith(t *testing.T, a *Authorizer, caller string, argv ...string) Decision {
	t.Helper()

	cat, err := catalog.Embedded()
	require.NoError(t, err)
	inv, err := resolve.Argv(cat, argv)
	require.NoError(t, err)

	return a.Authorize(Request{
		Caller:     identity.Identity{Sandbox: caller, Generation: 1},
		Invocation: inv,
		Workdir:    "/work",
	})
}

const permitRead = `permit (principal, action in SBX::Action::"read", resource);`

func TestPolicyMapAcceptsAScalarOrAList(t *testing.T) {
	path := writeMap(t, `
bindings:
  - sandboxes: worker-1
    policies: read.cedar
  - sandboxes: [worker-2, worker-3]
    policies: [read.cedar]
`, map[string]string{"read.cedar": permitRead})

	bindings, err := LoadPolicyMap(path)
	require.NoError(t, err)
	require.Len(t, bindings, 2)
	require.Equal(t, stringList{"worker-1"}, bindings[0].Sandboxes)
	require.Equal(t, stringList{"worker-2", "worker-3"}, bindings[1].Sandboxes)
}

func TestPolicyMapResolvesPolicyPathsAgainstItself(t *testing.T) {
	path := writeMap(t, `
bindings:
  - sandboxes: "*"
    policies: read.cedar
`, map[string]string{"read.cedar": permitRead})

	bindings, err := LoadPolicyMap(path)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(filepath.Dir(path), "read.cedar"), bindings[0].Policies[0])
}

func TestEveryMatchingBindingApplies(t *testing.T) {
	// Two bindings match worker-1, and it holds what both grant.
	path := writeMap(t, `
bindings:
  - sandboxes: "*"
    policies: read.cedar
  - sandboxes: "worker-*"
    policies: destroy.cedar
`, map[string]string{
		"read.cedar":    permitRead,
		"destroy.cedar": `permit (principal, action in SBX::Action::"destroySandbox", resource);`,
	})

	a, err := NewFromPolicyMap(path)
	require.NoError(t, err)

	require.True(t, decideWith(t, a, "worker-1", "ls").Allowed)
	require.True(t, decideWith(t, a, "worker-1", "rm", "worker-2").Allowed)

	// The pattern binding does not reach a name it does not match.
	require.True(t, decideWith(t, a, "builder", "ls").Allowed)
	require.False(t, decideWith(t, a, "builder", "rm", "worker-2").Allowed)
}

func TestAForbidInOneFileBeatsAPermitInAnother(t *testing.T) {
	// This is what makes a baseline bound to "*" a guardrail rather than a
	// default: no role file can restore what it forbids.
	path := writeMap(t, `
bindings:
  - sandboxes: "*"
    policies: baseline.cedar
  - sandboxes: worker-1
    policies: generous.cedar
`, map[string]string{
		"baseline.cedar": `forbid (principal, action in SBX::Action::"destroySandbox", resource);`,
		"generous.cedar": `permit (principal, action, resource);`,
	})

	a, err := NewFromPolicyMap(path)
	require.NoError(t, err)

	require.True(t, decideWith(t, a, "worker-1", "ls").Allowed, "the generous permit still applies elsewhere")
	require.False(t, decideWith(t, a, "worker-1", "rm", "worker-2").Allowed)
}

func TestASandboxNoBindingMatchesIsToldSo(t *testing.T) {
	// Distinguishing "nothing describes you" from "a rule refused" is what tells
	// an operator to fix the map instead of hunting for a rule.
	path := writeMap(t, `
bindings:
  - sandboxes: "worker-*"
    policies: read.cedar
`, map[string]string{"read.cedar": permitRead})

	a, err := NewFromPolicyMap(path)
	require.NoError(t, err)

	d := decideWith(t, a, "stranger", "ls")
	require.False(t, d.Allowed)
	require.True(t, d.Unassigned)
	require.Contains(t, d.Reason("sbx ls"), "no policy is assigned to this sandbox")

	require.False(t, decideWith(t, a, "worker-1", "ls").Unassigned)
}

func TestPolicyIdsAreQualifiedByTheirFile(t *testing.T) {
	// Cedar numbers policies per source, so two files both hold a "policy0".
	// Qualifying the id keeps them from colliding and names the deciding file.
	path := writeMap(t, `
bindings:
  - sandboxes: "*"
    policies: [read.cedar, destroy.cedar]
`, map[string]string{
		"read.cedar":    permitRead,
		"destroy.cedar": `permit (principal, action in SBX::Action::"destroySandbox", resource);`,
	})

	a, err := NewFromPolicyMap(path)
	require.NoError(t, err)

	require.Equal(t, []string{"read.cedar#policy0"}, decideWith(t, a, "worker-1", "ls").Policies)
	require.Equal(t, []string{"destroy.cedar#policy0"}, decideWith(t, a, "worker-1", "rm", "w").Policies)
}

func TestLoadPolicyMapRejectsAnUnusableMap(t *testing.T) {
	read := map[string]string{"read.cedar": permitRead}

	for name, source := range map[string]string{
		"no bindings":      "bindings: []",
		"no sandboxes":     "bindings:\n  - policies: read.cedar",
		"nothing assigned": "bindings:\n  - sandboxes: worker-1",
		"bad pattern":      "bindings:\n  - sandboxes: \"worker-[\"\n    policies: read.cedar",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadPolicyMap(writeMap(t, source, read))
			require.Error(t, err)
		})
	}
}

func TestNewFromPolicyMapReportsAMissingPolicyFile(t *testing.T) {
	path := writeMap(t, `
bindings:
  - sandboxes: "*"
    policies: absent.cedar
`, nil)

	_, err := NewFromPolicyMap(path)
	require.ErrorContains(t, err, "absent.cedar")
}
