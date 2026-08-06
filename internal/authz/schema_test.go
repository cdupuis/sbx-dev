package authz

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	expast "github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/resolved"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"
	"github.com/stretchr/testify/require"

	"github.com/cdupuis/sbx-warden/internal/catalog"
	"github.com/cdupuis/sbx-warden/internal/resolve"
)

func schemaPath() string { return filepath.Join("..", "..", SchemaFile) }

// resolvedSchema parses the committed schema, which also proves it is valid
// Cedar rather than merely plausible.
func resolvedSchema(t *testing.T) *resolved.Schema {
	t.Helper()

	raw, err := os.ReadFile(schemaPath())
	require.NoError(t, err)

	var parsed schema.Schema
	require.NoError(t, parsed.UnmarshalCedar(raw), "the committed schema is not valid Cedar")

	out, err := parsed.Resolve()
	require.NoError(t, err)
	return out
}

func TestShippedPoliciesValidateAgainstTheCommittedSchema(t *testing.T) {
	// The schema is worth committing only if it describes the real vocabulary,
	// and this is what proves it: every rule the repository ships type-checks
	// against it, so a policy naming an action or attribute that does not exist
	// fails here rather than silently never matching at runtime.
	validator := validate.New(resolvedSchema(t), validate.WithStrict())

	bindings, err := LoadPolicyMap(shippedMapPath())
	require.NoError(t, err)

	checked := 0
	for _, binding := range bindings {
		for _, file := range binding.Policies {
			source, err := os.ReadFile(file)
			require.NoError(t, err)

			set, err := cedar.NewPolicySetFromBytes(file, source)
			require.NoError(t, err)

			name := filepath.Base(file)
			for id, policy := range set.All() {
				// cedar.Policy exposes the public ast.Policy, which is defined as
				// the experimental one the validator takes.
				tree := (*expast.Policy)(policy.AST())
				require.NoError(t, validator.Policy(name+"#"+string(id), tree),
					"%s#%s does not validate against %s", name, id, SchemaFile)
				checked++
			}
		}
	}
	require.NotZero(t, checked, "no shipped policy was checked")
}

func TestSchemaValidationRejectsAVocabularyThatDoesNotExist(t *testing.T) {
	// Without this the check above could pass by validating nothing.
	validator := validate.New(resolvedSchema(t), validate.WithStrict())

	for name, source := range map[string]string{
		"unknown context attribute": `permit (principal, action in SBX::Action::"read", resource) when { context.mood == "good" };`,
		"unknown action":            `permit (principal, action == SBX::Action::"teleport", resource);`,
		"unknown entity type":       `permit (principal == SBX::Robot::"r2", action, resource);`,
		"misspelled attribute":      `permit (principal, action, resource) when { context.targetsSelfish };`,
	} {
		t.Run(name, func(t *testing.T) {
			set, err := cedar.NewPolicySetFromBytes("bad.cedar", []byte(source))
			require.NoError(t, err, "the policy must parse, so that only validation can reject it")

			for id, policy := range set.All() {
				require.Error(t, validator.Policy(string(id), (*expast.Policy)(policy.AST())))
			}
		})
	}
}

func TestCommittedSchemaMatchesTheCatalog(t *testing.T) {
	cat, err := catalog.Embedded()
	require.NoError(t, err)

	committed, err := os.ReadFile(schemaPath())
	require.NoError(t, err)

	require.Equal(t, string(Schema(cat)), string(committed),
		"the committed schema is stale; run \"task policy:schema\"")
}

func TestSchemaDescribesEveryContextAttribute(t *testing.T) {
	// The context record is the one hand-written part of the schema, so it is
	// the part that can drift. Comparing it against a real request keeps the
	// documented vocabulary and the actual one the same.
	cat, err := catalog.Embedded()
	require.NoError(t, err)
	inv, err := resolve.Argv(cat, []string{"cp", "worker-1:/etc/hostname", "/work/copy"})
	require.NoError(t, err)

	actual := buildContext(inv, "worker-1", Target{Kind: TargetSandbox, Name: "worker-1"}, "/work")

	var documented []string
	for _, attr := range contextAttributes() {
		documented = append(documented, attr.name)
	}

	var present []string
	for key := range actual.Keys() {
		present = append(present, string(key))
	}

	sort.Strings(documented)
	sort.Strings(present)

	// flagValues has keys that depend on the command, which a Cedar record
	// cannot type, so the schema documents its absence instead.
	require.Equal(t, []string{"flagValues"}, missing(present, documented),
		"an attribute is in the request but not in the schema")
	require.Empty(t, missing(documented, present),
		"an attribute is in the schema but not in the request")
}

// missing returns the members of have that want does not contain.
func missing(have, want []string) []string {
	index := make(map[string]bool, len(want))
	for _, name := range want {
		index[name] = true
	}
	var out []string
	for _, name := range have {
		if !index[name] {
			out = append(out, name)
		}
	}
	return out
}

func TestSchemaTypesMatchTheValuesARequestCarries(t *testing.T) {
	cat, err := catalog.Embedded()
	require.NoError(t, err)
	inv, err := resolve.Argv(cat, []string{"cp", "worker-1:/etc/hostname", "/work/copy"})
	require.NoError(t, err)

	actual := buildContext(inv, "worker-1", Target{Kind: TargetSandbox, Name: "worker-1"}, "/work")

	for _, attr := range contextAttributes() {
		value, ok := actual.Get(types.String(attr.name))
		require.True(t, ok, "%s is documented but absent", attr.name)

		var want string
		switch value.(type) {
		case types.String:
			want = "String"
		case types.Boolean:
			want = "Bool"
		case types.Set:
			want = "Set<String>"
		default:
			t.Fatalf("%s has an unhandled type %T", attr.name, value)
		}
		require.Equal(t, want, attr.cedarType, "%s is documented as the wrong type", attr.name)
	}
}
