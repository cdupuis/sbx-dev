package authz

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// A policy map is the layer above the policies themselves: it says which policy
// files apply to which sandboxes, so a policy file describes a role and the map
// decides who holds it.
//
//	bindings:
//	  - sandboxes: "*"
//	    policies: baseline.cedar
//
//	  - sandboxes: "worker-*"
//	    policies: [readonly.cedar, worker.cedar]
//	    groups: workers
//
//	  - sandboxes: orchestrator
//	    policies: orchestrator.cedar
//	    groups: orchestrators
//
// Every binding whose pattern matches the calling sandbox applies, so order does
// not matter and a baseline bound to "*" cannot be skipped by a later entry.
// Cedar decides the rest: permits accumulate and a forbid in any matching file
// beats them all. A sandbox no binding matches is granted nothing.
type policyMap struct {
	Bindings []Binding `yaml:"bindings"`
}

// Binding assigns policy files, and optionally group membership, to the
// sandboxes whose names match one of its patterns.
type Binding struct {
	// Sandboxes are the name patterns this binding applies to. A pattern is a
	// glob over the sandbox name: "*" matches any run of characters and "?" a
	// single one. A pattern without a wildcard is an exact name.
	Sandboxes stringList `yaml:"sandboxes"`
	// Policies are the Cedar files to evaluate, relative to the policy map.
	Policies stringList `yaml:"policies"`
	// Groups are the group memberships to give the matching sandboxes, which is
	// how a policy can say "in SBX::Group::\"workers\"" instead of naming each
	// sandbox.
	Groups stringList `yaml:"groups"`
}

// stringList accepts either a single value or a list, because a binding that
// names one pattern or one file is the common case and quoting it as a list adds
// nothing.
type stringList []string

func (l *stringList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var one string
		if err := node.Decode(&one); err != nil {
			return err
		}
		*l = stringList{one}
		return nil
	}
	var many []string
	if err := node.Decode(&many); err != nil {
		return err
	}
	*l = many
	return nil
}

// LoadPolicyMap reads a policy map and resolves each policy path against the
// map's own directory, so a directory of policies can be moved or checked out
// anywhere without editing it.
func LoadPolicyMap(mapPath string) ([]Binding, error) {
	raw, err := os.ReadFile(mapPath)
	if err != nil {
		return nil, fmt.Errorf("authz: read policy map: %w", err)
	}

	var parsed policyMap
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("authz: parse policy map %s: %w", mapPath, err)
	}
	if len(parsed.Bindings) == 0 {
		return nil, fmt.Errorf("authz: policy map %s binds no sandboxes to a policy", mapPath)
	}

	base := filepath.Dir(mapPath)
	for i, binding := range parsed.Bindings {
		if len(binding.Sandboxes) == 0 {
			return nil, fmt.Errorf("authz: policy map %s: binding %d names no sandboxes", mapPath, i+1)
		}
		for _, pattern := range binding.Sandboxes {
			// A malformed pattern would silently match nothing, which reads as a
			// policy that was applied and denied rather than one never consulted.
			if _, err := path.Match(pattern, "probe"); err != nil {
				return nil, fmt.Errorf("authz: policy map %s: %q is not a valid sandbox pattern: %w", mapPath, pattern, err)
			}
		}
		if len(binding.Policies) == 0 && len(binding.Groups) == 0 {
			return nil, fmt.Errorf("authz: policy map %s: binding for %s assigns neither a policy nor a group",
				mapPath, strings.Join(binding.Sandboxes, ", "))
		}
		for j, policy := range binding.Policies {
			if !filepath.IsAbs(policy) {
				parsed.Bindings[i].Policies[j] = filepath.Join(base, policy)
			}
		}
	}
	return parsed.Bindings, nil
}

// matches reports whether a sandbox name is covered by this binding.
func (b Binding) matches(sandbox string) bool {
	for _, pattern := range b.Sandboxes {
		if ok, err := path.Match(pattern, sandbox); err == nil && ok {
			return true
		}
	}
	return false
}
