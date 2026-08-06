// Package authz decides whether a caller may run a resolved sbx command.
//
// Decisions come from Cedar policies, so the rules live in a file an operator
// owns rather than in this code. Cedar denies by default and a forbid always
// beats a permit, which gives two properties worth having at a boundary like
// this one: a server with no policy grants nothing, and a guardrail cannot be
// undone by a later permit.
//
// The vocabulary is deliberately small. The principal is the sandbox that
// called, the action is the sbx command it named, the resource is what that
// command acts on, and the context describes the arguments as the server parsed
// them. A policy never sees the raw argv, because a rule matching on text would
// be matching on the caller's spelling rather than on what sbx will do.
package authz

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/cdupuis/sbx-dev/internal/identity"
	"github.com/cdupuis/sbx-dev/internal/resolve"
)

// Entity types. Keeping them in one place keeps a policy's spelling and this
// package's spelling from drifting apart.
const (
	TypeSandbox = types.EntityType("SBX::Sandbox")
	TypeGroup   = types.EntityType("SBX::Group")
	TypeAction  = types.EntityType("SBX::Action")
	TypeHost    = types.EntityType("SBX::Host")
)

// approvalAnnotation marks a permit that an operator wants to confirm before it
// takes effect. A policy carrying it grants nothing on its own.
const approvalAnnotation = "requireApproval"

// TargetKind says what sort of thing a command acts on.
type TargetKind int

const (
	// TargetHost is the default: a command that does not name a sandbox acts on
	// the host's sbx installation.
	TargetHost TargetKind = iota
	// TargetSandbox is a command that names the sandbox it acts on.
	TargetSandbox
)

// Target is what a command acts on.
type Target struct {
	Kind TargetKind
	Name string
}

// Request is one authorization question.
type Request struct {
	// Caller is the sandbox that presented an identity token. Its zero value
	// means the caller proved no identity, which no policy can grant.
	Caller identity.Identity
	// Invocation is the argv as the server resolved it.
	Invocation *resolve.Invocation
	// Workdir is the directory the server runs commands in, used to resolve the
	// relative paths a command names.
	Workdir string
}

// Decision is the answer, together with enough detail to tell a caller why.
type Decision struct {
	// Allowed reports whether the command may run.
	Allowed bool
	// NeedsApproval reports that a policy would permit the command but asked for
	// confirmation first. Allowed is false in that case: an unconfirmed request
	// has not been approved.
	NeedsApproval bool
	// Unassigned reports that no policy covers the calling sandbox at all, which
	// is a gap in the policy map rather than a rule that refused.
	Unassigned bool
	// Policies names the policies that decided, so an operator can find the rule
	// that applied.
	Policies []string
	// Errors holds policy evaluation failures. Any error denies.
	Errors []string
}

// Reason renders a decision for a caller, naming the command and the rule
// without quoting the caller's arguments back at them.
func (d Decision) Reason(command string) string {
	switch {
	case len(d.Errors) > 0:
		return fmt.Sprintf("policy could not be evaluated for %s", command)
	case d.Unassigned:
		return fmt.Sprintf("no policy is assigned to this sandbox, so %s is not allowed", command)
	case d.NeedsApproval:
		return fmt.Sprintf("%s needs an operator's approval", command)
	case !d.Allowed:
		return fmt.Sprintf("policy does not allow %s", command)
	default:
		return fmt.Sprintf("policy allows %s", command)
	}
}

// Authorizer evaluates requests against the policies bound to the caller.
//
// Which policies apply depends on who is calling: a policy map binds files to
// sandbox names and patterns, and a caller is judged by every binding it matches.
// A policy that should reach everyone is bound to "*".
type Authorizer struct {
	bindings []compiledBinding

	// resolved caches the merged policy set per caller. Callers are
	// HMAC-authenticated sandbox names, so the key space is the set of sandboxes
	// an operator granted rather than anything a caller can inflate.
	mu       sync.RWMutex
	resolved map[string]*cedar.PolicySet
}

// compiledBinding is a Binding with its policy files parsed.
type compiledBinding struct {
	binding  Binding
	policies cedar.PolicyMap
}

// New compiles the policies every binding names.
func New(bindings []Binding) (*Authorizer, error) {
	a := &Authorizer{resolved: map[string]*cedar.PolicySet{}}
	for _, binding := range bindings {
		compiled, err := compileBinding(binding)
		if err != nil {
			return nil, err
		}
		a.bindings = append(a.bindings, compiled)
	}
	return a, nil
}

// NewFromPolicyMap compiles every policy a map binds. The map is a path or a
// URL, and so is each policy it names.
func NewFromPolicyMap(mapRef string) (*Authorizer, error) {
	bindings, err := LoadPolicyMap(mapRef)
	if err != nil {
		return nil, err
	}
	return New(bindings)
}

// compileBinding parses a binding's policies, qualifying each policy id with the
// document it came from. Cedar numbers policies per source, so two documents both
// contain a "policy0"; without qualification merging them would drop one, and a
// diagnostic could not say which one decided.
func compileBinding(binding Binding) (compiledBinding, error) {
	compiled := compiledBinding{binding: binding, policies: cedar.PolicyMap{}}
	for _, ref := range binding.Policies {
		source, err := readRef(ref)
		if err != nil {
			return compiledBinding{}, fmt.Errorf("authz: read policy: %w", err)
		}
		set, err := cedar.NewPolicySetFromBytes(ref, source)
		if err != nil {
			return compiledBinding{}, fmt.Errorf("authz: parse %s: %w", ref, err)
		}
		name := refName(ref)
		for id, policy := range set.All() {
			compiled.policies[cedar.PolicyID(name+"#"+string(id))] = policy
		}
	}
	return compiled, nil
}

// policiesFor returns the policy set that judges a caller: everything bound to a
// pattern the caller's name matches.
func (a *Authorizer) policiesFor(caller string) *cedar.PolicySet {
	a.mu.RLock()
	cached, ok := a.resolved[caller]
	a.mu.RUnlock()
	if ok {
		return cached
	}

	merged := cedar.NewPolicySet()
	for _, binding := range a.bindings {
		if !binding.binding.matches(caller) {
			continue
		}
		for id, policy := range binding.policies {
			merged.Add(id, policy)
		}
	}

	a.mu.Lock()
	a.resolved[caller] = merged
	a.mu.Unlock()
	return merged
}

// hasPolicyFor reports whether any policy at all judges a caller. A sandbox no
// binding matches is not merely denied, it was never described, and saying so
// tells an operator to fix the map rather than hunt for a rule.
func (a *Authorizer) hasPolicyFor(caller string) bool {
	return len(a.policiesFor(caller).Map()) > 0
}

// groupsFor reports the groups a sandbox belongs to, from every binding whose
// pattern matches it.
func (a *Authorizer) groupsFor(sandbox string) []string {
	if sandbox == "" {
		return nil
	}
	var groups []string
	for _, binding := range a.bindings {
		if binding.binding.matches(sandbox) {
			groups = append(groups, binding.binding.Groups...)
		}
	}
	return dedupe(groups)
}

func dedupe(values []string) []string {
	if len(values) < 2 {
		return values
	}
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// ErrNoIdentity reports a request from a caller that proved no identity.
var ErrNoIdentity = errors.New("the caller presented no sandbox identity")

// Authorize answers one request. An unidentified caller is denied before any
// policy runs, because every rule is written about a named sandbox and a request
// with no principal would silently match a policy that omitted one.
func (a *Authorizer) Authorize(req Request) Decision {
	if req.Caller.Sandbox == "" {
		return Decision{Errors: []string{ErrNoIdentity.Error()}}
	}
	if req.Invocation == nil {
		return Decision{Errors: []string{"no resolved command to authorize"}}
	}
	if !a.hasPolicyFor(req.Caller.Sandbox) {
		return Decision{Unassigned: true}
	}

	target := TargetOf(req.Invocation)
	entities := a.entities(req.Caller.Sandbox, req.Invocation, target)
	policies := a.policiesFor(req.Caller.Sandbox)

	decision, diagnostic := policies.IsAuthorized(entities, cedar.Request{
		Principal: types.NewEntityUID(TypeSandbox, types.String(req.Caller.Sandbox)),
		Action:    actionUID(req.Invocation),
		Resource:  resourceUID(target),
		Context:   buildContext(req.Invocation, req.Caller.Sandbox, target, req.Workdir),
	})

	out := Decision{Allowed: bool(decision)}
	for _, reason := range diagnostic.Reasons {
		out.Policies = append(out.Policies, string(reason.PolicyID))
	}
	for _, err := range diagnostic.Errors {
		out.Errors = append(out.Errors, err.String())
	}
	sort.Strings(out.Policies)

	// An evaluation error means a rule did not answer, so the answer is no.
	if len(out.Errors) > 0 {
		out.Allowed = false
		return out
	}
	if out.Allowed && anyRequiresApproval(policies, diagnostic.Reasons) {
		out.Allowed = false
		out.NeedsApproval = true
	}
	return out
}

// anyRequiresApproval reports whether a policy that permitted the request asked
// for confirmation. One such policy is enough: an operator who marked a rule for
// approval did not mean for another rule to wave it through.
func anyRequiresApproval(policies *cedar.PolicySet, reasons []types.DiagnosticReason) bool {
	for _, reason := range reasons {
		policy := policies.Get(reason.PolicyID)
		if policy == nil {
			continue
		}
		if _, ok := policy.Annotations()[approvalAnnotation]; ok {
			return true
		}
	}
	return false
}

// TargetOf reports what a command acts on: the sandbox it names, or the host.
//
// A command may name several sandboxes but a request has one resource, so the
// first name wins here. Rules that must hold for every named sandbox use
// context.targetsSelf, which considers all of them.
func TargetOf(inv *resolve.Invocation) Target {
	if names := namedSandboxes(inv); len(names) > 0 {
		return Target{Kind: TargetSandbox, Name: names[0]}
	}
	return Target{Kind: TargetHost}
}

func actionUID(inv *resolve.Invocation) types.EntityUID {
	return types.NewEntityUID(TypeAction, types.String(strings.Join(inv.Command.Path, " ")))
}

func resourceUID(target Target) types.EntityUID {
	if target.Kind == TargetSandbox {
		return types.NewEntityUID(TypeSandbox, types.String(target.Name))
	}
	return types.NewEntityUID(TypeHost, "local")
}

// entities builds the entity set a decision needs: the calling sandbox with its
// groups, the action with the capability groups it belongs to, and the resource.
func (a *Authorizer) entities(caller string, inv *resolve.Invocation, target Target) types.EntityMap {
	entities := types.EntityMap{}

	callerGroups := a.groupsFor(caller)
	callerUID := types.NewEntityUID(TypeSandbox, types.String(caller))
	entities[callerUID] = types.Entity{
		UID:        callerUID,
		Parents:    groupUIDs(callerGroups),
		Attributes: types.NewRecord(types.RecordMap{"name": types.String(caller)}),
	}

	for _, group := range callerGroups {
		uid := types.NewEntityUID(TypeGroup, types.String(group))
		entities[uid] = types.Entity{UID: uid}
	}

	// Every capability group is declared whether or not this command belongs to
	// one, so a policy naming a group parses and evaluates the same way on every
	// request.
	for _, group := range AllGroups() {
		uid := types.NewEntityUID(TypeAction, types.String(group))
		entities[uid] = types.Entity{UID: uid}
	}

	action := actionUID(inv)
	entities[action] = types.Entity{
		UID:     action,
		Parents: actionGroupUIDs(strings.Join(inv.Command.Path, " ")),
	}

	resource := resourceUID(target)
	if _, exists := entities[resource]; !exists {
		attrs := types.RecordMap{}
		if target.Kind == TargetSandbox {
			attrs["name"] = types.String(target.Name)
		}
		targetGroups := a.groupsFor(target.Name)
		entities[resource] = types.Entity{
			UID:        resource,
			Parents:    groupUIDs(targetGroups),
			Attributes: types.NewRecord(attrs),
		}
		for _, group := range targetGroups {
			uid := types.NewEntityUID(TypeGroup, types.String(group))
			if _, declared := entities[uid]; !declared {
				entities[uid] = types.Entity{UID: uid}
			}
		}
	}

	return entities
}

func groupUIDs(groups []string) types.EntityUIDSet {
	uids := make([]types.EntityUID, 0, len(groups))
	for _, group := range groups {
		uids = append(uids, types.NewEntityUID(TypeGroup, types.String(group)))
	}
	return types.NewEntityUIDSet(uids...)
}

func actionGroupUIDs(path string) types.EntityUIDSet {
	groups := Groups(path)
	uids := make([]types.EntityUID, 0, len(groups))
	for _, group := range groups {
		uids = append(uids, types.NewEntityUID(TypeAction, types.String(group)))
	}
	return types.NewEntityUIDSet(uids...)
}
