package authz

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cedar-policy/cedar-go/types"

	"github.com/cdupuis/sbx-warden/internal/catalog"
	"github.com/cdupuis/sbx-warden/internal/resolve"
)

// sandboxRef matches the "sandbox:/path" form sbx cp accepts on either side. The
// name must not begin with a separator or a dot, so an ordinary path that
// happens to contain a colon is still read as a path.
var sandboxRef = regexp.MustCompile(`\A([A-Za-z0-9][A-Za-z0-9_.-]*):(/.*)\z`)

// namedSandboxes lists every sandbox an invocation acts on, in the order a
// resource is chosen from: the --sandbox flag, then positional sandbox
// arguments, then the "sandbox:/path" references sbx cp accepts. The last of
// those is why this is not simply a positional lookup — cp names its sandbox
// inside a path, and a policy that could not see it could not confine cp at all.
func namedSandboxes(inv *resolve.Invocation) []string {
	var names []string
	if name, ok := inv.Flag("sandbox"); ok && name != "" {
		names = append(names, name)
	}
	names = append(names, inv.ValuesOfKind(catalog.KindSandbox)...)
	for _, value := range inv.ValuesOfKind(catalog.KindPath) {
		if match := sandboxRef.FindStringSubmatch(value); match != nil {
			names = append(names, match[1])
		}
	}
	return dedupe(names)
}

// targetsOnly reports whether a command names at least one sandbox and every
// sandbox it names is the caller.
//
// Naming a sibling alongside itself is not "itself". A variadic command such as
// "sbx rm self other" would otherwise satisfy a self-only rule while acting on
// both, because a resource can only be one entity and the first name would win.
func targetsOnly(names []string, caller string) bool {
	if caller == "" || len(names) == 0 {
		return false
	}
	for _, name := range names {
		if name != caller {
			return false
		}
	}
	return true
}

// buildContext describes an invocation to a policy.
//
// Everything here is derived from a parse the server performed, never from a
// claim the caller made. Host paths are resolved against the directory the
// server runs commands in and cleaned, so a policy comparing prefixes cannot be
// walked out of with "..".
func buildContext(inv *resolve.Invocation, caller string, target Target, workdir string) types.Record {
	hostPaths, sandboxPaths := splitPaths(inv.ValuesOfKind(catalog.KindPath), workdir)

	return types.NewRecord(types.RecordMap{
		"command":    types.String(inv.Name()),
		"flags":      stringSet(inv.FlagNames()),
		"flagValues": flagValues(inv),
		"hostPaths":  stringSet(hostPaths),
		// Cedar has no way to test every member of a set, so confinement is
		// expressed against the deepest directory containing all the host paths
		// a command named: that directory lies under a prefix exactly when all
		// of the paths do.
		"hostPathsRoot": types.String(commonAncestor(hostPaths)),
		// Confinement to the server's own working directory, which a policy
		// cannot express for itself: Cedar cannot build a "like" pattern out of
		// another value, so a portable rule needs the comparison done here.
		"hostPathsUnderWorkdir": types.Boolean(allUnder(hostPaths, workdir)),
		"sandboxes":             stringSet(inv.ValuesOfKind(catalog.KindSandbox)),
		"references":            stringSet(inv.ValuesOfKind(catalog.KindReference)),
		"network":               stringSet(inv.ValuesOfKind(catalog.KindNetwork)),
		"targetsSelf":           types.Boolean(targetsOnly(namedSandboxes(inv), caller)),
		"targetsHost":           types.Boolean(target.Kind == TargetHost),
		// A pass-through argument is opaque to sbx, so a policy can see that
		// arguments were forwarded but must not be invited to match on them as
		// though sbx interpreted them.
		"forwardsArguments": types.Boolean(len(inv.PassThrough) > 0),
		// A path inside a sandbox is not a host path, but a policy may still
		// want to know one was named.
		"sandboxPaths": stringSet(sandboxPaths),
	})
}

// splitPaths separates the host paths a command names from the sandbox-relative
// ones, canonicalising the host paths.
func splitPaths(values []string, workdir string) (host, sandbox []string) {
	for _, value := range values {
		if match := sandboxRef.FindStringSubmatch(value); match != nil {
			sandbox = append(sandbox, value)
			continue
		}
		host = append(host, canonicalPath(value, workdir))
	}
	return host, sandbox
}

// canonicalPath resolves a path the way the command will see it: relative paths
// against the directory the server runs sbx in, and "." elements removed.
func canonicalPath(value, workdir string) string {
	if !filepath.IsAbs(value) {
		value = filepath.Join(workdir, value)
	}
	return filepath.Clean(value)
}

// allUnder reports whether every path is root or below it. Paths are already
// canonical, so a "..": cannot walk out. A command that named no host path is
// confined by definition, and one with no workdir to compare against is not.
func allUnder(paths []string, root string) bool {
	if root == "" {
		return false
	}
	root = filepath.Clean(root)
	for _, p := range paths {
		if p == root {
			continue
		}
		if !strings.HasPrefix(p, root+string(filepath.Separator)) {
			return false
		}
	}
	return true
}

// commonAncestor returns the deepest directory containing every path, or an
// empty string when there are none. A single path is its own ancestor, so a
// policy can compare one path and many the same way.
func commonAncestor(paths []string) string {
	if len(paths) == 0 {
		return ""
	}

	shared := strings.Split(paths[0], string(filepath.Separator))
	for _, path := range paths[1:] {
		parts := strings.Split(path, string(filepath.Separator))
		if len(parts) < len(shared) {
			shared = shared[:len(parts)]
		}
		for i := range shared {
			if parts[i] != shared[i] {
				shared = shared[:i]
				break
			}
		}
	}

	joined := strings.Join(shared, string(filepath.Separator))
	if joined == "" {
		return string(filepath.Separator)
	}
	return joined
}

func stringSet(values []string) types.Set {
	unique := make([]types.Value, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		unique = append(unique, types.String(value))
	}
	return types.NewSet(unique...)
}

// flagValues exposes the value sbx will read for each flag. A repeatable flag
// keeps every value, joined, because a policy that saw only the last one would
// miss the rest.
func flagValues(inv *resolve.Invocation) types.Record {
	values := make(types.RecordMap, len(inv.Flags))
	for name, given := range inv.Flags {
		values[types.String(name)] = types.String(strings.Join(given, ","))
	}
	return types.NewRecord(values)
}
