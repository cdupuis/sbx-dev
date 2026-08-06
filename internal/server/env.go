package server

import (
	"regexp"
	"sort"
	"strings"
)

// envNamePattern is the portable shape of an environment variable name. A name
// outside it is refused rather than escaped, because a name containing "="
// would smuggle a second assignment into a single environ entry.
var envNamePattern = regexp.MustCompile(`\A[A-Za-z_][A-Za-z0-9_]*\z`)

// hijackEnv names variables that decide which code a child process runs rather
// than how it behaves. A session's requested environment arrives from a
// sandbox, so honouring one of these would let the caller aim the host's sbx at
// binaries or shared libraries it controls through a shared workspace. They
// stay refused even when an operator allows them by name.
var hijackEnv = map[string]struct{}{
	"BASH_ENV":              {},
	"DYLD_INSERT_LIBRARIES": {},
	"DYLD_LIBRARY_PATH":     {},
	"ENV":                   {},
	"IFS":                   {},
	"LD_AUDIT":              {},
	"LD_LIBRARY_PATH":       {},
	"LD_PRELOAD":            {},
	"PATH":                  {},
	"SHELL":                 {},
}

// filterEnv selects the requested variables that allow names, and reports the
// refused names so a session can say why a variable did not arrive. Entries are
// returned sorted, so a child's environment does not vary with map iteration
// order.
func filterEnv(requested map[string]string, allow map[string]struct{}) (accepted, refused []string) {
	names := make([]string, 0, len(requested))
	for name := range requested {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if !envPermitted(name, requested[name], allow) {
			refused = append(refused, name)
			continue
		}
		accepted = append(accepted, name+"="+requested[name])
	}
	return accepted, refused
}

func envPermitted(name, value string, allow map[string]struct{}) bool {
	if !envNamePattern.MatchString(name) || strings.ContainsRune(value, 0) {
		return false
	}
	if _, hijack := hijackEnv[name]; hijack {
		return false
	}
	_, ok := allow[name]
	return ok
}
