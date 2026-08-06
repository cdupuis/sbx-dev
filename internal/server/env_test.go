package server

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func allowSet(names ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		set[name] = struct{}{}
	}
	return set
}

func TestFilterEnvAcceptsOnlyAllowedNames(t *testing.T) {
	accepted, refused := filterEnv(
		map[string]string{"WANTED": "yes", "OTHER": "no"},
		allowSet("WANTED"),
	)

	require.Equal(t, []string{"WANTED=yes"}, accepted)
	require.Equal(t, []string{"OTHER"}, refused)
}

func TestFilterEnvAcceptsNothingByDefault(t *testing.T) {
	accepted, refused := filterEnv(map[string]string{"ANYTHING": "value"}, nil)

	require.Empty(t, accepted)
	require.Equal(t, []string{"ANYTHING"}, refused)
}

func TestFilterEnvRefusesHijackNamesEvenWhenAllowed(t *testing.T) {
	// A session that can set these picks which binaries and libraries the
	// host's sbx loads, so an operator cannot opt into them by mistake.
	for name := range hijackEnv {
		accepted, refused := filterEnv(map[string]string{name: "/tmp/attacker"}, allowSet(name))

		require.Empty(t, accepted, "%s must never reach the child", name)
		require.Equal(t, []string{name}, refused)
	}
}

func TestFilterEnvRefusesNamesThatCouldSmuggleAssignments(t *testing.T) {
	// "A=B" as a name would render as the entry "A=B=C", setting A to "B=C".
	// A NUL in a value truncates the entry the child receives.
	requested := map[string]string{
		"A=B":       "C",
		"has space": "v",
		"1LEADING":  "v",
		"":          "v",
		"NUL":       "va\x00lue",
	}
	accepted, refused := filterEnv(requested, allowSet("A=B", "has space", "1LEADING", "", "NUL"))

	require.Empty(t, accepted)
	require.Len(t, refused, len(requested))
}

func TestFilterEnvOrdersEntriesDeterministically(t *testing.T) {
	accepted, _ := filterEnv(
		map[string]string{"C": "3", "A": "1", "B": "2"},
		allowSet("A", "B", "C"),
	)

	require.Equal(t, []string{"A=1", "B=2", "C=3"}, accepted)
}

func TestNewRejectsHijackNamesInAllowEnv(t *testing.T) {
	_, err := New(Config{
		IdentityKey: testKey,
		SbxPath:     "sh",
		AllowEnv:    []string{"PATH"},
		Logger:      slog.New(slog.DiscardHandler),
	})

	require.ErrorContains(t, err, "refusing to forward PATH")
}

func TestNewRejectsMalformedAllowEnvName(t *testing.T) {
	_, err := New(Config{
		IdentityKey: testKey,
		SbxPath:     "sh",
		AllowEnv:    []string{"not a name"},
		Logger:      slog.New(slog.DiscardHandler),
	})

	require.ErrorContains(t, err, "not a valid environment variable name")
}
