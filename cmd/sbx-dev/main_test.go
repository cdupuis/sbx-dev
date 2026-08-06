package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGitHubRawNamesAFileInTheModulesRepository(t *testing.T) {
	url, ok := gitHubRaw("github.com/owner/repo", "main", "policies/policy-map.yaml")
	require.True(t, ok)
	require.Equal(t, "https://raw.githubusercontent.com/owner/repo/main/policies/policy-map.yaml", url)

	// A major-version suffix belongs to the module path, not the repository.
	v2, ok := gitHubRaw("github.com/owner/repo/v2", "main", "f")
	require.True(t, ok)
	require.Equal(t, "https://raw.githubusercontent.com/owner/repo/main/f", v2)
}

func TestGitHubRawDeclinesWhatItCannotName(t *testing.T) {
	for _, module := range []string{
		"gitlab.com/owner/repo",
		"example.com/owner/repo",
		"github.com/owner",
		"github.com/owner/repo/nested",
		"",
	} {
		_, ok := gitHubRaw(module, "main", "f")
		require.False(t, ok, "module %q", module)
	}
}

// The default is derived from the module path, so it follows a fork instead of
// pinning every build to one repository. It also has to keep naming a file that
// exists: moving the shipped map without updating this would leave every default
// install fetching a 404.
func TestDefaultPolicyMapNamesTheShippedMap(t *testing.T) {
	require.Equal(t,
		"https://raw.githubusercontent.com/cdupuis/sbx-dev/main/"+shippedPolicyMap,
		defaultPolicyMap())

	require.FileExists(t, filepath.Join("..", "..", shippedPolicyMap))
}

func TestCheckBindAcceptsLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:7391", "[::1]:7391", "localhost:7391", "127.0.0.1:0"} {
		require.NoError(t, checkBind(addr, false), "addr %s", addr)
	}
}

func TestCheckBindRejectsNonLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:7391", "192.168.1.10:7391", "[::]:7391"} {
		require.Error(t, checkBind(addr, false), "addr %s must be refused without --allow-any-bind", addr)
	}
}

func TestCheckBindRejectsMissingHost(t *testing.T) {
	require.ErrorContains(t, checkBind(":7391", false), "explicit host")
}

func TestCheckBindHonoursOverride(t *testing.T) {
	require.NoError(t, checkBind("0.0.0.0:7391", true))
}

func TestStringListSplitsOnComma(t *testing.T) {
	var l stringList
	require.NoError(t, l.Set("create, exec ,,ls"))
	require.Equal(t, stringList{"create", "exec", "ls"}, l)
	require.NoError(t, l.Set("ps"))
	require.Equal(t, stringList{"create", "exec", "ls", "ps"}, l)
}
