package identity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func openTestRegistry(t *testing.T) (*Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nested", "generations.json")
	reg, err := OpenRegistry(path)
	require.NoError(t, err)
	return reg, path
}

func TestRegistryAcceptsEveryTokenBeforeAnyGrant(t *testing.T) {
	reg, _ := openTestRegistry(t)

	// An empty registry means nothing has been revoked, so a verified token is
	// current. Identity does not depend on this file.
	require.True(t, reg.Accepts(Identity{Sandbox: "worker-1", Generation: 1}))
	require.Zero(t, reg.Minimum("worker-1"))
	require.Equal(t, 1, reg.Next("worker-1"))
}

func TestRegistryRetiresGenerationsBelowTheRecordedOne(t *testing.T) {
	reg, _ := openTestRegistry(t)
	require.NoError(t, reg.Record("worker-1", 3))

	require.False(t, reg.Accepts(Identity{Sandbox: "worker-1", Generation: 2}))
	require.True(t, reg.Accepts(Identity{Sandbox: "worker-1", Generation: 3}))
	require.Equal(t, 4, reg.Next("worker-1"))
}

func TestRegistryTracksSandboxesSeparately(t *testing.T) {
	reg, _ := openTestRegistry(t)
	require.NoError(t, reg.Record("worker-1", 5))

	require.True(t, reg.Accepts(Identity{Sandbox: "worker-2", Generation: 1}),
		"retiring one sandbox's token must not affect another's")
}

func TestRegistrySurvivesReopening(t *testing.T) {
	reg, path := openTestRegistry(t)
	require.NoError(t, reg.Record("worker-1", 2))

	reopened, err := OpenRegistry(path)
	require.NoError(t, err)
	require.Equal(t, 2, reopened.Minimum("worker-1"))

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestOpenRegistryRejectsACorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "generations.json")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))

	_, err := OpenRegistry(path)
	require.ErrorContains(t, err, "read generation registry")
}
