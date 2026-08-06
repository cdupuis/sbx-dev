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

func accepts(t *testing.T, reg *Registry, sandbox string, generation int) bool {
	t.Helper()
	ok, err := reg.Accepts(Identity{Sandbox: sandbox, Generation: generation})
	require.NoError(t, err)
	return ok
}

func minimum(t *testing.T, reg *Registry, sandbox string) int {
	t.Helper()
	got, err := reg.Minimum(sandbox)
	require.NoError(t, err)
	return got
}

func next(t *testing.T, reg *Registry, sandbox string) int {
	t.Helper()
	got, err := reg.Next(sandbox)
	require.NoError(t, err)
	return got
}

func TestRegistryAcceptsEveryTokenBeforeAnyGrant(t *testing.T) {
	reg, _ := openTestRegistry(t)

	// An empty registry means nothing has been revoked, so a verified token is
	// current. Identity does not depend on this file.
	require.True(t, accepts(t, reg, "worker-1", 1))
	require.Zero(t, minimum(t, reg, "worker-1"))
	require.Equal(t, 1, next(t, reg, "worker-1"))
}

func TestRegistryRetiresGenerationsBelowTheRecordedOne(t *testing.T) {
	reg, _ := openTestRegistry(t)
	require.NoError(t, reg.Record("worker-1", 3))

	require.False(t, accepts(t, reg, "worker-1", 2))
	require.True(t, accepts(t, reg, "worker-1", 3))
	require.Equal(t, 4, next(t, reg, "worker-1"))
}

func TestRegistryTracksSandboxesSeparately(t *testing.T) {
	reg, _ := openTestRegistry(t)
	require.NoError(t, reg.Record("worker-1", 5))

	require.True(t, accepts(t, reg, "worker-2", 1),
		"retiring one sandbox's token must not affect another's")
}

func TestRegistrySurvivesReopening(t *testing.T) {
	reg, path := openTestRegistry(t)
	require.NoError(t, reg.Record("worker-1", 2))

	reopened, err := OpenRegistry(path)
	require.NoError(t, err)
	require.Equal(t, 2, minimum(t, reopened, "worker-1"))

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

func TestRegistrySeesWhatAnotherProcessRevoked(t *testing.T) {
	// The server holds its registry for its whole life while "revoke" is a
	// separate short-lived command, so a decision made from a start-up snapshot
	// would keep honouring a token that was retired minutes ago.
	serverSide, path := openTestRegistry(t)
	require.NoError(t, serverSide.Record("worker-1", 1))
	require.True(t, accepts(t, serverSide, "worker-1", 1))

	revokeSide, err := OpenRegistry(path)
	require.NoError(t, err)
	generation, err := revokeSide.Revoke("worker-1")
	require.NoError(t, err)
	require.Equal(t, 2, generation)

	require.False(t, accepts(t, serverSide, "worker-1", 1),
		"the token must stop being current without reopening the registry")
}

func TestRegistryRevokeLeavesNoUsableGeneration(t *testing.T) {
	reg, _ := openTestRegistry(t)
	require.NoError(t, reg.Record("worker-1", 4))

	generation, err := reg.Revoke("worker-1")
	require.NoError(t, err)
	require.Equal(t, 5, generation)

	require.False(t, accepts(t, reg, "worker-1", 4), "the token it held is retired")
	require.True(t, accepts(t, reg, "worker-1", 5), "and only a token nobody holds would pass")

	// Revoking reserves nothing, so the next grant simply mints above the bar it
	// raised. Generations are a counter, not an inventory.
	require.Equal(t, 6, next(t, reg, "worker-1"))
}

func TestRegistryRevokeOnAnUngrantedSandboxRetiresNothing(t *testing.T) {
	reg, _ := openTestRegistry(t)

	generation, err := reg.Revoke("never-granted")
	require.NoError(t, err)
	require.Equal(t, 1, generation)

	// Nothing was outstanding to retire, which is why a minimum of zero is the
	// signal that a name was never granted rather than that it was revoked.
	require.True(t, accepts(t, reg, "never-granted", 1))
	require.True(t, accepts(t, reg, "other", 1), "and no other sandbox is touched")
}

func TestRegistryWriteDoesNotUndoAnotherWriter(t *testing.T) {
	// Both hold a view of the whole file, so a writer working from a stale one
	// would write back its stale idea of every other sandbox.
	first, path := openTestRegistry(t)
	second, err := OpenRegistry(path)
	require.NoError(t, err)

	require.NoError(t, first.Record("worker-1", 7))
	require.NoError(t, second.Record("worker-2", 3))

	reopened, err := OpenRegistry(path)
	require.NoError(t, err)
	require.Equal(t, 7, minimum(t, reopened, "worker-1"), "the first writer's revocation must survive")
	require.Equal(t, 3, minimum(t, reopened, "worker-2"))
}

func TestRegistryReportsAFileItCannotRead(t *testing.T) {
	reg, path := openTestRegistry(t)
	require.NoError(t, reg.Record("worker-1", 2))

	require.NoError(t, os.WriteFile(path, []byte("{truncated"), 0o600))

	_, err := reg.Accepts(Identity{Sandbox: "worker-1", Generation: 2})
	require.Error(t, err, "an unreadable registry is not evidence that a token is current")

	_, err = reg.Minimum("worker-1")
	require.Error(t, err)
}

func TestRegistryTreatsADeletedFileAsNothingRevoked(t *testing.T) {
	reg, path := openTestRegistry(t)
	require.NoError(t, reg.Record("worker-1", 3))
	require.False(t, accepts(t, reg, "worker-1", 1))

	require.NoError(t, os.Remove(path))

	// Documented behaviour: absent means nothing was ever revoked. Worth pinning
	// down, because it is the difference between deleting this file locking every
	// sandbox out and restoring every retired token.
	require.True(t, accepts(t, reg, "worker-1", 1))
}

func TestRegistryLeavesNoTemporaryFilesBehind(t *testing.T) {
	reg, path := openTestRegistry(t)
	require.NoError(t, reg.Record("worker-1", 1))
	require.NoError(t, reg.Record("worker-2", 1))

	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1, "the replacement is renamed over the registry, not left beside it")
	require.Equal(t, filepath.Base(path), entries[0].Name())
}
