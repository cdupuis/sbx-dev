package grant

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cdupuis/sbx-dev/internal/identity"
)

// fakeSbx writes the arguments it was given and the value it read on stdin to
// separate files, then exits with exitCode.
func fakeSbx(t *testing.T, dir string, exitCode int) (path, argsFile, stdinFile string) {
	t.Helper()

	path = filepath.Join(dir, "sbx")
	argsFile = filepath.Join(dir, "args")
	stdinFile = filepath.Join(dir, "stdin")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" > " + argsFile + "\ncat > " + stdinFile + "\nexit " + strconv.Itoa(exitCode) + "\n"
	require.NoError(t, os.WriteFile(path, []byte(script), 0o700))
	return path, argsFile, stdinFile
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return strings.TrimSpace(string(raw))
}

func testConfig(t *testing.T, sbxPath string) Config {
	t.Helper()

	key, err := identity.NewKey()
	require.NoError(t, err)
	registry, err := identity.OpenRegistry(filepath.Join(t.TempDir(), "generations.json"))
	require.NoError(t, err)

	return Config{Sandbox: "worker-1", SbxPath: sbxPath, Key: key, Registry: registry, ViaProxy: true}
}

func TestRunPrintsTheTokenForDeliveryAtCreation(t *testing.T) {
	sbxPath, argsFile, _ := fakeSbx(t, t.TempDir(), 0)
	cfg := testConfig(t, sbxPath)
	cfg.ViaProxy = false

	var out bytes.Buffer
	require.NoError(t, Run(context.Background(), &out, cfg))

	require.Contains(t, out.String(), "--env SBX_DEV_TOKEN=v1.worker-1.1.")
	require.NoFileExists(t, argsFile, "printing a token must not touch sbx's secret store")
}

func TestRunRegistersASandboxScopedSecret(t *testing.T) {
	sbxPath, argsFile, stdinFile := fakeSbx(t, t.TempDir(), 0)
	cfg := testConfig(t, sbxPath)

	var out bytes.Buffer
	require.NoError(t, Run(context.Background(), &out, cfg))
	require.NotContains(t, out.String(), readFile(t, stdinFile),
		"a proxy-delivered token stays out of the operator's terminal")

	// Scoping is the whole point: a global secret would give every sandbox the
	// same token and erase the identity this grant establishes.
	require.Equal(t,
		"secret set-custom --sandbox=worker-1 --host=localhost --env=SBX_DEV_TOKEN --placeholder=sbx-dev-worker-1",
		readFile(t, argsFile))

	token := readFile(t, stdinFile)
	got, err := cfg.Key.Verify(token)
	require.NoError(t, err)
	require.Equal(t, identity.Identity{Sandbox: "worker-1", Generation: 1}, got)
}

func TestRunKeepsTheTokenOutOfArgv(t *testing.T) {
	sbxPath, argsFile, stdinFile := fakeSbx(t, t.TempDir(), 0)
	cfg := testConfig(t, sbxPath)

	require.NoError(t, Run(context.Background(), &bytes.Buffer{}, cfg))

	// argv is readable by other processes on the host, so the token travels on
	// stdin instead.
	token := readFile(t, stdinFile)
	require.NotEmpty(t, token)
	require.NotContains(t, readFile(t, argsFile), token)
}

func TestRunRetiresTheEarlierGeneration(t *testing.T) {
	sbxPath, _, stdinFile := fakeSbx(t, t.TempDir(), 0)
	cfg := testConfig(t, sbxPath)

	require.NoError(t, Run(context.Background(), &bytes.Buffer{}, cfg))
	first, err := cfg.Key.Verify(readFile(t, stdinFile))
	require.NoError(t, err)

	var out bytes.Buffer
	require.NoError(t, Run(context.Background(), &out, cfg))
	second, err := cfg.Key.Verify(readFile(t, stdinFile))
	require.NoError(t, err)

	require.Equal(t, first.Generation+1, second.Generation)
	require.True(t, cfg.Registry.Accepts(second))
	require.False(t, cfg.Registry.Accepts(first), "the replaced token must stop authenticating")
	require.Contains(t, out.String(), "no longer authenticate")
}

func TestRunHonoursAnExplicitGeneration(t *testing.T) {
	sbxPath, _, stdinFile := fakeSbx(t, t.TempDir(), 0)
	cfg := testConfig(t, sbxPath)
	cfg.Generation = 7

	require.NoError(t, Run(context.Background(), &bytes.Buffer{}, cfg))

	got, err := cfg.Key.Verify(readFile(t, stdinFile))
	require.NoError(t, err)
	require.Equal(t, 7, got.Generation)
}

func TestRunLeavesTheCurrentTokenAliveWhenSbxFails(t *testing.T) {
	sbxPath, _, _ := fakeSbx(t, t.TempDir(), 1)
	cfg := testConfig(t, sbxPath)
	require.NoError(t, cfg.Registry.Record("worker-1", 4))

	err := Run(context.Background(), &bytes.Buffer{}, cfg)
	require.ErrorContains(t, err, "register the token with sbx")

	// A grant that never reached sbx must not retire the generation the sandbox
	// is still using.
	require.Equal(t, 4, cfg.Registry.Minimum("worker-1"))
}

func TestRunRequiresASandboxName(t *testing.T) {
	cfg := testConfig(t, "/bin/true")
	cfg.Sandbox = ""

	require.ErrorContains(t, Run(context.Background(), &bytes.Buffer{}, cfg), "sandbox name is required")
}

func TestRunRejectsAnInvalidSandboxName(t *testing.T) {
	sbxPath, _, _ := fakeSbx(t, t.TempDir(), 0)
	cfg := testConfig(t, sbxPath)
	cfg.Sandbox = "not a name"

	require.Error(t, Run(context.Background(), &bytes.Buffer{}, cfg))
}
