package identity

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) Key {
	t.Helper()
	key, err := NewKey()
	require.NoError(t, err)
	return key
}

func TestMintRoundTrip(t *testing.T) {
	key := testKey(t)

	token, err := key.Mint("worker-1", 1)
	require.NoError(t, err)

	got, err := key.Verify(token)
	require.NoError(t, err)
	require.Equal(t, Identity{Sandbox: "worker-1", Generation: 1}, got)
}

func TestTokenNamesItsSandboxWithoutALookup(t *testing.T) {
	key := testKey(t)

	token, err := key.Mint("orchestrator", 3)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(token, "v1.orchestrator.3."),
		"the sandbox and generation are readable from the token: %s", token)
}

func TestVerifyAcceptsSandboxNamesContainingDots(t *testing.T) {
	// Docker naming allows dots, and the token delimiter is also a dot, so
	// parsing has to survive a name that contains one.
	key := testKey(t)

	token, err := key.Mint("api.example.com", 2)
	require.NoError(t, err)

	got, err := key.Verify(token)
	require.NoError(t, err)
	require.Equal(t, Identity{Sandbox: "api.example.com", Generation: 2}, got)
}

func TestVerifyRejectsATokenFromAnotherKey(t *testing.T) {
	token, err := testKey(t).Mint("worker-1", 1)
	require.NoError(t, err)

	_, err = testKey(t).Verify(token)
	require.ErrorIs(t, err, ErrUnauthenticated)
}

func TestVerifyRejectsARenamedSandbox(t *testing.T) {
	// The MAC covers the name, so swapping it for a more privileged sandbox
	// invalidates the token rather than escalating.
	key := testKey(t)
	token, err := key.Mint("worker-1", 1)
	require.NoError(t, err)

	forged := strings.Replace(token, "worker-1", "orchestrator", 1)
	_, err = key.Verify(forged)
	require.ErrorIs(t, err, ErrUnauthenticated)
}

func TestVerifyRejectsARaisedGeneration(t *testing.T) {
	key := testKey(t)
	token, err := key.Mint("worker-1", 1)
	require.NoError(t, err)

	_, err = key.Verify(strings.Replace(token, ".1.", ".2.", 1))
	require.ErrorIs(t, err, ErrUnauthenticated)
}

func TestVerifyRejectsMalformedTokens(t *testing.T) {
	key := testKey(t)
	valid, err := key.Mint("worker-1", 1)
	require.NoError(t, err)
	mac := valid[strings.LastIndex(valid, ".")+1:]

	for name, token := range map[string]string{
		"empty":             "",
		"no separator":      "v1",
		"two fields":        "v1.worker-1",
		"three fields":      "v1.worker-1.1",
		"empty sandbox":     "v1..1." + mac,
		"wrong version":     "v2.worker-1.1." + mac,
		"zero generation":   "v1.worker-1.0." + mac,
		"negative":          "v1.worker-1.-1." + mac,
		"unparsed gen":      "v1.worker-1.one." + mac,
		"illegal name":      "v1.worker 1.1." + mac,
		"placeholder value": "sbx-cs-abc123",
	} {
		_, err := key.Verify(token)
		require.Error(t, err, "%s must be rejected", name)
	}
}

func TestMintRejectsInvalidInput(t *testing.T) {
	key := testKey(t)

	_, err := key.Mint("", 1)
	require.ErrorContains(t, err, "not a valid sandbox name")

	_, err = key.Mint("has space", 1)
	require.ErrorContains(t, err, "not a valid sandbox name")

	_, err = key.Mint("worker-1", 0)
	require.ErrorContains(t, err, "generation must be positive")
}

func TestLoadOrCreateKeyPersistsOneKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "identity.key")

	first, err := LoadOrCreateKey(path)
	require.NoError(t, err)
	require.Len(t, first, keySize)

	second, err := LoadOrCreateKey(path)
	require.NoError(t, err)
	require.Equal(t, first, second, "a second call must reuse the stored key")

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"the key mints tokens for every sandbox, so it must not be group or world readable")
}

func TestLoadOrCreateKeyRejectsACorruptFile(t *testing.T) {
	dir := t.TempDir()

	notBase64 := filepath.Join(dir, "bad.key")
	require.NoError(t, os.WriteFile(notBase64, []byte("not base64!"), 0o600))
	_, err := LoadOrCreateKey(notBase64)
	require.ErrorContains(t, err, "not valid base64")

	tooShort := filepath.Join(dir, "short.key")
	require.NoError(t, os.WriteFile(tooShort, []byte(base64.StdEncoding.EncodeToString([]byte("short"))), 0o600))
	_, err = LoadOrCreateKey(tooShort)
	require.ErrorContains(t, err, "want 32")
}
