// Package identity mints and verifies the tokens that tell an sbx-dev server
// which sandbox is calling it.
//
// A token names its sandbox and authenticates that name with an HMAC over a
// host-held key, so the server learns the caller's identity from the token
// alone: there is no token store to consult and no way to enumerate sandboxes
// from a token. A sandbox never holds its own token — the egress proxy
// substitutes it into the request from a host-side credential — so a caller can
// neither read its token nor forge another sandbox's.
package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// tokenVersion prefixes every token so the format can change without a server
// mistaking an old token for a malformed one.
const tokenVersion = "v1"

// keySize is the HMAC key length in bytes, matching SHA-256's block-independent
// recommendation of at least the digest size.
const keySize = 32

// namePattern is the sandbox name shape sbx accepts, which follows Docker
// container naming. Names may contain dots, so a token is parsed from the right
// where the generation and MAC fields are fixed in position.
var namePattern = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\z`)

// ErrMalformed reports a token that is not in the expected format. It is
// deliberately indistinguishable in effect from a bad MAC: a caller learns only
// that the token was rejected.
var ErrMalformed = errors.New("malformed token")

// ErrUnauthenticated reports a token whose MAC does not match the server's key.
var ErrUnauthenticated = errors.New("token is not signed by this server")

// Key is the host-held secret that signs every token.
type Key []byte

// NewKey returns a freshly generated key.
func NewKey() (Key, error) {
	buf := make([]byte, keySize)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate identity key: %w", err)
	}
	return buf, nil
}

// DefaultKeyPath returns the conventional key location, $SBX_DEV_KEY_FILE when
// set and ~/.sbx-dev/identity.key otherwise.
func DefaultKeyPath() (string, error) {
	if p := os.Getenv("SBX_DEV_KEY_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".sbx-dev", "identity.key"), nil
}

// LoadOrCreateKey reads the key at path, generating and persisting one if the
// file does not exist. The file is written 0600 in a 0700 directory: whoever
// holds it can mint a token for any sandbox.
func LoadOrCreateKey(path string) (Key, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		key, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if decodeErr != nil {
			return nil, fmt.Errorf("identity key %s is not valid base64: %w", path, decodeErr)
		}
		if len(key) != keySize {
			return nil, fmt.Errorf("identity key %s is %d bytes, want %d", path, len(key), keySize)
		}
		return key, nil
	case !os.IsNotExist(err):
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create identity key directory: %w", err)
	}
	key, err := NewKey()
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(key) + "\n"
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return nil, fmt.Errorf("write identity key: %w", err)
	}
	return key, nil
}

// Identity is the caller a verified token names.
type Identity struct {
	// Sandbox is the sandbox name the token was minted for.
	Sandbox string
	// Generation increments when a sandbox's token is reissued, so an operator
	// can retire an earlier one without rotating the key for every sandbox.
	Generation int
}

// Mint returns the token for a sandbox at a generation. Generation must be
// positive; pass 1 for a sandbox's first token.
func (k Key) Mint(sandbox string, generation int) (string, error) {
	if len(k) != keySize {
		return "", fmt.Errorf("identity key is %d bytes, want %d", len(k), keySize)
	}
	if !namePattern.MatchString(sandbox) {
		return "", fmt.Errorf("%q is not a valid sandbox name", sandbox)
	}
	if generation < 1 {
		return "", fmt.Errorf("generation must be positive, got %d", generation)
	}
	gen := strconv.Itoa(generation)
	return strings.Join([]string{tokenVersion, sandbox, gen, k.mac(sandbox, gen)}, "."), nil
}

// Verify returns the identity a token names, or an error if the token is
// malformed or was not signed by this key.
func (k Key) Verify(token string) (Identity, error) {
	version, sandbox, gen, mac, err := splitToken(token)
	if err != nil {
		return Identity{}, err
	}
	if version != tokenVersion {
		return Identity{}, fmt.Errorf("%w: unsupported version %q", ErrMalformed, version)
	}
	if !namePattern.MatchString(sandbox) {
		return Identity{}, fmt.Errorf("%w: invalid sandbox name", ErrMalformed)
	}
	generation, err := strconv.Atoi(gen)
	if err != nil || generation < 1 {
		return Identity{}, fmt.Errorf("%w: invalid generation", ErrMalformed)
	}
	if !hmac.Equal([]byte(mac), []byte(k.mac(sandbox, gen))) {
		return Identity{}, ErrUnauthenticated
	}
	return Identity{Sandbox: sandbox, Generation: generation}, nil
}

// splitToken separates a token from the right, so a sandbox name containing
// dots stays intact.
func splitToken(token string) (version, sandbox, generation, mac string, err error) {
	rest, mac, found := cutLast(token, ".")
	if !found {
		return "", "", "", "", fmt.Errorf("%w: too few fields", ErrMalformed)
	}
	rest, generation, found = cutLast(rest, ".")
	if !found {
		return "", "", "", "", fmt.Errorf("%w: too few fields", ErrMalformed)
	}
	version, sandbox, found = strings.Cut(rest, ".")
	if !found || sandbox == "" {
		return "", "", "", "", fmt.Errorf("%w: too few fields", ErrMalformed)
	}
	return version, sandbox, generation, mac, nil
}

func cutLast(s, sep string) (before, after string, found bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}

// mac binds the version, sandbox and generation together, so a token minted for
// one sandbox cannot be replayed as another by moving fields around.
func (k Key) mac(sandbox, generation string) string {
	h := hmac.New(sha256.New, k)
	// namePattern excludes "/", so the separators here delimit the fields
	// unambiguously and no two distinct inputs share a signed message.
	h.Write([]byte("sbx-dev/" + tokenVersion + "/" + sandbox + "/" + generation))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
