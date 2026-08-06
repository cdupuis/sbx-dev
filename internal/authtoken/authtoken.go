// Package authtoken creates, stores and compares the shared secret that
// authenticates sbx clients to an sbx-dev server.
package authtoken

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultPath returns the conventional token location, $SBX_DEV_TOKEN_FILE when
// set and ~/.sbx-dev/token otherwise.
func DefaultPath() (string, error) {
	if p := os.Getenv("SBX_DEV_TOKEN_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".sbx-dev", "token"), nil
}

// Generate returns a new 256-bit token as a hex string.
func Generate() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// Load reads a token from path, trimming surrounding whitespace.
func Load(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}
	return token, nil
}

// LoadOrCreate reads the token at path, generating and persisting a new one if
// the file does not exist. The file is written 0600 in a 0700 directory because
// it grants full control of the host's sbx CLI.
func LoadOrCreate(path string) (string, error) {
	token, err := Load(path)
	if err == nil {
		return token, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create token directory: %w", err)
	}
	token, err = Generate()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write token file: %w", err)
	}
	return token, nil
}

// Equal compares two tokens without leaking their contents through timing.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
