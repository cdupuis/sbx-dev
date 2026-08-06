package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Registry records the lowest token generation each sandbox may still present.
//
// A token authenticates itself, so identifying a caller needs no lookup here.
// The registry exists only to retire a token that leaked — for instance to a
// host-side service that logged the header the proxy injected. An absent or
// empty registry therefore means "nothing has been revoked" and never blocks a
// caller.
type Registry struct {
	path string

	mu  sync.Mutex
	min map[string]int
}

// DefaultRegistryPath returns the conventional registry location,
// $SBX_DEV_REGISTRY_FILE when set and ~/.sbx-dev/generations.json otherwise.
func DefaultRegistryPath() (string, error) {
	if p := os.Getenv("SBX_DEV_REGISTRY_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".sbx-dev", "generations.json"), nil
}

// OpenRegistry reads the registry at path. A missing file opens an empty
// registry, which is written on the first Record.
func OpenRegistry(path string) (*Registry, error) {
	reg := &Registry{path: path, min: map[string]int{}}

	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return reg, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &reg.min); err != nil {
		return nil, fmt.Errorf("read generation registry %s: %w", path, err)
	}
	return reg, nil
}

// Minimum returns the lowest generation sandbox may present, or 0 when the
// sandbox has never been granted a token.
func (r *Registry) Minimum(sandbox string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.min[sandbox]
}

// Next returns the generation to mint for a sandbox's next token, which retires
// every token it holds today.
func (r *Registry) Next(sandbox string) int {
	return r.Minimum(sandbox) + 1
}

// Record stores generation as the lowest a sandbox may present from now on.
func (r *Registry) Record(sandbox string, generation int) error {
	r.mu.Lock()
	r.min[sandbox] = generation
	snapshot, err := json.MarshalIndent(r.min, "", "  ")
	r.mu.Unlock()
	if err != nil {
		return fmt.Errorf("encode generation registry: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return fmt.Errorf("create generation registry directory: %w", err)
	}
	return os.WriteFile(r.path, append(snapshot, '\n'), 0o600)
}

// Accepts reports whether a verified identity is still current. It is separate
// from Verify because a valid signature and a live grant are different
// questions: the first asks whether this server minted the token, the second
// whether the token has since been retired.
func (r *Registry) Accepts(id Identity) bool {
	return id.Generation >= r.Minimum(id.Sandbox)
}
