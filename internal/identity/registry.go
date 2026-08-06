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
//
// The file, not this struct, is the registry. Every read consults it and every
// write re-reads it first, because the process that retires a token is not the
// one enforcing it: "sbx-warden revoke" and "sbx-warden grant" are short-lived
// commands, and a server holding a snapshot from its own start-up would keep
// honouring tokens that were retired minutes ago.
type Registry struct {
	path string

	mu  sync.Mutex
	min map[string]int
}

// DefaultRegistryPath returns the conventional registry location,
// $SBX_WARDEN_REGISTRY_FILE when set and ~/.sbx-warden/generations.json otherwise.
func DefaultRegistryPath() (string, error) {
	if p := os.Getenv("SBX_WARDEN_REGISTRY_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".sbx-warden", "generations.json"), nil
}

// OpenRegistry reads the registry at path. A missing file opens an empty
// registry, which is written on the first Record.
func OpenRegistry(path string) (*Registry, error) {
	reg := &Registry{path: path, min: map[string]int{}}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if err := reg.reload(); err != nil {
		return nil, err
	}
	return reg, nil
}

// reload replaces the in-memory view with the file's contents. The caller holds
// mu.
//
// A missing file is an empty registry rather than an error, which is what makes
// "nothing has been revoked" the state of a host that has never revoked
// anything. Any other failure is returned: a registry that exists but cannot be
// read is not evidence that a token is still current.
//
// The file is small and is read once per session rather than per byte
// transferred, so it is read every time instead of being cached behind a
// modification time. Caching would trade an unmeasurable saving for a window in
// which a retired token still works.
func (r *Registry) reload() error {
	raw, err := os.ReadFile(r.path)
	if os.IsNotExist(err) {
		r.min = map[string]int{}
		return nil
	}
	if err != nil {
		return err
	}

	loaded := map[string]int{}
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return fmt.Errorf("read generation registry %s: %w", r.path, err)
	}
	r.min = loaded
	return nil
}

// Minimum returns the lowest generation sandbox may present, or 0 when the
// sandbox has never been granted a token.
func (r *Registry) Minimum(sandbox string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.reload(); err != nil {
		return 0, err
	}
	return r.min[sandbox], nil
}

// Next returns the generation to mint for a sandbox's next token, which retires
// every token it holds today.
func (r *Registry) Next(sandbox string) (int, error) {
	minimum, err := r.Minimum(sandbox)
	if err != nil {
		return 0, err
	}
	return minimum + 1, nil
}

// Record stores generation as the lowest a sandbox may present from now on.
func (r *Registry) Record(sandbox string, generation int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.set(sandbox, generation)
}

// Revoke retires every token a sandbox holds without issuing one to replace
// them, and returns the generation now required.
//
// Raising the bar one above the recorded minimum is enough because a grant
// records the generation it minted, so the newest token a sandbox holds carries
// exactly that minimum and every older one is below it. A sandbox whose minimum
// is still zero has never been granted anything, so this only raises the bar for
// a token it might be given later.
func (r *Registry) Revoke(sandbox string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.reload(); err != nil {
		return 0, err
	}
	generation := r.min[sandbox] + 1
	if err := r.set(sandbox, generation); err != nil {
		return 0, err
	}
	return generation, nil
}

// set writes one sandbox's minimum, merging it into what the file holds now. The
// caller holds mu.
//
// Re-reading before writing is what keeps two of these from undoing each other.
// The whole map is serialized, so a writer working from a stale view would write
// back its stale idea of every other sandbox and silently restore tokens
// somebody else had just retired.
func (r *Registry) set(sandbox string, generation int) error {
	if err := r.reload(); err != nil {
		return err
	}
	r.min[sandbox] = generation

	snapshot, err := json.MarshalIndent(r.min, "", "  ")
	if err != nil {
		return fmt.Errorf("encode generation registry: %w", err)
	}
	return r.write(append(snapshot, '\n'))
}

// write replaces the registry file in one step.
//
// A partial write would leave a file that parses as neither the old registry nor
// the new one, and since unreadable is treated as unknown rather than
// unrestricted, that costs every sandbox its access until someone repairs it by
// hand. Renaming over the old file cannot be observed half-done.
func (r *Registry) write(content []byte) error {
	dir := filepath.Dir(r.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create generation registry directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".generations-*")
	if err != nil {
		return fmt.Errorf("create generation registry: %w", err)
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure generation registry: %w", err)
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return fmt.Errorf("write generation registry: %w", err)
	}
	// Durability before visibility: a rename that outlives the data it points at
	// would lose a revocation the operator was told had been recorded.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("flush generation registry: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close generation registry: %w", err)
	}
	if err := os.Rename(tmp.Name(), r.path); err != nil {
		return fmt.Errorf("replace generation registry: %w", err)
	}
	return nil
}

// Accepts reports whether a verified identity is still current. It is separate
// from Verify because a valid signature and a live grant are different
// questions: the first asks whether this server minted the token, the second
// whether the token has since been retired.
func (r *Registry) Accepts(id Identity) (bool, error) {
	minimum, err := r.Minimum(id.Sandbox)
	if err != nil {
		return false, err
	}
	return id.Generation >= minimum, nil
}
