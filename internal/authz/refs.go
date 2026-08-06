package authz

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// A policy map and the policies it binds may live on the host or behind http, so
// that a fleet of servers can share one set of rules instead of each keeping a
// copy that drifts.
//
// Either way a document is named by a reference: a URL, or a path on the host. A
// relative reference inside a map resolves against the map's own location — the
// enclosing directory for a path, the enclosing URL for a URL — so a map and its
// policies move as a unit.

// fetchTimeout bounds one remote read. Policies load while the server starts and
// before the listener opens, so an unreachable host has to fail rather than hang.
const fetchTimeout = 10 * time.Second

// maxRemoteSize caps a remote document. A truncated policy is not a smaller
// policy — it could be one whose forbid was cut off — so exceeding the cap is an
// error rather than a partial read.
const maxRemoteSize = 1 << 20

// remoteClient reads remote references, pooling connections across the several
// documents a map usually names.
var remoteClient = &http.Client{Timeout: fetchTimeout}

// isRemote reports whether a reference is read over http.
//
// The scheme is matched literally rather than by parsing, because a Windows path
// such as `C:\policies` parses as a URL whose scheme is "c".
func isRemote(ref string) bool {
	lower := strings.ToLower(ref)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// resolveRef resolves a reference found inside a policy map against the map.
//
// A remote map resolves its references as URLs, which is what keeps it from
// reaching the host reading it: `/etc/shadow` in a map served over https names a
// path on that server, not on this one. A scheme that is neither http nor https
// is refused for the same reason, so a remote map cannot name a local file.
func resolveRef(mapRef, ref string) (string, error) {
	if isRemote(ref) {
		return ref, nil
	}
	if !isRemote(mapRef) {
		if filepath.IsAbs(ref) {
			return ref, nil
		}
		return filepath.Join(filepath.Dir(mapRef), ref), nil
	}

	base, err := url.Parse(mapRef)
	if err != nil {
		return "", fmt.Errorf("%s is not a valid URL: %w", mapRef, err)
	}
	relative, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid reference: %w", ref, err)
	}

	resolved := base.ResolveReference(relative).String()
	if !isRemote(resolved) {
		return "", fmt.Errorf("%q resolves to %s, and a policy map served over http may only name http and https references", ref, resolved)
	}
	return resolved, nil
}

// readRef reads a policy map or a policy.
func readRef(ref string) ([]byte, error) {
	if !isRemote(ref) {
		return os.ReadFile(ref)
	}

	resp, err := remoteClient.Get(ref)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", ref, resp.Status)
	}

	// Reading one byte past the cap is what tells a document that fits from one
	// that would have been cut short.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", ref, err)
	}
	if len(body) > maxRemoteSize {
		return nil, fmt.Errorf("%s is larger than the %d byte limit for a remote policy", ref, maxRemoteSize)
	}
	return body, nil
}

// refName is the short name a policy's ids are qualified with, so a diagnostic
// can name the file that decided without repeating a whole URL.
func refName(ref string) string {
	if !isRemote(ref) {
		return filepath.Base(ref)
	}
	parsed, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	if name := path.Base(parsed.Path); name != "" && name != "." && name != "/" {
		return name
	}
	return ref
}

// PlaintextRefs reports which of a map's references are read over plaintext
// http.
//
// A server says so at startup rather than refusing: whoever can answer or
// intercept those requests chooses what every sandbox may do, which is a
// different proposition from serving the same rules over https.
func PlaintextRefs(mapRef string, bindings []Binding) []string {
	var plaintext []string
	if isPlaintext(mapRef) {
		plaintext = append(plaintext, mapRef)
	}
	for _, binding := range bindings {
		for _, policy := range binding.Policies {
			if isPlaintext(policy) {
				plaintext = append(plaintext, policy)
			}
		}
	}
	return dedupe(plaintext)
}

func isPlaintext(ref string) bool {
	return strings.HasPrefix(strings.ToLower(ref), "http://")
}
