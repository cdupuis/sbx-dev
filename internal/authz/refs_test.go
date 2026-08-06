package authz

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// serveMap serves a policy map and its policies over http, recording the paths
// that were requested so a test can assert what was fetched rather than only
// what was loaded. Documents are keyed by request path.
func serveMap(t *testing.T, documents map[string]string) (base string, requested func() []string) {
	t.Helper()

	var mu sync.Mutex
	var paths []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()

		body, ok := documents[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	return srv.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

func TestRemotePolicyMapResolvesPoliciesAgainstItsOwnURL(t *testing.T) {
	base, requested := serveMap(t, map[string]string{
		"/policies/policy-map.yaml": `
bindings:
  - sandboxes: "*"
    policies: read.cedar
`,
		"/policies/read.cedar": permitRead,
	})

	a, err := NewFromPolicyMap(base + "/policies/policy-map.yaml")
	require.NoError(t, err)
	require.True(t, decideWith(t, a, "worker-1", "ls").Allowed)

	// The relative reference resolved next to the map, not at the server root.
	require.Equal(t, []string{"/policies/policy-map.yaml", "/policies/read.cedar"}, requested())
}

func TestRemotePolicyIdsAreQualifiedByTheirName(t *testing.T) {
	// A diagnostic should name the policy, not repeat the URL it came from.
	base, _ := serveMap(t, map[string]string{
		"/policy-map.yaml": "bindings:\n  - sandboxes: \"*\"\n    policies: read.cedar\n",
		"/read.cedar":      permitRead,
	})

	a, err := NewFromPolicyMap(base + "/policy-map.yaml")
	require.NoError(t, err)
	require.Equal(t, []string{"read.cedar#policy0"}, decideWith(t, a, "worker-1", "ls").Policies)
}

func TestLocalPolicyMapMayNameARemotePolicy(t *testing.T) {
	base, _ := serveMap(t, map[string]string{"/read.cedar": permitRead})

	path := writeMap(t, "bindings:\n  - sandboxes: \"*\"\n    policies: "+base+"/read.cedar\n", nil)

	a, err := NewFromPolicyMap(path)
	require.NoError(t, err)
	require.True(t, decideWith(t, a, "worker-1", "ls").Allowed)
}

func TestRemotePolicyMapCannotNameALocalFile(t *testing.T) {
	// The boundary this holds: a document fetched from elsewhere decides nothing
	// about the filesystem of the host that reads it.
	local := filepath.Join(t.TempDir(), "read.cedar")
	require.NoError(t, os.WriteFile(local, []byte(permitRead), 0o600))

	base, _ := serveMap(t, map[string]string{
		"/policy-map.yaml": "bindings:\n  - sandboxes: \"*\"\n    policies: file://" + local + "\n",
	})

	_, err := NewFromPolicyMap(base + "/policy-map.yaml")
	require.ErrorContains(t, err, "may only name http and https references")
}

// An absolute path in a remote map is a path on the server that served it, which
// is what URL resolution means and what keeps it off this host.
func TestRemotePolicyMapResolvesAnAbsolutePathAgainstItsHost(t *testing.T) {
	base, requested := serveMap(t, map[string]string{
		"/nested/policy-map.yaml": "bindings:\n  - sandboxes: \"*\"\n    policies: /shared/read.cedar\n",
		"/shared/read.cedar":      permitRead,
	})

	a, err := NewFromPolicyMap(base + "/nested/policy-map.yaml")
	require.NoError(t, err)
	require.True(t, decideWith(t, a, "worker-1", "ls").Allowed)
	require.Contains(t, requested(), "/shared/read.cedar")
}

func TestRemotePolicyMapReportsAMissingPolicy(t *testing.T) {
	base, _ := serveMap(t, map[string]string{
		"/policy-map.yaml": "bindings:\n  - sandboxes: \"*\"\n    policies: absent.cedar\n",
	})

	_, err := NewFromPolicyMap(base + "/policy-map.yaml")
	require.ErrorContains(t, err, "absent.cedar")
	require.ErrorContains(t, err, "404")
}

// A server that cannot be reached must fail the load rather than yield an empty
// policy set, because starting with no rules grants more than the operator asked
// for.
func TestRemotePolicyMapReportsAnUnreachableServer(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	address := srv.URL
	srv.Close()

	_, err := NewFromPolicyMap(address + "/policy-map.yaml")
	require.ErrorContains(t, err, "read policy map")
}

func TestRemotePolicyIsRefusedRatherThanTruncated(t *testing.T) {
	// A policy cut short is not a smaller policy: the missing tail could be a
	// forbid, so an oversized document must not load at all.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "policy-map.yaml") {
			_, _ = w.Write([]byte("bindings:\n  - sandboxes: \"*\"\n    policies: big.cedar\n"))
			return
		}
		_, _ = w.Write([]byte(permitRead + strings.Repeat("\n// padding", maxRemoteSize)))
	}))
	t.Cleanup(srv.Close)

	_, err := NewFromPolicyMap(srv.URL + "/policy-map.yaml")
	require.ErrorContains(t, err, "big.cedar")
	require.ErrorContains(t, err, "larger than")
}

// Certificates are verified, so an https map cannot be served by whoever can
// answer for the name. Without this, https would only look safer than http.
func TestRemotePolicyMapVerifiesTheServerCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("bindings:\n  - sandboxes: \"*\"\n    policies: read.cedar\n"))
	}))
	t.Cleanup(srv.Close)

	_, err := NewFromPolicyMap(srv.URL + "/policy-map.yaml")
	require.ErrorContains(t, err, "certificate")
}

func TestPlaintextRefsNamesEveryDocumentReadInTheClear(t *testing.T) {
	bindings := []Binding{
		{Policies: stringList{"http://config/read.cedar", "https://config/worker.cedar", "/etc/local.cedar"}},
		{Policies: stringList{"http://config/read.cedar"}},
	}

	require.Equal(t,
		[]string{"http://config/policy-map.yaml", "http://config/read.cedar"},
		PlaintextRefs("http://config/policy-map.yaml", bindings))

	require.Empty(t, PlaintextRefs("/etc/policy-map.yaml", []Binding{
		{Policies: stringList{"https://config/read.cedar"}},
	}))
}
