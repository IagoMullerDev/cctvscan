package credbrute

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// prependKnown must put declared credentials first, drop duplicates and leave
// both inputs untouched.
func TestPrependKnown(t *testing.T) {
	wordlist := []string{"admin:admin", "root:root"}
	known := []string{"admin:secret", "admin:admin"}

	got := prependKnown(wordlist, known)
	want := []string{"admin:secret", "admin:admin", "root:root"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if !reflect.DeepEqual(wordlist, []string{"admin:admin", "root:root"}) {
		t.Errorf("wordlist mutated: %v", wordlist)
	}
	if len(known) != 2 {
		t.Errorf("known mutated: %v", known)
	}
	if got2 := prependKnown(wordlist, nil); !reflect.DeepEqual(got2, wordlist) {
		t.Errorf("got %v, want %v", got2, wordlist)
	}
}

// A credential declared in the database must be usable even when there is no
// wordlist at all.
func TestOptimizedBruteForceKnownWithoutWordlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if ok && u == "admin" && p == "secret" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="camera"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	got := OptimizedBruteForceKnown(context.Background(), "127.0.0.1",
		[]string{srv.URL + "/login"}, filepath.Join(t.TempDir(), "missing.txt"),
		[]string{"admin:secret"}, 3*time.Second)
	if got != "admin:secret" {
		t.Errorf("got %q, want admin:secret", got)
	}
}

// basicAuthServer answers 200 only to the listed pairs and 401 to everything
// else, always with the same body.
func basicAuthServer(t *testing.T, accept func(user, pass string) bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if ok && accept(u, p) {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="camera"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A device that accepts an empty user with an empty password — the ",," entry
// of the database — must report exactly that pair.
func TestBruteForceBlankUserAndBlankPassword(t *testing.T) {
	srv := basicAuthServer(t, func(u, p string) bool { return u == "" && p == "" })

	got := OptimizedBruteForceKnown(context.Background(), "127.0.0.1",
		[]string{srv.URL + "/login"}, filepath.Join(t.TempDir(), "missing.txt"),
		[]string{":"}, 3*time.Second)
	if got != ":" {
		t.Errorf("got %q, want : (empty user and empty password)", got)
	}
}

// A device that accepts a known user with an empty password — the
// "usuario," entry — must report it.
func TestBruteForceBlankPassword(t *testing.T) {
	srv := basicAuthServer(t, func(u, p string) bool { return u == "admin" && p == "" })

	got := OptimizedBruteForceKnown(context.Background(), "127.0.0.1",
		[]string{srv.URL + "/login"}, filepath.Join(t.TempDir(), "missing.txt"),
		[]string{"admin:"}, 3*time.Second)
	if got != "admin:" {
		t.Errorf("got %q, want admin:", got)
	}
}

// A device that answers 200 to ANY password for an empty user accepts nothing
// in particular: the same answer the wrong-password baseline got, so no
// credential may be claimed for it.
func TestBruteForceDoesNotClaimBlankUserThatAcceptsAnything(t *testing.T) {
	srv := basicAuthServer(t, func(u, _ string) bool { return u == "" })

	got := OptimizedBruteForceKnown(context.Background(), "127.0.0.1",
		[]string{srv.URL + "/login"}, filepath.Join(t.TempDir(), "missing.txt"),
		[]string{":"}, 3*time.Second)
	if got != "" {
		t.Errorf("got %q, want no credential: the endpoint accepts any password", got)
	}
}

// The blank username must take part in the baseline loop like any other user.
func TestDistinctUsersIncludesBlank(t *testing.T) {
	got := distinctUsers([]string{"admin:admin", ":", "admin:12345", ":"})
	want := []string{"admin", ""}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
