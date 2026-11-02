package camrecon

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The credentials declared for a host in the database must come first in the
// pwneye pools, followed by the shared wordlist pools (duplicates dropped).
func TestMergePwneyePools(t *testing.T) {
	dir := t.TempDir()
	usersFile := filepath.Join(dir, "pool-users.txt")
	passesFile := filepath.Join(dir, "pool-passes.txt")
	if err := os.WriteFile(usersFile, []byte("admin\nroot\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passesFile, []byte("admin\n12345\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "out")
	u, p, err := MergePwneyePools("1.2.3.4",
		[]string{"admin:known", "operator:", "admin:admin"},
		usersFile, passesFile, out)
	if err != nil {
		t.Fatalf("MergePwneyePools: %v", err)
	}

	gotUsers := strings.Split(strings.TrimSpace(readAll(t, u)), "\n")
	if want := []string{"admin", "operator", "root"}; !reflect.DeepEqual(gotUsers, want) {
		t.Errorf("users = %v, want %v", gotUsers, want)
	}
	// "operator:" carries an empty password: it is not a pwneye password.
	gotPasses := strings.Split(strings.TrimSpace(readAll(t, p)), "\n")
	if want := []string{"known", "admin", "12345"}; !reflect.DeepEqual(gotPasses, want) {
		t.Errorf("passes = %v, want %v", gotPasses, want)
	}
}

// Pools are optional: known credentials alone are enough to build them.
func TestMergePwneyePoolsWithoutSharedPools(t *testing.T) {
	dir := t.TempDir()
	u, p, err := MergePwneyePools("1.2.3.4", []string{"admin:12345"},
		filepath.Join(dir, "missing-users.txt"), "", filepath.Join(dir, "out"))
	if err != nil {
		t.Fatalf("MergePwneyePools: %v", err)
	}
	if got := strings.TrimSpace(readAll(t, u)); got != "admin" {
		t.Errorf("users = %q, want admin", got)
	}
	if got := strings.TrimSpace(readAll(t, p)); got != "12345" {
		t.Errorf("passes = %q, want 12345", got)
	}
}

// A credential with a blank user still contributes its password: pwneye
// crosses the pools, so the password is tried with every username.
func TestMergePwneyePoolsBlankUser(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	u, p, err := MergePwneyePools("1.2.3.4", []string{":secret", ":"},
		"", filepath.Join(dir, "missing-passes.txt"), out)
	if err != nil {
		t.Fatalf("MergePwneyePools: %v", err)
	}
	if u != "" {
		t.Errorf("users file = %q, want none (pwneye falls back to its common usernames)", u)
	}
	if got := strings.TrimSpace(readAll(t, p)); got != "secret" {
		t.Errorf("passes = %q, want secret", got)
	}
}

// A blank user with a blank password cannot be expressed in pools: the shared
// pools are returned untouched (and no error is raised for a database line
// that declares only ",,").
func TestMergePwneyePoolsBlankOnly(t *testing.T) {
	dir := t.TempDir()
	usersFile := filepath.Join(dir, "pool-users.txt")
	passesFile := filepath.Join(dir, "pool-passes.txt")
	if err := os.WriteFile(usersFile, []byte("admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passesFile, []byte("admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	u, p, err := MergePwneyePools("1.2.3.4", []string{":"}, usersFile, passesFile, filepath.Join(dir, "out"))
	if err != nil {
		t.Fatalf("MergePwneyePools: %v", err)
	}
	if u != usersFile || p != passesFile {
		t.Errorf("got (%q, %q), want the shared pools unchanged", u, p)
	}
	if _, err := os.Stat(filepath.Join(dir, "out")); !os.IsNotExist(err) {
		t.Error("no per-host pool should be written for a blank-only declaration")
	}
}

func readAll(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}
