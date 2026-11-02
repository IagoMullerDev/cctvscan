package eyehack

import (
	"reflect"
	"testing"
)

// The database format "ip:port,user,pass" (",," = no credential) must parse,
// merge repeated hosts and carry the declared credentials through to the
// brute-forcers.
func TestLoadHostRequestsCredSuffix(t *testing.T) {
	p := writeTemp(t, "db.txt", `# autorizados — ip:porta,user,pass

1.1.1.1:443,,
1.1.1.1:8080,admin,12345
2.2.2.2:554,admin,
3.3.3.3,root,secret
1.1.1.1:443,admin,12345
notanip:80,badline
`)
	reqs, err := LoadHostRequests(p)
	if err != nil {
		t.Fatalf("LoadHostRequests: %v", err)
	}
	if len(reqs) != 3 {
		t.Fatalf("got %d hosts, want 3: %+v", len(reqs), reqs)
	}

	one := reqs[0]
	if one.Host != "1.1.1.1" || !reflect.DeepEqual(one.Ports, []int{443, 8080}) {
		t.Errorf("1.1.1.1 = %+v, want ports [443 8080]", one)
	}
	wantOne := []Cred{{}, {User: "admin", Pass: "12345"}}
	if !reflect.DeepEqual(one.Creds, wantOne) {
		t.Errorf("1.1.1.1 creds = %+v, want %v (blank declaration kept, duplicate dropped)", one.Creds, wantOne)
	}

	two := reqs[1]
	if two.Host != "2.2.2.2" || !reflect.DeepEqual(two.Creds, []Cred{{User: "admin", Pass: ""}}) {
		t.Errorf("2.2.2.2 = %+v, want admin with empty password", two)
	}

	three := reqs[2]
	if three.Host != "3.3.3.3" || !three.Bare {
		t.Errorf("3.3.3.3 = %+v, want bare host", three)
	}
	if !reflect.DeepEqual(three.Creds, []Cred{{User: "root", Pass: "secret"}}) {
		t.Errorf("3.3.3.3 creds = %+v, want root:secret", three.Creds)
	}
}

// CredsByHost must expose every declared credential expanded into its blank
// variants, in "user:pass" form for the scanners.
func TestCredsByHost(t *testing.T) {
	p := writeTemp(t, "db.txt", "1.1.1.1:443,admin,12345\n2.2.2.2:80,,\n3.3.3.3:81,,secret\n")
	reqs, err := LoadHostRequests(p)
	if err != nil {
		t.Fatalf("LoadHostRequests: %v", err)
	}
	got := CredsByHost(reqs)
	want := map[string][]string{
		"1.1.1.1": {"admin:12345", "admin:", ":12345", ":"},
		"2.2.2.2": {":"},
		"3.3.3.3": {":secret", ":"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// Every declared pair expands to the three blank combinations.
func TestCredCandidates(t *testing.T) {
	cases := []struct {
		declared Cred
		want     []Cred
	}{
		{Cred{User: "admin", Pass: "12345"}, []Cred{
			{User: "admin", Pass: "12345"}, {User: "admin"}, {Pass: "12345"}, {},
		}},
		{Cred{User: "admin"}, []Cred{{User: "admin"}, {}}},
		{Cred{Pass: "secret"}, []Cred{{Pass: "secret"}, {}}},
		{Cred{}, []Cred{{}}},
	}
	for _, c := range cases {
		got := credCandidates(c.declared)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("credCandidates(%+v) = %v, want %v", c.declared, got, c.want)
		}
	}
}

// splitCreds keeps commas inside the password and keeps blank fields — they
// are credentials to test, not a missing credential.
func TestSplitCreds(t *testing.T) {
	cases := []struct {
		in   string
		want string
		cred *Cred
	}{
		{"1.2.3.4:80", "1.2.3.4:80", nil},
		{"1.2.3.4:80,,", "1.2.3.4:80", &Cred{}},
		{"1.2.3.4:80,,secret", "1.2.3.4:80", &Cred{Pass: "secret"}},
		{"1.2.3.4:80,admin,12345", "1.2.3.4:80", &Cred{User: "admin", Pass: "12345"}},
		{"1.2.3.4,root,a,b", "1.2.3.4", &Cred{User: "root", Pass: "a,b"}},
		{"1.2.3.4:8080,admin,", "1.2.3.4:8080", &Cred{User: "admin"}},
	}
	for _, c := range cases {
		base, cred := splitCreds(c.in)
		if base != c.want {
			t.Errorf("splitCreds(%q) base = %q, want %q", c.in, base, c.want)
		}
		if (cred == nil) != (c.cred == nil) {
			t.Errorf("splitCreds(%q) cred = %v, want %v", c.in, cred, c.cred)
			continue
		}
		if cred != nil && *cred != *c.cred {
			t.Errorf("splitCreds(%q) cred = %v, want %v", c.in, *cred, *c.cred)
		}
	}
}
