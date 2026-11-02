package credbrute

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseLoginForm(t *testing.T) {
	html := `
	<html><body>
	<form action="/cgi-bin/login.cgi" method="POST">
	  <input type="hidden" name="csrf" value="abc123">
	  <input type="text" name="username">
	  <input type="password" name="password">
	  <input type="submit" value="Login">
	</form></body></html>`

	f := parseLoginForm("http://1.2.3.4:8080/index.html", html)
	if f == nil {
		t.Fatal("expected a form")
	}
	if f.action != "http://1.2.3.4:8080/cgi-bin/login.cgi" {
		t.Errorf("action resolved to %q", f.action)
	}
	if f.userField != "username" {
		t.Errorf("userField = %q", f.userField)
	}
	if f.passField != "password" {
		t.Errorf("passField = %q", f.passField)
	}
	if !f.hadPassword {
		t.Error("hadPassword should be true")
	}
	if f.hidden["csrf"] != "abc123" {
		t.Errorf("hidden csrf = %q", f.hidden["csrf"])
	}
}

func TestParseLoginFormNoPassword(t *testing.T) {
	if f := parseLoginForm("http://x/", `<html><body>hi</body></html>`); f != nil {
		t.Errorf("expected nil without password field, got %+v", f)
	}
}

func TestParseLoginFormPickUserField(t *testing.T) {
	// No type hints, only names: should pick "user" for user and "pass" for pass.
	html := `<form><input name="user"><input name="pass" type="password"></form>`
	f := parseLoginForm("http://x/", html)
	if f == nil {
		t.Fatal("expected a form")
	}
	if f.userField != "user" {
		t.Errorf("userField = %q, want user", f.userField)
	}
	if f.passField != "pass" {
		t.Errorf("passField = %q, want pass", f.passField)
	}
}

func TestLoginSucceeded(t *testing.T) {
	withPw := &loginForm{hadPassword: true}
	noPw := &loginForm{hadPassword: false}

	cases := []struct {
		name     string
		status   int
		location string
		body     string
		form     *loginForm
		want     bool
	}{
		{"redirect to dashboard", 302, "http://x/dashboard", "", withPw, true},
		{"redirect back to login", 302, "http://x/login", "", withPw, false},
		{"401", 401, "", "", withPw, false},
		{"403", 403, "", "", withPw, false},
		{"200 form still there", 200, "", `<input type="password">`, withPw, false},
		{"200 error msg", 200, "", `Invalid password`, withPw, false},
		// A disappearing password field alone proves nothing: error pages have
		// no form either. Success must be asserted by the page.
		{"200 form gone, no success marker", 200, "", `<div>welcome</div>`, withPw, false},
		{"200 logout present", 200, "", `<div>session ok, please logout</div>`, withPw, true},
		{"200 dashboard", 200, "", `<div>camera dashboard</div>`, withPw, true},
		{"200 no pw baseline + logout", 200, "", `please logout`, noPw, true},
		{"200 no signals", 200, "", `<div>nothing here</div>`, noPw, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := loginSucceeded(c.status, c.location, c.body, c.form); got != c.want {
				t.Errorf("loginSucceeded = %v, want %v", got, c.want)
			}
		})
	}
}

func TestSplitCred(t *testing.T) {
	if u, p, ok := splitCred("admin:12345"); !ok || u != "admin" || p != "12345" {
		t.Errorf("got %q,%q,%v", u, p, ok)
	}
	if _, _, ok := splitCred("nopass"); ok {
		t.Error("expected failure for credential without colon")
	}
}

// Real Grandstream lockout page: HTTP 200, no password input, but NOT a login.
func TestLockoutIsNotSuccess(t *testing.T) {
	body := `<html><head><title>Grandstream Device Configuration</title></head>
<body><tr id="trlocked"><td>The device has been locked due to too many login errors...
Please relogin by clicking on the link below.</td></tr></body></html>`

	if !isLocked(body) {
		t.Error("expected isLocked to detect the lockout page")
	}
	form := &loginForm{hadPassword: true}
	if loginSucceeded(200, "", body, form) {
		t.Error("lockout page must NOT be reported as a successful login")
	}
	if loginSucceeded(200, "", "Invalid password, please retry", form) {
		t.Error("error page must NOT be reported as a successful login")
	}
}

func TestGrandstreamUnquotedForm(t *testing.T) {
	// Real markup from a Grandstream UCM/IPVM: no quotes around attribute values.
	html := `<form action="/cgi-bin/dologin" method="post" name="loginForm">
<input name="P2" type=password id="input-password" size=30>
<input type="submit" name="Login" value="Login">
<input name="gnkey" type=hidden value=0b82></form>`

	f := parseLoginForm("http://cam:8081/", html)
	if f == nil {
		t.Fatal("expected a form")
	}
	if f.passField != "P2" {
		t.Errorf("passField = %q, want P2", f.passField)
	}
	if f.action != "http://cam:8081/cgi-bin/dologin" {
		t.Errorf("action = %q", f.action)
	}
	if f.hidden["gnkey"] != "0b82" {
		t.Errorf("hidden gnkey = %q", f.hidden["gnkey"])
	}
	// Password-only login: no username input at all.
	if f.userField != "" {
		t.Errorf("userField = %q, want empty (password-only)", f.userField)
	}
}

// Real device (170.0.218.189:9000): the account password input has no name
// (JavaScript fills it) and the only named password input is a security code.
// Bruting that form would post to the wrong field and report bogus successes.
func TestRefusesJavaScriptOnlyPassword(t *testing.T) {
	html := `<form action="cgi-bin/main-cgi" method="post">
<input type="text" name="szUserName" />
<input type=password class="in_text" id="szUserPasswdSrc" maxlength="20" />
<input type="checkbox" name="recordPassword" />
<input type="password" id="securityCode" name="safetyCode" maxlength="10">
<input type="hidden" name="nonce" value="abc">
</form>`

	if f := parseLoginForm("http://cam:9000/", html); f != nil {
		t.Errorf("expected nil (JS-driven password), got passField=%q", f.passField)
	}
}

func TestFirstPasswordFieldWins(t *testing.T) {
	// A named security code after the real password must not become the target.
	html := `<form>
<input type="password" name="passwd">
<input type="password" name="pinCode">
</form>`
	f := parseLoginForm("http://cam/", html)
	if f == nil {
		t.Fatal("expected a form")
	}
	if f.passField != "passwd" {
		t.Errorf("passField = %q, want passwd (first password input)", f.passField)
	}
}

func TestSameOutcomeGuardsFalsePositive(t *testing.T) {
	// The endpoint answers this exact body no matter what we send.
	const body = `<html><head><meta http-equiv="refresh" content="0;url=../index.html"></head></html>`

	baseline := respFP{status: 200, body: body}
	candidate := respFP{status: 200, body: body}
	if !sameOutcome(candidate, baseline) {
		t.Error("identical responses must be treated as the same outcome (failure)")
	}

	// A genuinely different page is a different outcome.
	other := respFP{status: 200, body: `<html><body>Welcome admin <a href="logout">Logout</a></body></html>`}
	if sameOutcome(other, baseline) {
		t.Error("different bodies must not be treated as the same outcome")
	}

	// A status change is always a different outcome.
	if sameOutcome(respFP{status: 302, location: "/main", body: body}, baseline) {
		t.Error("a redirect must not be treated as the same outcome")
	}
}

func TestNormalizeBodyIgnoresDynamicTokens(t *testing.T) {
	a := `<html>session 7f3a9c21e5 token 1791207028 ok</html>`
	b := `<html>session 9b17d4f0aa token 1791209999 ok</html>`
	if normalizeBody(a) != normalizeBody(b) {
		t.Errorf("dynamic tokens must normalize equal:\n%q\n%q", normalizeBody(a), normalizeBody(b))
	}
}

// Real response from 138.204.44.82:8081 /cgi-bin/dologin for a WRONG password.
// HTTP 200, no password input — everything the old heuristic treated as a win.
func TestGrandstreamWrongPasswordIsFailure(t *testing.T) {
	body := `<table><tr><td>
	 your login password is not recognized,<br> or you do not have access privilege. Please try again. <br>
	 Remaining Attempts: 2 </font></b></div></td></tr></table>`

	if isLocked(body) {
		t.Error("attempt 2 is not a lockout yet")
	}
	if loginSucceeded(200, "", body, &loginForm{hadPassword: true}) {
		t.Error("Grandstream wrong-password page must not be reported as success")
	}
}

// Between the baseline and a later failed try, the only difference was the
// attempt counter. That must not read as a different authentication outcome.
func TestAttemptCounterIsNotADifferentOutcome(t *testing.T) {
	const tmpl = `<div>your login password is not recognized. Remaining Attempts: %d </div>`
	base := respFP{status: 200, body: fmt.Sprintf(tmpl, 2)}
	next := respFP{status: 200, body: fmt.Sprintf(tmpl, 1)}
	if !sameOutcome(next, base) {
		t.Error("attempt counters must normalize equal, or every failed try looks like a win")
	}
}

// Some devices answer 200/401 at random regardless of the credentials sent.
// A single baseline cannot catch that, so two baselines must disagree first.
func TestBasicUnstableEndpointYieldsNothing(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1)%2 == 0 {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	got := bruteBasicURL(context.Background(), srv.Client(), srv.URL, []string{"admin:admin", "admin:12345"})
	if got != "" {
		t.Errorf("bruteBasicURL = %q, want \"\" (status does not depend on credentials)", got)
	}
}

// A stable endpoint that returns 200 with the same body to everyone must never
// yield a credential, even though the status looks like a success.
func TestBasicAlways200SameBodyYieldsNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html>17 bytes of nope</html>`)
	}))
	defer srv.Close()

	got := bruteBasicURL(context.Background(), srv.Client(), srv.URL, []string{"admin:admin", "admin:12345"})
	if got != "" {
		t.Errorf("bruteBasicURL = %q, want \"\" (identical to baseline)", got)
	}
}

// Regression: a device answers 401 to an unknown user but 200 to ANY password
// for a user it recognises. Compared only against the impossible-user baseline,
// the first candidate for that user looks like a hit. The per-username baseline
// (same username, wrong password) must reject it.
func TestBasicRejectsAnyPasswordForKnownUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _, ok := r.BasicAuth()
		if ok && u == "admin" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "stream open")
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="cam"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	got := bruteBasicURL(context.Background(), srv.Client(), srv.URL,
		[]string{"admin:12345", "admin:admin", "root:root"})
	if got != "" {
		t.Errorf("bruteBasicURL = %q, want \"\" — the password is never checked here", got)
	}
}

// Positive control: an endpoint that genuinely validates the password must
// still yield it, so the fix above is not simply too strict.
func TestBasicFindsValidatedPassword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if ok && u == "admin" && p == "s3cret" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "welcome to the dashboard")
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="cam"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	got := bruteBasicURL(context.Background(), srv.Client(), srv.URL,
		[]string{"admin:wrong", "admin:s3cret"})
	if got != "admin:s3cret" {
		t.Errorf("bruteBasicURL = %q, want admin:s3cret", got)
	}
}

// The same regression on the form path: the failure page for an unknown user
// differs from the success page a known user gets with any password, so the
// impossible-user baseline passes and loginSucceeded fires — unless the
// candidate is held against the same username carrying a wrong password.
func TestFormRejectsAnyPasswordForKnownUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `<html><form method="POST">
				<input type="text" name="username">
				<input type="password" name="password"></form></html>`)
			return
		}
		_ = r.ParseForm()
		if r.FormValue("username") == "admin" {
			// Success page: affirmative marker, no password field left.
			fmt.Fprint(w, `<html><a href="/logout">Log out</a><div>Welcome back admin</div></html>`)
			return
		}
		fmt.Fprint(w, `<html><form method="POST">
			<input type="password" name="password"></form>Invalid user</html>`)
	}))
	defer srv.Close()

	got := bruteFormURL(context.Background(), srv.Client(), srv.URL+"/login",
		[]string{"admin:12345", "admin:admin"}, 3*time.Second)
	if got != "" {
		t.Errorf("bruteFormURL = %q, want \"\" — the password is never checked here", got)
	}
}
