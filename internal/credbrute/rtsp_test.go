package credbrute

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- digest math -----------------------------------------------------------

// RFC 2617 §3.5 reference vector.
func TestDigestResponseRFC2617(t *testing.T) {
	ch := &rtspChallenge{scheme: "digest", realm: "testrealm@host.com",
		nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093", qop: "auth"}

	got := digestResponse("GET", "/dir/index.html", ch,
		"Mufasa", "Circle Of Life", "0a4f113b", "00000001")
	if want := "6629fae49393a05397450978507c4ef1"; got != want {
		t.Errorf("digestResponse = %s, want %s", got, want)
	}

	// Without qop the response is HA1:nonce:HA2 (the common RTSP form).
	ch2 := &rtspChallenge{scheme: "digest", realm: "testrealm@host.com",
		nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093"}
	got2 := digestResponse("GET", "/dir/index.html", ch2,
		"Mufasa", "Circle Of Life", "0a4f113b", "00000001")
	if want := "670fd8c2df070c60b045671b8b24ff02"; got2 != want {
		t.Errorf("digestResponse(no qop) = %s, want %s", got2, want)
	}
}

func TestParseWWWAuthenticate(t *testing.T) {
	t.Run("digest quoted", func(t *testing.T) {
		ch := parseWWWAuthenticate(`Digest realm="IP Camera", nonce="abc123", qop="auth,auth-int", algorithm=MD5, opaque="deadbeef"`)
		if ch == nil {
			t.Fatal("nil challenge")
		}
		if ch.scheme != "digest" || ch.realm != "IP Camera" || ch.nonce != "abc123" {
			t.Errorf("got %+v", ch)
		}
		if ch.qop != "auth,auth-int" || ch.algorithm != "MD5" || ch.opaque != "deadbeef" {
			t.Errorf("got %+v", ch)
		}
		if firstQOP(ch.qop) != "auth" {
			t.Errorf("firstQOP = %q, want auth", firstQOP(ch.qop))
		}
	})

	t.Run("digest without quotes", func(t *testing.T) {
		ch := parseWWWAuthenticate(`Digest realm=cam, nonce=n1`)
		if ch == nil || ch.realm != "cam" || ch.nonce != "n1" {
			t.Errorf("got %+v", ch)
		}
	})

	t.Run("basic", func(t *testing.T) {
		ch := parseWWWAuthenticate(`Basic realm="NVR"`)
		if ch == nil || ch.scheme != "basic" || ch.realm != "NVR" {
			t.Errorf("got %+v", ch)
		}
	})

	t.Run("empty", func(t *testing.T) {
		if ch := parseWWWAuthenticate(""); ch != nil {
			t.Errorf("want nil, got %+v", ch)
		}
	})
}

func TestPickChallengePrefersDigest(t *testing.T) {
	got := pickChallenge([]string{`Basic realm="x"`, `Digest realm="y", nonce="n"`})
	if got == nil || got.scheme != "digest" || got.nonce != "n" {
		t.Errorf("got %+v, want digest", got)
	}
}

func TestGroupRTSPURLs(t *testing.T) {
	groups := GroupRTSPURLs([]string{
		"rtsp://1.2.3.4:554/live",
		"rtsp://1.2.3.4/live", // default port, same endpoint
		"rtsp://1.2.3.4/live", // duplicate path
		"rtsp://1.2.3.4/h264",
		"rtsp://5.6.7.8:8554/x",
		"http://9.9.9.9/nope", // not rtsp
	})
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2: %v", len(groups), groups)
	}
	a := groups["1.2.3.4:554"]
	if len(a) != 2 {
		t.Errorf("1.2.3.4 paths = %v, want 2 distinct", a)
	}
	if len(groups["5.6.7.8:8554"]) != 1 {
		t.Errorf("5.6.7.8 paths = %v", groups["5.6.7.8:8554"])
	}
}

// --- fake RTSP server ------------------------------------------------------

type rtspReq struct{ method, uri, auth string }

// startRTSP runs a one-request-per-connection RTSP server for the tests.
func startRTSP(t *testing.T, h func(rtspReq) (int, []string, string)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(conn)

				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				var req rtspReq
				if f := strings.Fields(strings.TrimRight(line, "\r\n")); len(f) >= 2 {
					req.method, req.uri = f[0], f[1]
				}
				for {
					h2, err := br.ReadString('\n')
					if err != nil {
						return
					}
					h2 = strings.TrimRight(h2, "\r\n")
					if h2 == "" {
						break
					}
					if i := strings.IndexByte(h2, ':'); i > 0 {
						if strings.EqualFold(strings.TrimSpace(h2[:i]), "authorization") {
							req.auth = strings.TrimSpace(h2[i+1:])
						}
					}
				}

				status, auths, body := h(req)
				var out strings.Builder
				out.WriteString(fmt.Sprintf("RTSP/1.0 %d %s\r\nCSeq: 1\r\n", status, statusText(status)))
				for _, a := range auths {
					out.WriteString("WWW-Authenticate: " + a + "\r\n")
				}
				out.WriteString(fmt.Sprintf("Content-Length: %d\r\nConnection: close\r\n\r\n", len(body)))
				out.WriteString(body)
				_, _ = conn.Write([]byte(out.String()))
			}(c)
		}
	}()
	return ln.Addr().String()
}

func statusText(s int) string {
	switch s {
	case 200:
		return "OK"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	}
	return "Status"
}

const (
	testRealm = "IP Camera"
	testNonce = "aabbccddeeff00112233445566778899"
)

// checkDigest recomputes the digest response the way a camera would.
func checkDigest(auth, method, uri, wantUser, wantPass string) bool {
	if !strings.HasPrefix(auth, "Digest ") {
		return false
	}
	quoted := func(k string) string {
		m := regexp.MustCompile(k + `="([^"]*)"`).FindStringSubmatch(auth)
		if m == nil {
			return ""
		}
		return m[1]
	}
	unquoted := func(k string) string {
		m := regexp.MustCompile(`(?i)\b` + k + `=([^,\s]+)`).FindStringSubmatch(auth)
		if m == nil {
			return ""
		}
		return strings.Trim(m[1], `"`)
	}
	user, resp := quoted("username"), quoted("response")
	if user != wantUser {
		return false
	}
	ch := &rtspChallenge{scheme: "digest", realm: testRealm, nonce: testNonce, qop: "auth"}
	return digestResponse(method, uri, ch, user, wantPass, quoted("cnonce"), unquoted("nc")) == resp
}

func writeCreds(t *testing.T, creds []string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "creds.txt")
	if err := os.WriteFile(p, []byte(strings.Join(creds, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write creds: %v", err)
	}
	return p
}

// --- integration -----------------------------------------------------------

// A camera that validates the digest properly must yield the credential.
func TestRTSPFindsCredential(t *testing.T) {
	addr := startRTSP(t, func(r rtspReq) (int, []string, string) {
		if r.auth == "" {
			return 401, []string{fmt.Sprintf(`Digest realm="%s", nonce="%s", qop="auth"`, testRealm, testNonce)}, ""
		}
		if checkDigest(r.auth, r.method, r.uri, "admin", "secret123") {
			return 200, nil, "v=0\r\n"
		}
		return 401, []string{fmt.Sprintf(`Digest realm="%s", nonce="%s", qop="auth"`, testRealm, testNonce)}, ""
	})

	creds := writeCreds(t, []string{"admin:wrong", "root:root", "admin:secret123", "admin:12345"})
	res := RTSPBruteForce(context.Background(),
		[]string{"rtsp://" + addr + "/live"}, creds, 3*time.Second)

	if res.Outcome != RTSPCreds {
		t.Fatalf("outcome = %s (%s), want creds", res.Outcome, res.Note)
	}
	if res.Credential != "admin:secret123" {
		t.Errorf("credential = %q, want admin:secret123", res.Credential)
	}
	if res.Attempts != 3 {
		t.Errorf("attempts = %d, want 3 (stops at the first hit)", res.Attempts)
	}
}

// A camera that answers 401 to everything must never yield a credential —
// this is the exact shape of the earlier false positives.
func TestRTSPRejectsAlways401(t *testing.T) {
	auth := fmt.Sprintf(`Digest realm="%s", nonce="%s", qop="auth"`, testRealm, testNonce)
	addr := startRTSP(t, func(rtspReq) (int, []string, string) {
		return 401, []string{auth}, ""
	})

	creds := writeCreds(t, []string{"admin:admin", "admin:12345"})
	res := RTSPBruteForce(context.Background(),
		[]string{"rtsp://" + addr + "/live"}, creds, 3*time.Second)

	if res.Outcome == RTSPCreds {
		t.Fatalf("must not report credentials on an endpoint that never accepts anything: %+v", res)
	}
	if res.Attempts == 0 {
		t.Error("expected the brute loop to actually run")
	}
}

// Challenges unauthenticated requests but accepts ANY credential afterwards:
// the baseline already returns 200, so nothing may be claimed.
func TestRTSPRejectsBaselineThatSucceeds(t *testing.T) {
	auth := fmt.Sprintf(`Digest realm="%s", nonce="%s", qop="auth"`, testRealm, testNonce)
	addr := startRTSP(t, func(r rtspReq) (int, []string, string) {
		if r.auth == "" {
			return 401, []string{auth}, ""
		}
		return 200, nil, "v=0\r\n"
	})

	creds := writeCreds(t, []string{"admin:admin"})
	res := RTSPBruteForce(context.Background(),
		[]string{"rtsp://" + addr + "/live"}, creds, 3*time.Second)

	if res.Outcome != RTSPUnstable {
		t.Errorf("outcome = %s (%s), want unstable", res.Outcome, res.Note)
	}
	if res.Credential != "" {
		t.Errorf("credential = %q, want none", res.Credential)
	}
}

// Status code that does not depend on what we sent: two baselines disagree.
func TestRTSPRejectsFlakyEndpoint(t *testing.T) {
	auth := fmt.Sprintf(`Digest realm="%s", nonce="%s"`, testRealm, testNonce)
	var n int
	var mu sync.Mutex
	addr := startRTSP(t, func(rtspReq) (int, []string, string) {
		mu.Lock()
		n++
		mu.Unlock()
		if n%2 == 1 {
			return 401, []string{auth}, ""
		}
		return 200, nil, ""
	})

	creds := writeCreds(t, []string{"admin:admin"})
	res := RTSPBruteForce(context.Background(),
		[]string{"rtsp://" + addr + "/live"}, creds, 3*time.Second)

	if res.Outcome != RTSPUnstable {
		t.Errorf("outcome = %s (%s), want unstable", res.Outcome, res.Note)
	}
	if res.Credential != "" {
		t.Errorf("credential = %q, want none", res.Credential)
	}
}

// Regression: 186.216.35.129 rejects unknown usernames with 401 but accepts
// ANY password for "admin". An impossible-username baseline passes the stability
// check, so the first admin candidate looked like a hit and was reported as
// credentials. The per-username baseline must catch it.
func TestRTSPRejectsAnyPasswordForKnownUser(t *testing.T) {
	auth := func() string {
		return fmt.Sprintf(`Digest realm="%s", nonce="%s", qop="auth"`, testRealm, testNonce)
	}
	// 401 unless the Authorization names the user we know, regardless of password.
	addr := startRTSP(t, func(r rtspReq) (int, []string, string) {
		if r.auth == "" {
			return 401, []string{auth()}, ""
		}
		if strings.Contains(r.auth, `username="admin"`) {
			return 200, nil, "v=0\r\n"
		}
		return 401, []string{auth()}, ""
	})

	creds := writeCreds(t, []string{"admin:12345", "admin:admin", "root:root"})
	res := RTSPBruteForce(context.Background(),
		[]string{"rtsp://" + addr + "/Streaming/Channels/1"}, creds, 3*time.Second)

	if res.Outcome != RTSPAnyPassword {
		t.Errorf("outcome = %s (%s), want any_password", res.Outcome, res.Note)
	}
	if res.Credential != "" {
		t.Errorf("credential = %q — must not claim one when the password is never checked", res.Credential)
	}
}

// An open stream needs no credentials at all.
func TestRTSPPublicStream(t *testing.T) {
	addr := startRTSP(t, func(rtspReq) (int, []string, string) {
		return 200, nil, "v=0\r\n"
	})

	res := RTSPBruteForce(context.Background(),
		[]string{"rtsp://" + addr + "/live"}, writeCreds(t, []string{"a:b"}), 3*time.Second)
	if res.Outcome != RTSPPublic {
		t.Errorf("outcome = %s (%s), want public", res.Outcome, res.Note)
	}
}

// A lockout must stop the run instead of hammering the device further.
func TestRTSPLockoutStopsAttempts(t *testing.T) {
	auth := fmt.Sprintf(`Digest realm="%s", nonce="%s"`, testRealm, testNonce)
	addr := startRTSP(t, func(rtspReq) (int, []string, string) {
		return 401, []string{auth}, "The device has been locked due to too many login errors."
	})

	res := RTSPBruteForce(context.Background(),
		[]string{"rtsp://" + addr + "/live"}, writeCreds(t, []string{"a:b", "c:d", "e:f"}), 3*time.Second)
	if res.Outcome != RTSPLocked {
		t.Errorf("outcome = %s, want locked", res.Outcome)
	}
	if res.Attempts != 1 {
		t.Errorf("attempts = %d, want 1 (stop immediately)", res.Attempts)
	}
}

// An unreachable endpoint must not be reported as anything.
func TestRTSPUnreachable(t *testing.T) {
	res := RTSPBruteForce(context.Background(),
		[]string{"rtsp://127.0.0.1:1/live"}, writeCreds(t, []string{"a:b"}), time.Second)
	if res.Outcome != RTSPNone && res.Outcome != RTSPError {
		t.Errorf("outcome = %s, want none/error", res.Outcome)
	}
	if res.Credential != "" {
		t.Errorf("credential = %q on an unreachable host", res.Credential)
	}
}

// Regression: 45.160.26.32:554 runs an HTTP server, not RTSP. Reading its
// HTTP/1.1 200 as an RTSP status line made it look like an open stream.
func TestNonRTSPReplyIsNotAPublicStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html>not an rtsp server</html>")
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	res := RTSPBruteForce(context.Background(),
		[]string{"rtsp://" + addr + "/live"}, writeCreds(t, []string{"a:b"}), 3*time.Second)

	if res.Outcome == RTSPPublic {
		t.Errorf("outcome = public — an HTTP server on the RTSP port is not an open stream")
	}
	if res.Credential != "" {
		t.Errorf("credential = %q on a non-RTSP endpoint", res.Credential)
	}
}

// A 200 that still carries a WWW-Authenticate challenge contradicts itself
// (45.227.112.228:554 does this); it is not evidence of an open stream.
func TestRTSP200WithChallengeIsNotPublic(t *testing.T) {
	auth := fmt.Sprintf(`Digest realm="%s", nonce="%s"`, testRealm, testNonce)
	addr := startRTSP(t, func(rtspReq) (int, []string, string) {
		return 200, []string{auth}, ""
	})

	res := RTSPBruteForce(context.Background(),
		[]string{"rtsp://" + addr + "/live"}, writeCreds(t, []string{"a:b"}), 3*time.Second)

	if res.Outcome != RTSPUnstable {
		t.Errorf("outcome = %s (%s), want unstable", res.Outcome, res.Note)
	}
	if res.Credential != "" {
		t.Errorf("credential = %q, want none", res.Credential)
	}
}

func TestBruteRTSPBatch(t *testing.T) {
	auth := fmt.Sprintf(`Digest realm="%s", nonce="%s", qop="auth"`, testRealm, testNonce)
	addr := startRTSP(t, func(r rtspReq) (int, []string, string) {
		if r.auth != "" && checkDigest(r.auth, r.method, r.uri, "admin", "ok") {
			return 200, nil, ""
		}
		return 401, []string{auth}, ""
	})

	creds := writeCreds(t, []string{"admin:nope", "admin:ok"})
	groups := map[string][]string{
		addr: {"rtsp://" + addr + "/live", "rtsp://" + addr + "/h264"},
	}

	var seen []RTSPResult
	res := BruteRTSPBatch(context.Background(), groups, creds, 3*time.Second, 4,
		func(r RTSPResult) { seen = append(seen, r) })

	if len(res) != 1 || len(seen) != 1 {
		t.Fatalf("results = %d, callbacks = %d, want 1/1", len(res), len(seen))
	}
	if res[0].Outcome != RTSPCreds || res[0].Credential != "admin:ok" {
		t.Errorf("got %+v", res[0])
	}
}

// 172.233.27.101:10554 answered 200 without credentials once and 401 the next
// time. A single successful DESCRIBE does not make a stream open, so "public"
// needs the same double check everything else gets.
func TestRTSPFlakyUnauthenticatedAnswerIsNotPublic(t *testing.T) {
	auth := fmt.Sprintf(`Digest realm="%s", nonce="%s"`, testRealm, testNonce)
	var n int
	var mu sync.Mutex
	addr := startRTSP(t, func(rtspReq) (int, []string, string) {
		mu.Lock()
		first := n == 0
		n++
		mu.Unlock()
		if first {
			return 200, nil, "v=0\r\n"
		}
		return 401, []string{auth}, ""
	})

	res := RTSPBruteForce(context.Background(),
		[]string{"rtsp://" + addr + "/live"}, writeCreds(t, []string{"a:b"}), 3*time.Second)

	if res.Outcome == RTSPPublic {
		t.Errorf("outcome = public — the endpoint answers 200 once and 401 afterwards")
	}
	if res.Credential != "" {
		t.Errorf("credential = %q, want none", res.Credential)
	}
}

// A camera whose account has an empty password (the "usuario," entry of the
// database) must yield that pair, even with no wordlist around.
func TestRTSPBruteForceBlankPassword(t *testing.T) {
	auth := fmt.Sprintf(`Digest realm="%s", nonce="%s", qop="auth"`, testRealm, testNonce)
	addr := startRTSP(t, func(r rtspReq) (int, []string, string) {
		if r.auth == "" {
			return 401, []string{auth}, ""
		}
		if checkDigest(r.auth, r.method, r.uri, "admin", "") {
			return 200, nil, "v=0\r\n"
		}
		return 401, []string{auth}, ""
	})

	res := RTSPBruteForceKnown(context.Background(),
		[]string{"rtsp://" + addr + "/live"},
		filepath.Join(t.TempDir(), "missing.txt"),
		[]string{"admin:"}, 3*time.Second)

	if res.Outcome != RTSPCreds {
		t.Fatalf("outcome = %s (%s), want creds", res.Outcome, res.Note)
	}
	if res.Credential != "admin:" {
		t.Errorf("credential = %q, want admin:", res.Credential)
	}
}

// A camera that only answers to an empty user with an empty password (the
// ",," entry of the database) must yield ":".
func TestRTSPBruteForceBlankPair(t *testing.T) {
	auth := fmt.Sprintf(`Digest realm="%s", nonce="%s", qop="auth"`, testRealm, testNonce)
	addr := startRTSP(t, func(r rtspReq) (int, []string, string) {
		if r.auth == "" {
			return 401, []string{auth}, ""
		}
		if checkDigest(r.auth, r.method, r.uri, "", "") {
			return 200, nil, "v=0\r\n"
		}
		return 401, []string{auth}, ""
	})

	res := RTSPBruteForceKnown(context.Background(),
		[]string{"rtsp://" + addr + "/live"},
		filepath.Join(t.TempDir(), "missing.txt"),
		[]string{":"}, 3*time.Second)

	if res.Outcome != RTSPCreds {
		t.Fatalf("outcome = %s (%s), want creds", res.Outcome, res.Note)
	}
	if res.Credential != ":" {
		t.Errorf("credential = %q, want : (empty user and empty password)", res.Credential)
	}
}
