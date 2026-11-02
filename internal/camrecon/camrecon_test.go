package camrecon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/postfix/cctvscan/internal/credbrute"
	"github.com/postfix/cctvscan/internal/eyehack"
)

func TestParsePwneyeCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cam.yaml")
	doc := `target:
  host: 192.168.0.10
onvif:
  supported: true
  port: 80
  auth:
    username: admin
    password: 12345
  manufacturer: Hikvision
  streams:
    - rtsp://192.168.0.10/stream1
rtsp:
  supported: true
  port: 554
  auth:
    username: admin
    password: 654321
  path: /Streaming/Channels/1
  protocol: tcp
  url: rtsp://admin:654321@192.168.0.10:554/Streaming/Channels/1
  banner:
    port: 554
    value: Hikvision
  channels:
    - channel: 1
      port: 554
      path: /Streaming/Channels/1
      protocol: tcp
      url: rtsp://admin:654321@192.168.0.10:554/Streaming/Channels/1
`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := parsePwneyeCache(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.ONVIF == nil || res.ONVIF.Username != "admin" || res.ONVIF.Password != "12345" {
		t.Errorf("onvif auth: %+v", res.ONVIF)
	}
	if res.ONVIF.Port != 80 || res.ONVIF.Manufacturer != "Hikvision" {
		t.Errorf("onvif meta: %+v", res.ONVIF)
	}
	if len(res.ONVIF.Streams) != 1 {
		t.Errorf("onvif streams: %v", res.ONVIF.Streams)
	}
	if res.RTSP == nil || res.RTSP.Username != "admin" || res.RTSP.Password != "654321" {
		t.Errorf("rtsp auth: %+v", res.RTSP)
	}
	if res.RTSP.Banner != "Hikvision" || res.RTSP.Port != 554 {
		t.Errorf("rtsp meta: %+v", res.RTSP)
	}
	if len(res.RTSP.Channels) != 1 || res.RTSP.Channels[0].Channel != 1 {
		t.Errorf("rtsp channels: %+v", res.RTSP.Channels)
	}
}

// pwneye dumps numeric passwords unquoted; YAML then types them as integers.
func TestParsePwneyeCacheNumericPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cam.yaml")
	doc := "onvif:\n  supported: true\n  port: 8080\n  auth:\n    username: root\n    password: 888888\nrtsp: {}\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := parsePwneyeCache(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if res.ONVIF == nil || res.ONVIF.Password != "888888" {
		t.Errorf("numeric password lost: %+v", res.ONVIF)
	}
}

func TestAnswerFor(t *testing.T) {
	cases := []struct {
		name   string
		output string
		answer string
		ok     bool
	}{
		{
			name:   "confirm",
			output: "\x1b[2m> \x1b[0mDo you want to extend the test to other RTSP ports? (\x1b[32my\x1b[0m)es/(\x1b[31mn\x1b[0m)o (default: y): ",
			answer: "y",
			ok:     true,
		},
		{
			name:   "confirm wrapped over lines",
			output: "This RTSP stream may support multiple channels. Try to\n   enumerate them? (y)es/(n)o (default: y): ",
			answer: "y",
			ok:     true,
		},
		{
			name:   "channel selection",
			output: "   1 Channel 1: rtsp://cam/stream1\n\n> Select channel: ",
			answer: "1",
			ok:     true,
		},
		{
			name:   "destructive refused",
			output: "> Do you really want to factory-reset the camera via ONVIF? (y)es/(n)o (default: n): ",
			answer: "n",
			ok:     true,
		},
		{
			name:   "deface refused",
			output: "Do you want to proceed with the deface attempt? (y)es/(n)o (default: n): ",
			answer: "n",
			ok:     true,
		},
		{
			name:   "exhaustive scan refused",
			output: "Try an exhaustive RTSP path scan with 1200 combination(s) across 2 port(s)? (y)es/(n)o (default: n): ",
			answer: "n",
			ok:     true,
		},
		{
			name:   "no prompt yet",
			output: "The target seems to be reachable",
			ok:     false,
		},
	}
	for _, tc := range cases {
		got, ok := answerFor(tc.output)
		if ok != tc.ok || got != tc.answer {
			t.Errorf("%s: answerFor = (%q, %v), want (%q, %v)", tc.name, got, ok, tc.answer, tc.ok)
		}
	}
}

func TestRTSPURLsPrefersDiscoveredStreams(t *testing.T) {
	cam := Camera{
		Host:  "192.168.0.10",
		Ports: []int{554, 80},
		Streams: []string{
			"rtsp://192.168.0.10:554/known",
			"http://192.168.0.10/mjpeg",
		},
	}
	urls := RTSPURLs(cam)
	if len(urls) == 0 || urls[0] != "rtsp://192.168.0.10:554/known" {
		t.Fatalf("discovered stream should come first: %v", urls)
	}
	found := false
	for _, u := range urls {
		if strings.HasPrefix(u, "http://") {
			t.Errorf("non-rtsp URL leaked into targets: %s", u)
		}
		if u == "rtsp://192.168.0.10:554/Streaming/Channels/1" {
			found = true
		}
	}
	if !found {
		t.Errorf("common paths not synthesized: %v", urls)
	}
	for _, u := range urls {
		if strings.HasPrefix(u, "rtsp://192.168.0.10:80") {
			t.Errorf("port 80 is not an RTSP port: %s", u)
		}
	}
}

func TestAttachRTSPResults(t *testing.T) {
	cameras := []Camera{
		{Host: "192.168.0.10", DeviceType: "camera"},
		{Host: "192.168.0.20", DeviceType: "camera"},
	}
	AttachRTSPResults(cameras, []credbrute.RTSPResult{
		{URL: "rtsp://192.168.0.10:554", Outcome: credbrute.RTSPCreds, Credential: "admin:12345", Attempts: 7},
		{URL: "rtsp://192.168.0.20:554", Outcome: credbrute.RTSPPublic},
		{URL: "rtsp://192.168.0.10:554", Outcome: credbrute.RTSPNone, Note: "n/a"},
	})
	if !cameras[0].Access || len(cameras[0].Findings) != 1 || cameras[0].Findings[0].Credential != "admin:12345" {
		t.Errorf("camera 10: %+v", cameras[0])
	}
	if !cameras[1].Access || cameras[1].Findings[0].Vector != VectorRTSPOpen {
		t.Errorf("camera 20: %+v", cameras[1])
	}
}

func TestAttachPwneye(t *testing.T) {
	cam := Camera{Host: "192.168.0.30"}
	AttachPwneye(&cam, PwneyeResult{
		ONVIF: &PwneyeONVIF{Supported: true, Port: 80, Username: "admin", Password: "admin"},
		RTSP:  &PwneyeRTSP{Supported: true, Port: 554, URL: "rtsp://192.168.0.30/live"},
	})
	if !cam.Access {
		t.Fatal("access should be confirmed")
	}
	if cam.Findings[0].Vector != VectorONVIF {
		t.Errorf("findings: %+v", cam.Findings)
	}
	// A public stream with no credential is not a credential, but is access.
	if cam.Findings[1].Vector != VectorRTSPOpen || cam.Findings[1].Credential != "" {
		t.Errorf("findings: %+v", cam.Findings)
	}
	if got := cam.Credentials(); len(got) != 1 || got[0] != "admin:admin" {
		t.Errorf("credentials: %v", got)
	}
}

func TestBuildReport(t *testing.T) {
	cameras := []Camera{
		{Host: "10.0.0.2", Status: eyehack.StatusLive, DeviceType: eyehack.TypeCamera,
			CVEs: []string{"CVE-2017-7921"}, Findings: []Finding{{Vector: VectorHTTP, Credential: "admin:12345"}}, Access: true},
		{Host: "10.0.0.1", Status: eyehack.StatusLive, DeviceType: eyehack.TypeCamera,
			Findings: []Finding{{Vector: VectorRTSP, Credential: "root:root"}}, Access: true},
		{Host: "10.0.0.3", Status: eyehack.StatusLive, DeviceType: eyehack.TypeServer},
		{Host: "10.0.0.4", Status: eyehack.StatusDown, DeviceType: eyehack.TypeUnknown},
	}
	rep := BuildReport("ips.txt", "mycreds.txt", cameras)

	if rep.Summary.Targets != 4 || rep.Summary.Live != 3 || rep.Summary.Cameras != 2 {
		t.Errorf("summary: %+v", rep.Summary)
	}
	if rep.Summary.Access != 2 || rep.Summary.HTTP != 1 || rep.Summary.RTSP != 1 {
		t.Errorf("summary access: %+v", rep.Summary)
	}
	if len(rep.Access) != 2 || rep.Access[0].Host != "10.0.0.1" {
		t.Errorf("access list must be sorted: %+v", rep.Access)
	}
	if rep.Source != "ips.txt" || rep.Wordlist != "mycreds.txt" {
		t.Errorf("meta: %+v", rep)
	}
}

func TestRenderMarkdownIncludesAccess(t *testing.T) {
	rep := BuildReport("ips.txt", "mycreds.txt", []Camera{
		{Host: "10.0.0.1", Status: eyehack.StatusLive, DeviceType: eyehack.TypeCamera,
			Brand: "Hikvision", Model: "DS-2CD", CVEs: []string{"CVE-2017-7921"},
			Findings: []Finding{{Vector: VectorRTSP, Source: SourceRTSPBrute,
				URL: "rtsp://10.0.0.1:554/live", Credential: "admin:12345"}}, Access: true},
	})
	var b strings.Builder
	renderMarkdown(&b, rep)
	out := b.String()
	for _, want := range []string{
		"Câmeras com acesso confirmado",
		"10.0.0.1",
		"admin:12345",
		"CVE-2017-7921",
		"Remediação recomendada",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestIsPwneyeCandidate(t *testing.T) {
	if !IsPwneyeCandidate(Camera{Status: eyehack.StatusLive, DeviceType: eyehack.TypeCamera}) {
		t.Error("camera should be a candidate")
	}
	if !IsPwneyeCandidate(Camera{Status: eyehack.StatusLive, DeviceType: eyehack.TypeUnknown, RTSP: true}) {
		t.Error("rtsp host should be a candidate")
	}
	if IsPwneyeCandidate(Camera{Status: eyehack.StatusDown, DeviceType: eyehack.TypeCamera}) {
		t.Error("down host is not a candidate")
	}
	if IsPwneyeCandidate(Camera{Status: eyehack.StatusLive, DeviceType: eyehack.TypeServer}) {
		t.Error("plain server is not a candidate")
	}
}

func TestSanitizeCacheName(t *testing.T) {
	if got := sanitize("cam_1.example"); got != "cam_1.example" {
		t.Errorf("sanitize: %q", got)
	}
	if got := sanitize("host:554"); got != "host_554" {
		t.Errorf("sanitize: %q", got)
	}
}

func TestPoolFromWordlist(t *testing.T) {
	raw := `# comentário
admin:12345
root:root
admin:admin
user:pa:ss
inválida sem dois pontos
`
	users, passes := PoolFromWordlist(raw, 10, 10)
	if strings.Join(users, ",") != "admin,root,user" {
		t.Errorf("users: %v", users)
	}
	if strings.Join(passes, ",") != "12345,root,admin,pa:ss" {
		t.Errorf("passes: %v", passes)
	}

	// Caps keep the cross product bounded.
	users, passes = PoolFromWordlist(raw, 1, 2)
	if len(users) != 1 || len(passes) != 2 {
		t.Errorf("caps: %v %v", users, passes)
	}
}

func TestDeriveUserPassFiles(t *testing.T) {
	dir := t.TempDir()
	cred := filepath.Join(dir, "mycreds.txt")
	if err := os.WriteFile(cred, []byte("admin:12345\nroot:toor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	usersPath, passesPath, err := DeriveUserPassFiles(cred, filepath.Join(dir, "out"), 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := os.ReadFile(usersPath)
	p, _ := os.ReadFile(passesPath)
	if string(u) != "admin\nroot\n" || string(p) != "12345\ntoor\n" {
		t.Errorf("pools: %q %q", u, p)
	}
	if _, _, err := DeriveUserPassFiles(filepath.Join(dir, "nope.txt"), dir, 10, 10); err == nil {
		t.Error("missing wordlist must fail")
	}
}

func TestRTSPURLsExtraPorts(t *testing.T) {
	cam := Camera{Host: "10.0.0.9", Ports: []int{8555}}
	urls := RTSPURLs(cam, 8555)
	found := false
	for _, u := range urls {
		if strings.HasPrefix(u, "rtsp://10.0.0.9:8555/") {
			found = true
		}
	}
	if !found {
		t.Errorf("curated non-standard port must be tested: %v", urls)
	}
}
