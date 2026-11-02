package eyehack

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/postfix/cctvscan/internal/processor"
	"github.com/postfix/cctvscan/internal/probe"
	"github.com/postfix/cctvscan/internal/streams"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}

func TestLoadTargetsTXT(t *testing.T) {
	p := writeTemp(t, "db.txt", "192.168.1.10\n192.168.1.0/30\n# comment\n10.0.0.5 # note\n\n")
	got, err := LoadTargets(p)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	want := []string{"192.168.1.10", "192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3", "10.0.0.5"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestLoadTargetsSkipsIPv6(t *testing.T) {
	// masscan discovery is IPv4-only here; IPv6 targets must be excluded so a
	// single IPv6 entry does not abort the whole scan.
	p := writeTemp(t, "db.txt", "1.2.3.4\n2600:9000:2804:e200:5:b374:4000:93a1\n5.6.7.8\n")
	got, err := LoadTargets(p)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	want := []string{"1.2.3.4", "5.6.7.8"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestLoadHostRequestsIPPort(t *testing.T) {
	// Mixed: a bare IP, an ip:port pair, a repeat of the bare IP with another
	// port (must merge), and an IPv6 entry (must be skipped).
	p := writeTemp(t, "db.txt", "1.1.1.1\n1.1.1.1:443\n2.2.2.2:5905\n1.1.1.1:8080\n2600:9000:2804:e200:5:b374:4000:93a1:9000\n")
	reqs, err := LoadHostRequests(p)
	if err != nil {
		t.Fatalf("LoadHostRequests: %v", err)
	}
	if len(reqs) != 2 {
		t.Fatalf("got %d hosts, want 2: %+v", len(reqs), reqs)
	}
	// First-seen order: 1.1.1.1 then 2.2.2.2.
	if reqs[0].Host != "1.1.1.1" || reqs[1].Host != "2.2.2.2" {
		t.Errorf("order: got %s then %s", reqs[0].Host, reqs[1].Host)
	}
	// 1.1.1.1 appeared bare (default set) and with ports 443 + 8080 (merged).
	if !reqs[0].Bare {
		t.Error("1.1.1.1 should be bare")
	}
	if !reflect.DeepEqual(reqs[0].Ports, []int{443, 8080}) {
		t.Errorf("1.1.1.1 ports: got %v, want [443 8080]", reqs[0].Ports)
	}
	// 2.2.2.2 only appeared as ip:port → not bare, just port 5905.
	if reqs[1].Bare {
		t.Error("2.2.2.2 should not be bare")
	}
	if !reflect.DeepEqual(reqs[1].Ports, []int{5905}) {
		t.Errorf("2.2.2.2 ports: got %v, want [5905]", reqs[1].Ports)
	}
}

func TestLoadTargetsCSVHeaderIPColumn(t *testing.T) {
	p := writeTemp(t, "db.csv", "name,ip,port\nlan-a,192.168.2.1,80\nlan-b,192.168.2.2,554\n")
	got, err := LoadTargets(p)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	want := []string{"192.168.2.1", "192.168.2.2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestLoadTargetsCSVIDByContent(t *testing.T) {
	// No header names an IP column; IP is in column 2.
	p := writeTemp(t, "db.csv", "a,b,192.168.3.1,x\na,b,192.168.3.2,x\n")
	got, err := LoadTargets(p)
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	want := []string{"192.168.3.1", "192.168.3.2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseFilter(t *testing.T) {
	got, err := ParseFilter("camera, video  creds")
	if err != nil {
		t.Fatalf("ParseFilter: %v", err)
	}
	want := []string{"camera", "video", "creds"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if _, err := ParseFilter("bogus"); err == nil {
		t.Error("expected error for unknown filter")
	}
}

func TestApplyFilterAND(t *testing.T) {
	hosts := []HostRecord{
		{Host: "1.1.1.1", Status: StatusLive, DeviceType: TypeCamera, Video: true, Credentials: "admin:123"},
		{Host: "2.2.2.2", Status: StatusLive, DeviceType: TypeCamera, Video: false},
		{Host: "3.3.3.3", Status: StatusDown, DeviceType: TypeUnknown},
		{Host: "4.4.4.4", Status: StatusLive, DeviceType: TypeServer},
	}
	cam := ApplyFilter(hosts, []string{"camera"})
	if len(cam) != 2 {
		t.Errorf("camera filter: got %d, want 2", len(cam))
	}
	camCreds := ApplyFilter(hosts, []string{"camera", "creds"})
	if len(camCreds) != 1 || camCreds[0].Host != "1.1.1.1" {
		t.Errorf("camera+creds: got %v", camCreds)
	}
	down := ApplyFilter(hosts, []string{"down"})
	if len(down) != 1 || down[0].Host != "3.3.3.3" {
		t.Errorf("down filter: got %v", down)
	}
	all := ApplyFilter(hosts, nil)
	if len(all) != len(hosts) {
		t.Errorf("empty filter should return all: got %d", len(all))
	}
}

func TestClassifyHostDown(t *testing.T) {
	rec := ClassifyHost(processor.HostResult{Host: "10.0.0.9"})
	if rec.Status != StatusDown || rec.DeviceType != TypeUnknown {
		t.Errorf("got %+v, want down/unknown", rec)
	}
}

func TestClassifyHostCamera(t *testing.T) {
	rec := ClassifyHost(processor.HostResult{
		Host:        "10.0.0.1",
		Ports:       []int{80, 554},
		RTSPPorts:   []int{554},
		CameraDetection: probe.CameraDetectionResult{IsCamera: true, Brand: "hikvision"},
	})
	if rec.Status != StatusLive {
		t.Errorf("status: got %s, want live", rec.Status)
	}
	if rec.DeviceType != TypeCamera {
		t.Errorf("type: got %s, want camera", rec.DeviceType)
	}
	if !rec.RTSP {
		t.Error("expected RTSP true")
	}
}

func TestClassifyHostNVRByTitle(t *testing.T) {
	rec := ClassifyHost(processor.HostResult{
		Host:  "10.0.0.2",
		Ports: []int{80},
		CameraDetection: probe.CameraDetectionResult{
			IsCamera: true,
			PageTitle: "NVR - Network Video Recorder",
		},
	})
	if rec.DeviceType != TypeNVR {
		t.Errorf("type: got %s, want nvr", rec.DeviceType)
	}
}

func TestClassifyHostServer(t *testing.T) {
	rec := ClassifyHost(processor.HostResult{
		Host:      "10.0.0.3",
		Ports:     []int{22, 3306},
		HTTPMeta:  probe.HTTPMeta{Server: "nginx"},
	})
	if rec.DeviceType != TypeServer {
		t.Errorf("type: got %s, want server", rec.DeviceType)
	}
}

func TestClassifyHostVideoFromStream(t *testing.T) {
	rec := ClassifyHost(processor.HostResult{
		Host:  "10.0.0.4",
		Ports: []int{8080},
		StreamResults: []streams.StreamResult{
			{URL: "http://10.0.0.4:8080/video", Status: 200},
		},
	})
	if !rec.Video {
		t.Error("expected Video true from 200 stream")
	}
	if len(rec.Streams) != 1 {
		t.Errorf("streams: got %v", rec.Streams)
	}
	if rec.DeviceType != TypeCamera {
		t.Errorf("type: got %s, want camera (video present)", rec.DeviceType)
	}
}

func TestResultsRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "db.txt.results.json")
	res := NewResults("db.txt")
	res.Hosts = []HostRecord{
		{Host: "10.0.0.10", Status: StatusLive, DeviceType: TypeCamera},
		{Host: "10.0.0.2", Status: StatusDown, DeviceType: TypeUnknown},
	}
	if err := SaveResults(p, res); err != nil {
		t.Fatalf("SaveResults: %v", err)
	}
	loaded, err := LoadResults(p)
	if err != nil {
		t.Fatalf("LoadResults: %v", err)
	}
	if loaded == nil || len(loaded.Hosts) != 2 {
		t.Fatalf("loaded: %+v", loaded)
	}
	// IP-aware sort: .2 before .10.
	if loaded.Hosts[0].Host != "10.0.0.2" || loaded.Hosts[1].Host != "10.0.0.10" {
		t.Errorf("sort order: got %s then %s", loaded.Hosts[0].Host, loaded.Hosts[1].Host)
	}
	// Missing file returns nil, nil.
	none, err := LoadResults(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || none != nil {
		t.Errorf("missing file: got %v, %v; want nil, nil", none, err)
	}
}

func TestResultsPath(t *testing.T) {
	if got := ResultsPath("db.txt"); got != "db.txt.results.json" {
		t.Errorf("got %s", got)
	}
}
