// Package camrecon orchestrates the IP camera assessment pipeline. It runs the
// cctvscan/eyehack discovery engine (port scan, fingerprint, CVE mapping, HTTP
// credential testing), the RTSP credential tester and the external pwneye probe
// (ONVIF + RTSP), then consolidates everything into a single access report.
//
// A device is only reported as "access confirmed" when one of the engines
// positively proved it: a deliberately-wrong baseline was rejected while the
// candidate was accepted. Nothing here guesses, and nothing here alters the
// target — pwneye is invoked without any of its reboot/reset/deface/move
// actions.
package camrecon

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/postfix/cctvscan/internal/credbrute"
	"github.com/postfix/cctvscan/internal/eyehack"
	"github.com/postfix/cctvscan/internal/probe"
)

// nowStamp returns the current UTC timestamp in RFC3339.
func nowStamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// Finding vectors.
const (
	VectorHTTP     = "http"      // HTTP Basic or web login form
	VectorRTSP     = "rtsp"      // RTSP digest with a verified credential
	VectorRTSPOpen = "rtsp-open" // RTSP stream answering without credentials
	VectorONVIF    = "onvif"     // ONVIF device authentication
)

// Engines that can produce a finding.
const (
	SourceCCTVScan  = "cctvscan"
	SourceRTSPBrute = "rtspbrute"
	SourcePwneye    = "pwneye"
)

// Finding is one positively proven way into a device.
type Finding struct {
	Vector     string `json:"vector"`
	Source     string `json:"source"`
	URL        string `json:"url,omitempty"`
	Credential string `json:"credential,omitempty"`
	Note       string `json:"note,omitempty"`
}

// Camera is one host with everything the pipeline knows about it.
type Camera struct {
	Host       string        `json:"host"`
	Status     string        `json:"status"`
	DeviceType string        `json:"device_type"`
	Brand      string        `json:"brand,omitempty"`
	Model      string        `json:"model,omitempty"`
	Server     string        `json:"server,omitempty"`
	Ports      []int         `json:"ports,omitempty"`
	CVEs       []string      `json:"cves,omitempty"`
	Streams    []string      `json:"streams,omitempty"`
	RTSP       bool          `json:"rtsp,omitempty"`
	Video      bool          `json:"video,omitempty"`
	Findings   []Finding     `json:"findings,omitempty"`
	Access     bool          `json:"access"`
	Pwneye     *PwneyeResult `json:"pwneye,omitempty"`
}

// Summary counts for the whole run.
type Summary struct {
	Targets     int `json:"targets"`
	Live        int `json:"live"`
	Cameras     int `json:"cameras"`
	Access      int `json:"access_confirmed"`
	HTTP        int `json:"http_access"`
	RTSP        int `json:"rtsp_access"`
	ONVIF       int `json:"onvif_access"`
	OpenStreams int `json:"open_streams"`
	CVEs        int `json:"cve_findings"`
}

// Report is the consolidated output written to disk.
type Report struct {
	GeneratedAt string   `json:"generated_at"`
	Source      string   `json:"source"`
	Wordlist    string   `json:"wordlist,omitempty"`
	Summary     Summary  `json:"summary"`
	Access      []Camera `json:"access"`
	Hosts       []Camera `json:"hosts"`
}

// CameraFromRecord converts an eyehack host record into a report entry.
func CameraFromRecord(rec eyehack.HostRecord) Camera {
	return Camera{
		Host:       rec.Host,
		Status:     rec.Status,
		DeviceType: rec.DeviceType,
		Brand:      rec.Brand,
		Model:      rec.Model,
		Server:     rec.Server,
		Ports:      rec.Ports,
		CVEs:       rec.CVEs,
		Streams:    rec.Streams,
		RTSP:       rec.RTSP,
		Video:      rec.Video,
	}
}

// RTSPURLs returns candidate rtsp:// URLs for a host: streams already
// discovered by the scanner first (they are known to answer), then common
// paths on every open RTSP port as fallback. extraPorts covers ports the
// operator curated explicitly ("ip:port" in the database), which may run RTSP
// on a non-standard port the scanner's RTSP port list would miss.
func RTSPURLs(c Camera, extraPorts ...int) []string {
	var urls []string
	seen := map[string]bool{}
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	for _, s := range c.Streams {
		if strings.HasPrefix(strings.ToLower(s), "rtsp://") {
			add(s)
		}
	}
	ports := append([]int{}, probe.FilterRTSP(c.Ports)...)
	for _, p := range extraPorts {
		if p > 0 && !containsInt(ports, p) {
			ports = append(ports, p)
		}
	}
	for _, port := range ports {
		for _, path := range probe.RTSPPaths {
			add(fmt.Sprintf("rtsp://%s:%d%s", c.Host, port, path))
		}
	}
	return urls
}

func containsInt(haystack []int, needle int) bool {
	for _, n := range haystack {
		if n == needle {
			return true
		}
	}
	return false
}

// IsPwneyeCandidate reports whether a live host is worth handing to pwneye:
// anything that looks like a camera/recorder or speaks RTSP/video.
func IsPwneyeCandidate(c Camera) bool {
	if c.Status != eyehack.StatusLive {
		return false
	}
	switch c.DeviceType {
	case eyehack.TypeCamera, eyehack.TypeNVR, eyehack.TypeDVR:
		return true
	}
	return c.RTSP || c.Video
}

// AttachRTSPResults folds RTSP brute force results into the matching cameras.
// Only positively proven outcomes become findings; the rest is carried as
// context in the result list, never as access.
func AttachRTSPResults(cameras []Camera, results []credbrute.RTSPResult) {
	byHost := make(map[string][]credbrute.RTSPResult)
	for _, r := range results {
		if h := hostOfRTSP(r.URL); h != "" {
			byHost[h] = append(byHost[h], r)
		}
	}
	for i := range cameras {
		for _, r := range byHost[cameras[i].Host] {
			switch r.Outcome {
			case credbrute.RTSPCreds:
				cameras[i].addFinding(Finding{
					Vector:     VectorRTSP,
					Source:     SourceRTSPBrute,
					URL:        r.URL,
					Credential: r.Credential,
					Note:       r.Note,
				})
			case credbrute.RTSPPublic:
				cameras[i].addFinding(Finding{
					Vector: VectorRTSPOpen,
					Source: SourceRTSPBrute,
					URL:    r.URL,
					Note:   "stream responde sem autenticação",
				})
			}
		}
	}
}

// AttachPwneye folds a pwneye run into the camera entry.
func AttachPwneye(c *Camera, p PwneyeResult) {
	c.Pwneye = &p
	if p.ONVIF != nil && p.ONVIF.Username != "" {
		hostPort := c.Host
		if p.ONVIF.Port > 0 && p.ONVIF.Port != 80 {
			hostPort = fmt.Sprintf("%s:%d", c.Host, p.ONVIF.Port)
		}
		c.addFinding(Finding{
			Vector:     VectorONVIF,
			Source:     SourcePwneye,
			URL:        fmt.Sprintf("http://%s/onvif", hostPort),
			Credential: p.ONVIF.Username + ":" + p.ONVIF.Password,
			Note:       p.ONVIF.Manufacturer,
		})
	}
	if p.RTSP != nil {
		if p.RTSP.Username != "" {
			c.addFinding(Finding{
				Vector:     VectorRTSP,
				Source:     SourcePwneye,
				URL:        p.RTSP.URL,
				Credential: p.RTSP.Username + ":" + p.RTSP.Password,
				Note:       "pwneye (paths por fabricante)",
			})
		} else if p.RTSP.URL != "" {
			c.addFinding(Finding{
				Vector: VectorRTSPOpen,
				Source: SourcePwneye,
				URL:    p.RTSP.URL,
				Note:   "stream responde sem autenticação",
			})
		}
	}
}

// BuildReport assembles the final report from the per-host entries.
func BuildReport(source, wordlist string, cameras []Camera) Report {
	sort.Slice(cameras, func(i, j int) bool { return cameras[i].Host < cameras[j].Host })

	rep := Report{
		GeneratedAt: nowStamp(),
		Source:      source,
		Wordlist:    wordlist,
	}
	access := []Camera{}
	seenCVEs := map[string]bool{}
	for _, c := range cameras {
		rep.Summary.Targets++
		if c.Status == eyehack.StatusLive {
			rep.Summary.Live++
		}
		switch c.DeviceType {
		case eyehack.TypeCamera, eyehack.TypeNVR, eyehack.TypeDVR:
			rep.Summary.Cameras++
		}
		for _, v := range c.CVEs {
			if !seenCVEs[v] {
				seenCVEs[v] = true
				rep.Summary.CVEs++
			}
		}
		if !c.Access {
			continue
		}
		rep.Summary.Access++
		for _, f := range c.Findings {
			switch f.Vector {
			case VectorHTTP:
				rep.Summary.HTTP++
			case VectorRTSP:
				rep.Summary.RTSP++
			case VectorONVIF:
				rep.Summary.ONVIF++
			case VectorRTSPOpen:
				rep.Summary.OpenStreams++
			}
		}
		access = append(access, c)
	}
	rep.Access = access
	rep.Hosts = cameras
	return rep
}

// Vectors returns the distinct access vectors found on a camera.
func (c Camera) Vectors() []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range c.Findings {
		if !seen[f.Vector] {
			seen[f.Vector] = true
			out = append(out, f.Vector)
		}
	}
	return out
}

// Credentials returns every credential proven on a camera, de-duplicated.
func (c Camera) Credentials() []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range c.Findings {
		if f.Credential != "" && !seen[f.Credential] {
			seen[f.Credential] = true
			out = append(out, f.Credential)
		}
	}
	return out
}

// Description is a short "brand model (type)" label.
func (c Camera) Description() string {
	parts := []string{}
	for _, p := range []string{c.Brand, c.Model} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	label := strings.Join(parts, " ")
	if label == "" {
		label = c.DeviceType
	}
	return label
}

func (c *Camera) addFinding(f Finding) {
	for _, e := range c.Findings {
		if e.Vector == f.Vector && e.URL == f.URL && e.Credential == f.Credential {
			return
		}
	}
	c.Findings = append(c.Findings, f)
	c.Access = true
}

// hostOfRTSP extracts the hostname from an rtsp:// URL.
func hostOfRTSP(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
