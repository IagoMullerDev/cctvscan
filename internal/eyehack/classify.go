package eyehack

import (
	"strings"
	"time"

	"github.com/postfix/cctvscan/internal/processor"
)

// nowStamp returns the current UTC timestamp in RFC3339.
func nowStamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// ClassifyHost converts a processor.HostResult into a HostRecord, deriving
// status, device type, video availability and credentials.
func ClassifyHost(r processor.HostResult) HostRecord {
	rec := HostRecord{
		Host:      r.Host,
		Ports:     r.Ports,
		ScannedAt: nowStamp(),
	}

	// A host with no open ports is down and cannot be typed.
	if len(r.Ports) == 0 {
		rec.Status = StatusDown
		rec.DeviceType = TypeUnknown
		return rec
	}
	rec.Status = StatusLive

	rec.Server = r.HTTPMeta.Server
	rec.Brand = r.Brand
	if rec.Brand == "" {
		rec.Brand = r.CameraDetection.Brand
	}
	rec.Model = r.CameraDetection.Model
	rec.Credentials = r.Credentials
	rec.CVEs = r.CVEs

	rec.RTSP = r.RTSPInfo.Any || len(r.RTSPPorts) > 0

	// Streams: record URLs and flag working video (2xx/3xx).
	for _, s := range r.StreamResults {
		if s.URL != "" {
			rec.Streams = append(rec.Streams, s.URL)
		}
		if s.Status >= 200 && s.Status < 400 {
			rec.Video = true
		}
	}
	if len(r.MJPEGPaths) > 0 {
		rec.Video = true
	}
	// An answering RTSP endpoint serves video even when auth is required.
	if r.RTSPInfo.Any {
		rec.Video = true
	}

	rec.DeviceType = deviceType(r, rec)
	return rec
}

// DownRecord builds a record for a database host that showed no open ports.
func DownRecord(host string) HostRecord {
	return HostRecord{
		Host:       host,
		Status:     StatusDown,
		DeviceType: TypeUnknown,
		ScannedAt:  nowStamp(),
	}
}

// deviceType picks the category for a live host.
func deviceType(r processor.HostResult, rec HostRecord) string {
	// Explicit recorder identity in the title/model wins over camera cues:
	// these devices are NVR/DVR units rather than single cameras.
	label := strings.ToLower(strings.Join([]string{
		r.CameraDetection.PageTitle,
		r.CameraDetection.Model,
	}, " "))
	if containsWord(label, "nvr") || strings.Contains(label, "network video recorder") {
		return TypeNVR
	}
	if containsWord(label, "dvr") || strings.Contains(label, "digital video recorder") {
		return TypeDVR
	}

	// Camera indicators.
	if r.CameraDetection.IsCamera ||
		r.ONVIFResult != "" ||
		rec.RTSP ||
		rec.Video ||
		len(r.MJPEGPaths) > 0 {
		return TypeCamera
	}

	// Any open port but no camera signal: treat as a generic server.
	return TypeServer
}

// containsWord reports whether s contains word as a whole token (or substring
// for short tokens like "nvr"/"dvr" bounded by non-alphanumerics).
func containsWord(s, word string) bool {
	if s == "" || word == "" {
		return false
	}
	idx := strings.Index(s, word)
	for idx >= 0 {
		beforeOK := idx == 0 || !isAlnum(rune(s[idx-1]))
		end := idx + len(word)
		afterOK := end >= len(s) || !isAlnum(rune(s[end]))
		if beforeOK && afterOK {
			return true
		}
		next := strings.Index(s[idx+1:], word)
		if next < 0 {
			return false
		}
		idx = idx + 1 + next
	}
	return false
}

func isAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}
