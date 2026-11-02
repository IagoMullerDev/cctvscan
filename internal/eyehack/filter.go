package eyehack

import (
	"fmt"
	"strings"
	"unicode"
)

// ValidFilters lists the accepted --filter categories.
var ValidFilters = []string{
	"camera", "server", "nvr", "dvr", "device", "unknown",
	"live", "down", "video", "creds", "cve",
}

// ParseFilter splits a filter expression into normalized tokens. Tokens may be
// separated by commas and/or whitespace: `--filter "camera video"` and
// `--filter camera,video` are equivalent.
func ParseFilter(expr string) ([]string, error) {
	tokens := strings.FieldsFunc(expr, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
	var out []string
	for _, t := range tokens {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if !isValidFilter(t) {
			return nil, fmt.Errorf("unknown filter %q (valid: %s)", t, strings.Join(ValidFilters, ", "))
		}
		out = append(out, t)
	}
	return out, nil
}

func isValidFilter(t string) bool {
	for _, v := range ValidFilters {
		if t == v {
			return true
		}
	}
	return false
}

// ApplyFilter returns hosts matching all tokens. An empty filter returns all.
// With no results at all, callers should scan first.
func ApplyFilter(hosts []HostRecord, tokens []string) []HostRecord {
	if len(tokens) == 0 {
		return hosts
	}
	var out []HostRecord
	for _, h := range hosts {
		if matchesAll(h, tokens) {
			out = append(out, h)
		}
	}
	return out
}

func matchesAll(h HostRecord, tokens []string) bool {
	for _, t := range tokens {
		if !matches(h, t) {
			return false
		}
	}
	return true
}

func matches(h HostRecord, token string) bool {
	switch token {
	case "camera":
		return h.DeviceType == TypeCamera
	case "server":
		return h.DeviceType == TypeServer
	case "nvr":
		return h.DeviceType == TypeNVR
	case "dvr":
		return h.DeviceType == TypeDVR
	case "device":
		return h.DeviceType == TypeDevice
	case "unknown":
		return h.DeviceType == TypeUnknown
	case "live":
		return h.Status == StatusLive
	case "down":
		return h.Status == StatusDown
	case "video":
		return h.Video
	case "creds":
		return h.Credentials != ""
	case "cve":
		return len(h.CVEs) > 0
	default:
		return false
	}
}

// CountByType summarizes hosts per device type and status for a header line.
func CountByType(hosts []HostRecord) map[string]int {
	m := map[string]int{}
	for _, h := range hosts {
		m[h.DeviceType]++
		if h.Status == StatusLive {
			m[StatusLive]++
		} else {
			m[StatusDown]++
		}
		if h.Video {
			m["video"]++
		}
		if h.Credentials != "" {
			m["creds"]++
		}
		if len(h.CVEs) > 0 {
			m["cve"]++
		}
	}
	return m
}
