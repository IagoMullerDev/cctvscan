package eyehack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Device type classifications.
const (
	TypeCamera = "camera"
	TypeNVR    = "nvr"
	TypeDVR    = "dvr"
	TypeServer = "server"
	TypeDevice = "device"
	TypeUnknown = "unknown"
)

// Host status values.
const (
	StatusLive = "live"
	StatusDown = "down"
)

// HostRecord holds the scan result for a single host from the database file.
type HostRecord struct {
	Host        string   `json:"host"`
	Status      string   `json:"status"`                // live | down
	DeviceType  string   `json:"device_type"`           // camera | nvr | dvr | server | device | unknown
	Brand       string   `json:"brand,omitempty"`
	Model       string   `json:"model,omitempty"`
	Server      string   `json:"server,omitempty"`
	Ports       []int    `json:"ports,omitempty"`
	Video       bool     `json:"video"`
	RTSP        bool     `json:"rtsp"`
	Streams     []string `json:"streams,omitempty"`
	Credentials string   `json:"credentials,omitempty"`
	CVEs        []string `json:"cves,omitempty"`
	ScannedAt   string   `json:"scanned_at,omitempty"`
}

// Results is the on-disk document written next to the database file.
type Results struct {
	Source    string       `json:"source"`
	ScannedAt string       `json:"scanned_at"`
	HostCount int          `json:"host_count"`
	Hosts     []HostRecord `json:"hosts"`
}

// ResultsPath returns the JSON results path for a database file:
// db.txt -> db.txt.results.json, db.csv -> db.csv.results.json.
func ResultsPath(dbPath string) string {
	return dbPath + ".results.json"
}

// LoadResults reads an existing results file. It returns (nil, nil) when the
// file does not exist so callers can decide to scan first.
func LoadResults(path string) (*Results, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read results: %w", err)
	}
	var res Results
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("parse results %s: %w", path, err)
	}
	return &res, nil
}

// SaveResults writes the results as indented JSON to the given path.
func SaveResults(path string, res *Results) error {
	res.HostCount = len(res.Hosts)
	sort.Slice(res.Hosts, func(i, j int) bool {
		return hostLess(res.Hosts[i].Host, res.Hosts[j].Host)
	})
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return fmt.Errorf("encode results: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write results: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace results: %w", err)
	}
	return nil
}

// NewResults builds an empty results document for a source database file.
func NewResults(source string) *Results {
	return &Results{
		Source:    source,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Hosts:     []HostRecord{},
	}
}

// hostLess orders hosts by their IP components so 10.0.0.2 sorts before
// 10.0.0.10. Falls back to string comparison for non-IP hosts.
func hostLess(a, b string) bool {
	ap := strings.Split(a, ".")
	bp := strings.Split(b, ".")
	if len(ap) != len(bp) {
		return a < b
	}
	for i := range ap {
		an, aerr := strconv.Atoi(ap[i])
		bn, berr := strconv.Atoi(bp[i])
		if aerr != nil || berr != nil {
			return a < b
		}
		if an != bn {
			return an < bn
		}
	}
	return a < b
}

// ResultsDir returns the directory containing the results file.
func ResultsDir(resultsPath string) string {
	return filepath.Dir(resultsPath)
}
