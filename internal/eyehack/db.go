// Package eyehack implements the eyehack CLI: scan an authorized IP database
// file (txt or csv), record which hosts are live/down, which serve video
// (cameras), and any credentials found, and allow filtering by device category.
package eyehack

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/postfix/cctvscan/internal/targets"
)

// Cred is a credential declared in the database line itself
// ("ip:port,user,pass"). It is carried through the pipeline and tested before
// the wordlist so a pair already known for a host is never wasted.
type Cred struct {
	User string
	Pass string
}

// String renders the credential in the "user:pass" form the brute-forcers use.
func (c Cred) String() string { return c.User + ":" + c.Pass }

// HostReq is one host from the database together with the ports requested for
// it. Bare is true when the host was listed without a port (so the default
// camera/server port set should be scanned); Ports holds the explicit ports
// from one or more "ip:port" entries; Creds holds the credentials declared on
// those entries (first-seen order, duplicates dropped).
type HostReq struct {
	Host  string
	Ports []int
	Bare  bool
	Creds []Cred
}

// addCred appends a known credential unless it is nil or already present; it
// reports whether the credential was new.
func (r *HostReq) addCred(c *Cred) bool {
	if c == nil {
		return false
	}
	for _, have := range r.Creds {
		if have == *c {
			return false
		}
	}
	r.Creds = append(r.Creds, *c)
	return true
}

// Entry kinds returned by parseEntry.
const (
	entryInvalid = iota
	entryIPv4Bare
	entryIPv4Port
	entryIPv6
)

// LoadHostRequests reads a database file (.txt or .csv) and returns one HostReq
// per host, merged in first-seen order. Supported line formats are a bare IPv4
// address, an "ip:port" pair, or an IPv4 CIDR (expanded to bare hosts), each
// optionally followed by a credential: "ip:port,user,pass". Fields may be
// blank — ",," declares an empty user with an empty password, ",,senha" an
// empty user with a password, ",usuario," a user with an empty password — and
// CredsByHost later expands each declaration into the blank variants that get
// tested. IPv6 entries — bare, with a ":port" suffix, or CIDR — are skipped
// with a warning because masscan discovery here is IPv4-only. Blank lines and
// # comments are skipped.
func LoadHostRequests(path string) ([]HostReq, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	defer f.Close()

	var entries []string
	if isCSV(path) {
		entries, err = readCSV(f)
	} else {
		entries, err = readTXT(f)
	}
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no targets found in %s", path)
	}

	var (
		reqs    []HostReq
		index   = make(map[string]int)
		skipped int
		ipv6    int
		known   int
	)
	get := func(host string) *HostReq {
		if i, ok := index[host]; ok {
			return &reqs[i]
		}
		index[host] = len(reqs)
		reqs = append(reqs, HostReq{Host: host})
		return &reqs[len(reqs)-1]
	}
	// attach records a declared credential and counts it for the final report.
	attach := func(r *HostReq, cred *Cred) {
		if r.addCred(cred) {
			known++
		}
	}

	for _, e := range entries {
		line, cred := splitCreds(e)
		host, port, kind := parseEntry(line)
		switch kind {
		case entryIPv4Bare:
			if strings.Contains(host, "/") {
				// IPv4 CIDR: expand to individual hosts, all scanned bare.
				ips, err := targets.FromArgsOrFile([]string{host}, "")
				if err != nil {
					skipped++
					continue
				}
				for _, ip := range ips {
					r := get(ip)
					r.Bare = true
					attach(r, cred)
				}
				continue
			}
			r := get(host)
			r.Bare = true
			attach(r, cred)
		case entryIPv4Port:
			r := get(host)
			if !containsInt(r.Ports, port) {
				r.Ports = append(r.Ports, port)
			}
			attach(r, cred)
		case entryIPv6:
			ipv6++
		default:
			skipped++
		}
	}

	if len(reqs) == 0 {
		return nil, fmt.Errorf("no valid IPv4 targets in %s", path)
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "warning: skipped %d non-IP entries in %s\n", skipped, filepath.Base(path))
	}
	if ipv6 > 0 {
		fmt.Fprintf(os.Stderr, "warning: skipped %d IPv6 target(s) in %s (masscan discovery is IPv4-only here)\n",
			ipv6, filepath.Base(path))
	}
	if known > 0 {
		nonBlank := 0
		for _, r := range reqs {
			for _, c := range r.Creds {
				if c.User != "" || c.Pass != "" {
					nonBlank++
				}
			}
		}
		cand := 0
		for _, cs := range CredsByHost(reqs) {
			cand += len(cs)
		}
		fmt.Fprintf(os.Stderr, "info: %d credential(s) declared in %s (%d with a user or password, %d blank) -> %d candidate(s) tested before the wordlist\n",
			known, filepath.Base(path), nonBlank, known-nonBlank, cand)
	}
	return reqs, nil
}

// splitCreds peels the optional ",user,pass" credential suffix off a database
// line: "1.2.3.4:8080,admin,12345" yields "1.2.3.4:8080" and admin/12345.
// Fields may be empty — ",," declares a blank user and a blank password,
// ",,secret" a blank user with a password, ",admin," a user with a blank
// password — and all of them are kept so they can be tested. A line without
// any comma declares no credential at all.
func splitCreds(line string) (string, *Cred) {
	i := strings.Index(line, ",")
	if i < 0 {
		return line, nil
	}
	base := strings.TrimSpace(line[:i])
	fields := strings.Split(line[i+1:], ",")
	user := strings.TrimSpace(fields[0])
	// The password is the rest, so a "," inside it survives.
	pass := strings.TrimSpace(strings.Join(fields[1:], ","))
	return base, &Cred{User: user, Pass: pass}
}

// credCandidates expands a declared credential into every pair actually
// tested: the declared pair first, then the blank variants — blank password,
// blank user, and both blank. Cameras commonly ship with an empty password, an
// empty user or no credential at all, so each of those combinations is worth a
// try. Duplicates (a blank declaration collapses to a single pair) are removed.
func credCandidates(c Cred) []Cred {
	pairs := [][2]string{
		{c.User, c.Pass},
		{c.User, ""},
		{"", c.Pass},
		{"", ""},
	}
	out := make([]Cred, 0, len(pairs))
	seen := make(map[Cred]bool, len(pairs))
	for _, p := range pairs {
		k := Cred{User: p[0], Pass: p[1]}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out
}

// parseEntry classifies a single database line. It returns the host (a bare
// IPv4 address, an "ip:port" host, or an IPv4 CIDR), the port (for ip:port),
// and one of the entry* kinds.
func parseEntry(e string) (host string, port int, kind int) {
	if i := strings.LastIndex(e, ":"); i >= 0 {
		hp, ps := e[:i], e[i+1:]
		if p, err := strconv.Atoi(ps); err == nil && p >= 1 && p <= 65535 {
			if ip := net.ParseIP(hp); ip != nil {
				if ip.To4() != nil {
					return hp, p, entryIPv4Port
				}
				// IPv6 address with a port suffix.
				return "", 0, entryIPv6
			}
		}
		// Not an "ip:port" pair: treat a bare IPv6 literal as IPv6.
		if ip := net.ParseIP(e); ip != nil && ip.To4() == nil {
			return "", 0, entryIPv6
		}
		return "", 0, entryInvalid
	}
	if ip := net.ParseIP(e); ip != nil {
		if ip.To4() == nil {
			return "", 0, entryIPv6
		}
		return e, 0, entryIPv4Bare
	}
	if isCIDR(e) {
		// Only an IPv4 CIDR reaches here (an IPv6 CIDR contains ':').
		return e, 0, entryIPv4Bare
	}
	return "", 0, entryInvalid
}

// CredsByHost maps each host of a parsed database to the credentials to test
// for it, in "user:pass" form: every declared credential expanded into its
// blank variants (see credCandidates), first-seen order and duplicates
// removed. Hosts that declare no credential are absent from the map. A blank
// pair is ":" — an attempt with an empty user and an empty password.
func CredsByHost(reqs []HostReq) map[string][]string {
	var out map[string][]string
	for _, r := range reqs {
		if len(r.Creds) == 0 {
			continue
		}
		if out == nil {
			out = make(map[string][]string)
		}
		seen := make(map[string]bool)
		for _, c := range r.Creds {
			for _, cand := range credCandidates(c) {
				s := cand.String()
				if seen[s] {
					continue
				}
				seen[s] = true
				out[r.Host] = append(out[r.Host], s)
			}
		}
	}
	return out
}

// LoadTargets reads a database file and returns every host in first-seen order
// (IPv4 CIDRs expanded). It is a convenience wrapper over LoadHostRequests for
// callers that only need the flat target list.
func LoadTargets(path string) ([]string, error) {
	reqs, err := LoadHostRequests(path)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r.Host)
	}
	return out, nil
}

// isCIDR reports whether s parses as an IP network (CIDR) notation.
func isCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

func containsInt(haystack []int, needle int) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func isCSV(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".csv")
}

func readTXT(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow "ip # comment" and trailing comments.
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// readCSV parses CSV content and extracts the target column. If the first row
// looks like a header (contains ip/host/address), that column is used.
// Otherwise the first column that parses as an IP/CIDR in the data rows wins.
func readCSV(r io.Reader) ([]string, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true

	rows, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse csv: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	col := detectIPColumn(rows)
	if col < 0 {
		return nil, fmt.Errorf("csv: could not find an IP column")
	}

	var out []string
	start := 0
	if looksLikeHeader(rows[0], col) {
		start = 1
	}
	for _, row := range rows[start:] {
		if col >= len(row) {
			continue
		}
		val := strings.TrimSpace(row[col])
		if val == "" || strings.HasPrefix(val, "#") {
			continue
		}
		out = append(out, val)
	}
	return out, nil
}

// detectIPColumn returns the index of the column holding IPs. It prefers a
// header named ip/host/address/target, else the first column whose data cells
// parse as IP/CIDR.
func detectIPColumn(rows [][]string) int {
	header := rows[0]
	for i, h := range header {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "ip", "ip_address", "ipaddress", "host", "address", "target", "targets", "addr":
			return i
		}
	}
	// No header match: score columns by IP-looking data cells (skip row 0 if
	// it is a header, but scoring tolerates that).
	dataStart := 0
	if !headerLooksLikeHeader(header) {
		dataStart = 0
	}
	best, bestScore := -1, 0
	for i := range header {
		score := 0
		for _, row := range rows[dataStart:] {
			if i < len(row) && isIPOrCIDR(strings.TrimSpace(row[i])) {
				score++
			}
		}
		if score > bestScore {
			best, bestScore = i, score
		}
	}
	return best
}

func headerLooksLikeHeader(header []string) bool {
	for _, h := range header {
		if !isIPOrCIDR(strings.TrimSpace(h)) {
			return true
		}
	}
	return false
}

func looksLikeHeader(row []string, col int) bool {
	if col >= len(row) {
		return false
	}
	return !isIPOrCIDR(strings.TrimSpace(row[col]))
}

func isIPOrCIDR(s string) bool {
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}
