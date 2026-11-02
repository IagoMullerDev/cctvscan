package eyehack

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/postfix/cctvscan/internal/portscan"
	"github.com/postfix/cctvscan/internal/processor"
)

// ServerPorts are common non-camera ports scanned by default so the "server"
// filter can find hosts that are not cameras.
const ServerPorts = "21,22,23,25,53,110,135,139,143,445,993,995,1433,1521,3306,3389,5432,5900,5985,6379,9200,11211,27017"

// Direct TCP connect tuning for curated "ip:port" pairs.
const (
	tcpProbeTimeout = 2 * time.Second
	tcpProbeWorkers = 64
)

// ScanConfig configures a single eyehack scan run.
type ScanConfig struct {
	Ports        string // explicit port spec; empty uses camera (+server) defaults
	Comprehensive bool
	Rate         int
	Retry        int
	Wait         int
	Threads      int
	Adapter      string
	AdapterIP    string
	CredsFile    string
	OutputDir    string
	Debug        bool
	Privileged   bool
	Unprivileged bool
}

// RunScan scans every target from the database file and returns populated
// results. Hosts listed bare are port-scanned (masscan) on the default camera
// (+server) port set; hosts given as "ip:port" are probed directly with a TCP
// connect so only the curated ports are tested. Hosts with no open ports are
// recorded as down.
func RunScan(ctx context.Context, dbPath string, cfg ScanConfig) (*Results, error) {
	reqs, err := LoadHostRequests(dbPath)
	if err != nil {
		return nil, err
	}

	var (
		bareHosts []string
		pairs     = make(map[string][]int)
		allHosts  = make([]string, 0, len(reqs))
		nPorts    int
	)
	for _, r := range reqs {
		allHosts = append(allHosts, r.Host)
		if r.Bare {
			bareHosts = append(bareHosts, r.Host)
		}
		if len(r.Ports) > 0 {
			pairs[r.Host] = r.Ports
			nPorts += len(r.Ports)
		}
	}

	ports := resolvePorts(cfg)
	if cfg.Debug {
		fmt.Printf("Scanning %d target(s): %d bare on ports [%s], %d host(s) with %d explicit port(s)\n",
			len(allHosts), len(bareHosts), ports, len(pairs), nPorts)
	} else {
		fmt.Printf("Scanning %d target(s)...\n", len(allHosts))
	}

	scanRes := make(map[string][]int)

	// masscan over the bare hosts (wide default camera/server port set).
	if len(bareHosts) > 0 {
		scanner := portscan.NewHybridScanner(portscan.HybridConfig{
			Ports:        ports,
			Rate:         cfg.Rate,
			Retry:        cfg.Retry,
			Wait:         cfg.Wait,
			Adapter:      cfg.Adapter,
			AdapterIP:    cfg.AdapterIP,
			ExtraArgs:    []string{"--open-only"},
			Debug:        cfg.Debug,
			Privileged:   cfg.Privileged,
			Unprivileged: cfg.Unprivileged,
			Threads:      cfg.Threads,
		})
		m, err := scanner.Scan(ctx, bareHosts)
		if err != nil {
			return nil, fmt.Errorf("port scan: %w", err)
		}
		mergePortsInto(scanRes, m)
	}

	// Direct TCP connect for every curated "ip:port" pair (precise, no
	// over-scan) — also covers ports outside the default set.
	if len(pairs) > 0 {
		t := tcpProbePairs(ctx, pairs, tcpProbeTimeout, tcpProbeWorkers)
		mergePortsInto(scanRes, t)
	}
	for h := range scanRes {
		scanRes[h] = dedupSorted(scanRes[h])
	}

	fmt.Printf("Found %d host(s) with open ports\n", len(scanRes))

	proc := processor.NewOptimizedProcessor(cfg.Debug, cfg.CredsFile, cfg.OutputDir)
	proc.SetHostCreds(CredsByHost(reqs))
	hostResults := proc.ProcessHosts(ctx, scanRes)

	res := NewResults(dbPath)
	processed := make(map[string]bool, len(hostResults))
	for _, hr := range hostResults {
		res.Hosts = append(res.Hosts, ClassifyHost(hr))
		processed[hr.Host] = true
	}
	// Anything left is either a host with no open ports (down) or one whose
	// discovery found open ports but that ProcessHosts did not reach before the
	// context deadline. The latter is still live — never misreport it as down.
	for _, t := range allHosts {
		if processed[t] {
			continue
		}
		if ports, ok := scanRes[t]; ok {
			res.Hosts = append(res.Hosts, ClassifyHost(processor.HostResult{Host: t, Ports: ports}))
			continue
		}
		res.Hosts = append(res.Hosts, DownRecord(t))
	}
	return res, nil
}

// tcpProbePairs dials every explicit host:port pair concurrently and returns
// the ports that accepted a TCP connection, grouped by host.
func tcpProbePairs(ctx context.Context, pairs map[string][]int, timeout time.Duration, workers int) map[string][]int {
	type pair struct {
		host string
		port int
	}
	var jobs []pair
	for h, ps := range pairs {
		for _, p := range ps {
			jobs = append(jobs, pair{h, p})
		}
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	out := make(map[string][]int)
	sem := make(chan struct{}, workers)

	for _, j := range jobs {
		wg.Add(1)
		go func(h string, p int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			if dialOpen(ctx, h, p, timeout) {
				mu.Lock()
				out[h] = append(out[h], p)
				mu.Unlock()
			}
		}(j.host, j.port)
	}
	wg.Wait()
	return out
}

func dialOpen(ctx context.Context, host string, port int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// mergePortsInto appends ports from src into dst, grouped by host.
func mergePortsInto(dst, src map[string][]int) {
	for h, ps := range src {
		dst[h] = append(dst[h], ps...)
	}
}

// dedupSorted sorts ps and removes duplicates, returning the trimmed slice.
func dedupSorted(ps []int) []int {
	sort.Ints(ps)
	n := 0
	for i, p := range ps {
		if i == 0 || p != ps[n-1] {
			ps[n] = p
			n++
		}
	}
	return ps[:n]
}

// resolvePorts returns the port spec for the scan. An explicit user value wins;
// otherwise camera ports (comprehensive or default) are merged with common
// server ports so non-camera hosts are discoverable.
func resolvePorts(cfg ScanConfig) string {
	if cfg.Ports != "" && cfg.Ports != "0-65535" {
		return cfg.Ports
	}
	var cam string
	if cfg.Comprehensive {
		cam = portscan.GetComprehensiveCCTVPorts()
	} else {
		cam = portscan.GetCCTVPorts()
	}
	return mergePorts(cam, ServerPorts)
}

// mergePorts combines comma-separated port specs, dropping duplicates while
// preserving order.
func mergePorts(specs ...string) string {
	seen := make(map[string]bool)
	var out []string
	for _, spec := range specs {
		for _, p := range strings.Split(spec, ",") {
			p = strings.TrimSpace(p)
			if p == "" || seen[p] {
				continue
			}
			// Basic sanity: must be a number or range.
			if !validPortToken(p) {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return strings.Join(out, ",")
}

func validPortToken(p string) bool {
	if strings.Contains(p, "-") {
		parts := strings.SplitN(p, "-", 2)
		return isUint(parts[0]) && isUint(parts[1])
	}
	return isUint(p)
}

func isUint(s string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return err == nil && n >= 0 && n <= 65535
}
