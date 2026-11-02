// Command eyehack scans an authorized IP database file (txt or csv), records
// which hosts are live/down, which serve video (cameras), and any credentials
// found, and filters results by device category.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/postfix/cctvscan/internal/eyehack"
)

var (
	filterFlag         = flag.String("filter", "", "Filter saved results by category (camera, server, nvr, dvr, live, down, video, creds, cve). Skips rescanning when results exist.")
	portsFlag          = flag.String("ports", "", "Port range to scan (default: camera ports + common server ports)")
	comprehensiveFlag  = flag.Bool("comprehensive", false, "Use comprehensive 1000+ camera port scan")
	rescanFlag         = flag.Bool("rescan", false, "Force a fresh scan even when saved results exist")
	credsFlag          = flag.String("creds", "", "Credentials file (user:pass per line)")
	outputFlag         = flag.String("output", "", "Output directory for streams/snapshots (default: database file directory)")
	rateFlag           = flag.Int("rate", 1000, "Packets per second rate for masscan")
	retryFlag          = flag.Int("retry", 3, "Number of retries for port scanning")
	waitFlag           = flag.Int("wait", 1, "Seconds to wait for late replies")
	threadsFlag        = flag.Int("threads", 25, "Number of threads for naabu")
	adapterFlag        = flag.String("adapter", "", "Network adapter name for naabu")
	adapterIPFlag      = flag.String("adapter-ip", "", "Source IP address for naabu")
	timeoutFlag        = flag.String("timeout", "30m", "Overall scan timeout (e.g., '30m', '1h')")
	debugFlag          = flag.Bool("debug", false, "Enable debug mode with verbose output")
	privilegedFlag     = flag.Bool("privileged", false, "Force privileged mode (SYN scan)")
	unprivilegedFlag   = flag.Bool("unprivileged", false, "Force unprivileged mode (CONNECT scan)")
	helpFlag           = flag.Bool("help", false, "Show help message")
)

func main() {
	// Go's flag package stops parsing at the first non-flag argument, so
	// `eyehack db.txt -filter camera` would silently drop the flags. Move
	// flags ahead of positionals before parsing.
	flag.CommandLine.Parse(reorderArgs(os.Args[1:]))

	if *helpFlag || len(flag.Args()) == 0 {
		printHelp()
		os.Exit(0)
	}

	dbPath := flag.Args()[0]
	if _, err := os.Stat(dbPath); err != nil {
		log.Fatalf("Database file not found: %s", dbPath)
	}

	filterTokens, err := eyehack.ParseFilter(*filterFlag)
	if err != nil {
		log.Fatalf("Invalid filter: %v", err)
	}

	resultsPath := eyehack.ResultsPath(dbPath)
	outputDir := *outputFlag
	if outputDir == "" {
		outputDir = filepath.Dir(dbPath)
	}

	var res *eyehack.Results
	useFilter := len(filterTokens) > 0

	// With a filter, reuse saved results unless a rescan is forced (or none
	// exist yet). Without a filter, always run a fresh scan.
	if useFilter && !*rescanFlag {
		res, err = eyehack.LoadResults(resultsPath)
		if err != nil {
			log.Fatalf("Loading results: %v", err)
		}
		if res == nil {
			fmt.Println("No saved results found; scanning first...")
		}
	}

	if res == nil {
		res, err = runScan(dbPath, outputDir)
		if err != nil {
			log.Fatalf("Scan failed: %v", err)
		}
		if err := eyehack.SaveResults(resultsPath, res); err != nil {
			log.Fatalf("Saving results: %v", err)
		}
		fmt.Printf("Saved %d host(s) to %s\n", res.HostCount, resultsPath)
	}

	hosts := eyehack.ApplyFilter(res.Hosts, filterTokens)
	if useFilter {
		fmt.Printf("Filter %q matched %d of %d host(s) (results from %s)\n",
			*filterFlag, len(hosts), len(res.Hosts), res.ScannedAt)
	}
	eyehack.RenderTable(os.Stdout, hosts)
}

func runScan(dbPath, outputDir string) (*eyehack.Results, error) {
	timeout, err := time.ParseDuration(*timeoutFlag)
	if err != nil {
		return nil, fmt.Errorf("invalid timeout %q: %w", *timeoutFlag, err)
	}

	cfg := eyehack.ScanConfig{
		Ports:         *portsFlag,
		Comprehensive: *comprehensiveFlag,
		Rate:          *rateFlag,
		Retry:         *retryFlag,
		Wait:          *waitFlag,
		Threads:       *threadsFlag,
		Adapter:       *adapterFlag,
		AdapterIP:     *adapterIPFlag,
		CredsFile:     resolveCredsFile(*credsFlag, dbPath),
		OutputDir:     outputDir,
		Debug:         *debugFlag,
		Privileged:    *privilegedFlag,
		Unprivileged:  *unprivilegedFlag,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return eyehack.RunScan(ctx, dbPath, cfg)
}

// resolveCredsFile picks a credentials file: the explicit flag wins; otherwise
// the first existing candidate near the database file or system paths. A
// missing file is allowed (brute force is simply skipped).
// reorderArgs returns args with all flags (and their values) moved ahead of
// positional arguments. Go's flag package stops at the first non-flag token,
// so `eyehack db.txt -filter camera` would otherwise ignore the flag.
func reorderArgs(args []string) []string {
	var flags, positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if strings.Contains(name, "=") {
				continue // -flag=value carries its own value
			}
			if f := flag.Lookup(name); f != nil {
				if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
					continue // boolean flag takes no separate value
				}
				// Value flag: consume the next token unless it looks like a flag.
				if i+1 < len(args) && !(len(args[i+1]) > 1 && args[i+1][0] == '-') {
					i++
					flags = append(flags, args[i])
				}
			}
			continue
		}
		positionals = append(positionals, a)
	}
	return append(flags, positionals...)
}

func resolveCredsFile(explicit, dbPath string) string {	if explicit != "" {
		return explicit
	}
	dir := filepath.Dir(dbPath)
	for _, cand := range []string{
		filepath.Join(dir, "mycreds.txt"),
		"mycreds.txt",
		filepath.Join(dir, "..", "mycreds.txt"),
		"/etc/cctvscan/credentials.txt",
	} {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return "/etc/cctvscan/credentials.txt"
}

func printHelp() {
	fmt.Printf("Usage: %s [OPTIONS] <db-file>\n", os.Args[0])
	fmt.Println("\nScan an authorized IP database (.txt or .csv) and record live/down,")
	fmt.Println("video (camera) and credentials for each host. Results are saved next")
	fmt.Println("to the database as <db-file>.results.json and can be filtered later.")
	fmt.Println("\nOptions:")
	flag.VisitAll(func(f *flag.Flag) {
		fmt.Printf("  -%-14s %s (default: %v)\n", f.Name, f.Usage, f.DefValue)
	})
	fmt.Println("\nFilter categories:")
	fmt.Println("  camera, server, nvr, dvr, device, unknown, live, down, video, creds, cve")
	fmt.Println("\nExamples:")
	fmt.Printf("  %s db.txt                          # full scan, save results\n", os.Args[0])
	fmt.Printf("  %s db.txt -filter camera           # only cameras (from saved results)\n", os.Args[0])
	fmt.Printf("  %s db.txt -filter \"camera creds\"   # cameras with credentials\n", os.Args[0])
	fmt.Printf("  %s db.txt -filter down             # hosts that are down\n", os.Args[0])
	fmt.Printf("  %s db.csv -comprehensive -rescan   # force a thorough fresh scan\n", os.Args[0])
	fmt.Println("\nDatabase file formats:")
	fmt.Println("  txt: one IP or CIDR per line (# comments allowed)")
	fmt.Println("  csv: IP column detected from header (ip/host/address) or content")
	fmt.Println("\nCredentials file format (user:pass per line):")
	fmt.Println("  admin:admin")
	fmt.Println("  admin:12345")
}
