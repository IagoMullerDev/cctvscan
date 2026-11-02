// Command rtspbrute tests RTSP credentials against a list of rtsp:// URLs.
//
// It exists because the HTTP brute force cannot reach RTSP: cameras protect
// their streams with a digest challenge computed client-side with MD5, which is
// not affected by the JavaScript hashing that makes web login forms unbruteable.
//
// Usage:
//
//	rtspbrute urls.txt -creds cctvscan/mycreds.txt -workers 32
//
// URLs are bucketed by host:port so each device is tested once per credential
// rather than once per path, and a credential is only reported when a
// deliberately-wrong baseline received 401 on the same URL.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/postfix/cctvscan/internal/credbrute"
)

type resultFile struct {
	ScannedAt string                 `json:"scanned_at"`
	Targets   int                    `json:"targets"`
	Found     int                    `json:"found"`
	Public    int                    `json:"public_stream"`
	Results   []credbrute.RTSPResult `json:"results"`
}

// parseArgs accepts the URL file both before and after the flags. Go's flag
// package stops at the first non-flag argument, so `rtspbrute urls.txt -out x`
// would otherwise silently ignore every flag.
func parseArgs() string {
	args := os.Args[1:]
	var input string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			break
		}
		input = a
	}
	// Drop the hoisted positional so flag.Parse sees only flags.
	rest := make([]string, 0, len(args))
	skipped := false
	for _, a := range args {
		if !skipped && a == input {
			skipped = true
			continue
		}
		rest = append(rest, a)
	}
	if err := flag.CommandLine.Parse(rest); err != nil {
		fmt.Fprintf(os.Stderr, "rtspbrute: %v\n", err)
		os.Exit(2)
	}
	if input == "" && flag.NArg() > 0 {
		input = flag.Arg(0)
	}
	return input
}

func main() {
	creds := flag.String("creds", "cctvscan/mycreds.txt", "credential wordlist (user:pass per line)")
	perReq := flag.Duration("timeout", 5*time.Second, "timeout for a single RTSP request")
	workers := flag.Int("workers", 32, "endpoints tested concurrently")
	overall := flag.Duration("overall", 30*time.Minute, "overall deadline (0 disables)")
	out := flag.String("out", "rtsp.results.json", "where to write the JSON report")
	quiet := flag.Bool("quiet", false, "only print the summary")
	input := parseArgs()
	if input == "" {
		fmt.Fprintf(os.Stderr, "usage: %s <urls.txt> [-creds file] [-workers N] [-overall 30m]\n",
			filepath.Base(os.Args[0]))
		os.Exit(2)
	}
	raw, err := os.ReadFile(input)
	if err != nil {
		fatal("read urls: %v", err)
	}

	var urls []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}
	if len(urls) == 0 {
		fatal("no rtsp:// URLs in %s", input)
	}

	groups := credbrute.GroupRTSPURLs(urls)
	fmt.Printf("targets: %d endpoints (%d URLs deduplicated by host:port)\n", len(groups), len(urls))
	fmt.Printf("wordlist: %s\n\n", *creds)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *overall > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *overall)
		defer cancel()
	}

	var done atomic.Int64
	total := int64(len(groups))

	results := credbrute.BruteRTSPBatch(ctx, groups, *creds, *perReq, *workers,
		func(r credbrute.RTSPResult) {
			n := done.Add(1)
			if *quiet {
				return
			}
			switch r.Outcome {
			case credbrute.RTSPCreds:
				fmt.Printf("[%3d/%d] CRED   %-46s %s  (%d attempts)\n", n, total, r.URL, r.Credential, r.Attempts)
			case credbrute.RTSPPublic:
				fmt.Printf("[%3d/%d] OPEN   %-46s stream needs no credentials\n", n, total, r.URL)
			case credbrute.RTSPAnyPassword:
				fmt.Printf("[%3d/%d] OPEN*  %-46s %s\n", n, total, r.URL, r.Note)
			case credbrute.RTSPUnstable:
				fmt.Printf("[%3d/%d] SKIP   %-46s %s\n", n, total, r.URL, r.Note)
			}
		})

	sort.Slice(results, func(i, j int) bool { return results[i].URL < results[j].URL })

	var found, public int
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Outcome]++
		if r.Outcome == credbrute.RTSPCreds {
			found++
		}
		if r.Outcome == credbrute.RTSPPublic {
			public++
		}
	}

	report := resultFile{
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
		Targets:   len(groups),
		Found:     found,
		Public:    public,
		Results:   results,
	}
	blob, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fatal("marshal: %v", err)
	}
	if err := os.WriteFile(*out, blob, 0o644); err != nil {
		fatal("write %s: %v", *out, err)
	}

	fmt.Println()
	fmt.Println("=== summary ===")
	for _, k := range []string{credbrute.RTSPCreds, credbrute.RTSPPublic, credbrute.RTSPAnyPassword,
		credbrute.RTSPNone, credbrute.RTSPUnstable, credbrute.RTSPLocked, credbrute.RTSPError} {
		if counts[k] > 0 {
			fmt.Printf("  %-10s %d\n", k, counts[k])
		}
	}
	fmt.Printf("  report: %s\n", *out)

	if found > 0 {
		fmt.Println()
		fmt.Println("=== credentials confirmed (same user: wrong password 401 -> candidate 200) ===")
		for _, r := range results {
			if r.Outcome == credbrute.RTSPCreds {
				fmt.Printf("  %-46s %s\n", r.URL, r.Credential)
			}
		}
	}

	if n := counts[credbrute.RTSPAnyPassword]; n > 0 {
		fmt.Println()
		fmt.Println("=== reachable, but password never checked (NOT a credential) ===")
		for _, r := range results {
			if r.Outcome == credbrute.RTSPAnyPassword {
				fmt.Printf("  %-46s %s\n", r.URL, r.Note)
			}
		}
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "rtspbrute: "+format+"\n", args...)
	os.Exit(1)
}
