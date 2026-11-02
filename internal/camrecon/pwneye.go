package camrecon

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// PwneyeConfig configures one pwneye run against a single host.
type PwneyeConfig struct {
	Bin       string        // pwneye binary; "pwneye" from PATH when empty
	Timeout   time.Duration // per-host deadline (0 = none)
	UsersFile string        // optional username list (pwneye uses its own KB otherwise)
	PassFile  string        // optional password list
	LogDir    string        // where to write pwneye-<host>.log; "" discards
	Fresh     bool          // re-probe and drop any stale cache entry first
}

// PwneyeResult is what pwneye proved for one host, read from its cache.
type PwneyeResult struct {
	ONVIF *PwneyeONVIF `json:"onvif,omitempty"`
	RTSP  *PwneyeRTSP  `json:"rtsp,omitempty"`
}

// PwneyeONVIF is a proven ONVIF authentication.
type PwneyeONVIF struct {
	Supported    bool     `json:"supported"`
	Port         int      `json:"port,omitempty"`
	Username     string   `json:"username,omitempty"`
	Password     string   `json:"password,omitempty"`
	Manufacturer string   `json:"manufacturer,omitempty"`
	Streams      []string `json:"streams,omitempty"`
}

// PwneyeRTSP is a proven RTSP stream access (with or without credentials).
type PwneyeRTSP struct {
	Supported bool            `json:"supported"`
	Port      int             `json:"port,omitempty"`
	Username  string          `json:"username,omitempty"`
	Password  string          `json:"password,omitempty"`
	Path      string          `json:"path,omitempty"`
	Protocol  string          `json:"protocol,omitempty"`
	URL       string          `json:"url,omitempty"`
	Banner    string          `json:"banner,omitempty"`
	Channels  []PwneyeChannel `json:"channels,omitempty"`
}

// PwneyeChannel is one valid RTSP channel pwneye enumerated.
type PwneyeChannel struct {
	Channel  int    `json:"channel"`
	Port     int    `json:"port,omitempty"`
	Path     string `json:"path,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	URL      string `json:"url"`
}

// promptWindow is how much recent output is inspected for prompt patterns.
const promptWindow = 8192

var (
	ansiRe   = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]`)
	unsafeRe = regexp.MustCompile(`[^A-Za-z0-9._-]`)
)

// RunPwneye runs pwneye against one host and returns what it proved.
//
// pwneye is an interactive tool: it asks y/n questions and menu selections on
// stdin. camrecon drives it with an answer engine that only approves read-only
// probing — destructive prompts (factory reset, deface, ...) are refused, and
// the tool is invoked without any of its action flags (--reboot, --reset,
// --deface, --shell, --move, --record, --snapshot).
func RunPwneye(ctx context.Context, host string, cfg PwneyeConfig) (PwneyeResult, error) {
	bin := cfg.Bin
	if bin == "" {
		bin = "pwneye"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return PwneyeResult{}, fmt.Errorf("pwneye não encontrado: %w", err)
	}

	cache := PwneyeCachePath(host)
	if cfg.Fresh {
		// An old cache hit is not this run's proof: drop it so whatever shows
		// up afterwards was produced now.
		os.Remove(cache)
	}

	args := []string{
		"-t", host,
		"--no-video", // never open a viewer / decode video
		"--timeout", "10",
		"--threads", "1",
	}
	if cfg.Fresh {
		args = append(args, "--fresh")
	}
	if cfg.UsersFile != "" {
		args = append(args, "-u", cfg.UsersFile, "-ou", cfg.UsersFile)
	}
	if cfg.PassFile != "" {
		args = append(args, "-p", cfg.PassFile, "-op", cfg.PassFile)
	}

	runCtx := ctx
	var cancel context.CancelFunc
	if cfg.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(runCtx, bin, args...)
	cmd.Env = append(os.Environ(), "TERM=dumb", "NO_COLOR=1", "COLUMNS=200")

	var logw io.Writer
	if cfg.LogDir != "" {
		os.MkdirAll(cfg.LogDir, 0o755)
		if f, err := os.Create(filepath.Join(cfg.LogDir, "pwneye-"+sanitize(host)+".log")); err == nil {
			defer f.Close()
			logw = f
		}
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return PwneyeResult{}, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return PwneyeResult{}, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return PwneyeResult{}, err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		drivePrompts(stdin, stdout, logw)
	}()
	go func() {
		defer wg.Done()
		if logw != nil {
			io.Copy(logw, stderr) //nolint:errcheck // stderr is diagnostics only
		} else {
			io.Copy(io.Discard, stderr) //nolint:errcheck
		}
	}()

	runErr := cmd.Run()
	wg.Wait()

	res, loadErr := LoadPwneyeResult(host)
	if runErr != nil {
		if runCtx.Err() != nil {
			return res, fmt.Errorf("pwneye: prazo de %s excedido em %s (aumente -pwneye-timeout para varrer mais)",
				cfg.Timeout, host)
		}
		if loadErr != nil {
			return res, fmt.Errorf("pwneye falhou em %s: %v", host, runErr)
		}
	}
	return res, nil
}

// Caps for the wordlist-derived pwneye pools. pwneye tests the cross product
// users × passwords × paths × ports, so the pools stay deliberately small —
// the exact pairs of the wordlist are already tested by the rtspbrute engine.
const (
	MaxPwneyeUsers  = 10
	MaxPwneyePasses = 30
)

// DeriveUserPassFiles splits a "user:pass" wordlist into the username and
// password pools pwneye expects and writes them under dir. First-appearance
// order is kept so the most common factory pairs come first.
func DeriveUserPassFiles(credFile, dir string, maxUsers, maxPasses int) (string, string, error) {
	raw, err := os.ReadFile(credFile)
	if err != nil {
		return "", "", err
	}
	users, passes := PoolFromWordlist(string(raw), maxUsers, maxPasses)
	if len(users) == 0 || len(passes) == 0 {
		return "", "", fmt.Errorf("wordlist %s sem pares usuario:senha", credFile)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	usersPath := filepath.Join(dir, "pwneye-users.txt")
	passesPath := filepath.Join(dir, "pwneye-passes.txt")
	if err := os.WriteFile(usersPath, []byte(strings.Join(users, "\n")+"\n"), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(passesPath, []byte(strings.Join(passes, "\n")+"\n"), 0o600); err != nil {
		return "", "", err
	}
	return usersPath, passesPath, nil
}

// MergePwneyePools writes per-host pwneye pools under dir: the credentials
// declared for that host in the target database come first (so they survive
// any later cap pwneye applies), followed by whatever the shared pools of
// usersFile and passesFile still add. A credential with a blank user still
// contributes its password. Either shared pool may be empty or missing, and an
// empty password list is not written at all — pwneye then falls back to its own
// common passwords, while the HTTP/RTSP engines do test empty passwords
// declared in the database. When nothing is poolable (a blank user with a blank
// password cannot be expressed in pools) the shared pools are returned
// unchanged. It returns the files to hand to pwneye.
func MergePwneyePools(host string, known []string, usersFile, passesFile, dir string) (string, string, error) {
	users, err := readPoolLines(usersFile)
	if err != nil {
		return "", "", err
	}
	passes, err := readPoolLines(passesFile)
	if err != nil {
		return "", "", err
	}

	// Declared credentials first, deduplicated among themselves.
	seenU, seenP := make(map[string]bool), make(map[string]bool)
	var knownUsers, knownPasses []string
	for _, cred := range known {
		// Cut instead of splitCred: a blank user must be accepted here so
		// that ":pass" still contributes its password.
		u, p, ok := strings.Cut(cred, ":")
		if !ok {
			continue
		}
		if u != "" && !seenU[u] {
			seenU[u] = true
			knownUsers = append(knownUsers, u)
		}
		// A blank user with a known password still contributes the password:
		// pwneye crosses the pools, so it tries it with every username.
		if p != "" && !seenP[p] {
			seenP[p] = true
			knownPasses = append(knownPasses, p)
		}
	}
	if len(knownUsers) == 0 && len(knownPasses) == 0 {
		// Nothing the pools can express — only a blank user with a blank
		// password. Keep the shared pools untouched: that pair is sent as-is by
		// the HTTP and RTSP engines.
		return usersFile, passesFile, nil
	}

	// Shared pools behind them, without repeating anything above.
	users = append(knownUsers, unseen(users, seenU)...)
	passes = append(knownPasses, unseen(passes, seenP)...)

	if len(users) == 0 && len(passes) == 0 {
		return "", "", fmt.Errorf("pools vazios para %s", host)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	var usersPath, passesPath string
	if len(users) > 0 {
		usersPath = filepath.Join(dir, "pwneye-users-"+sanitize(host)+".txt")
		if err := os.WriteFile(usersPath, []byte(strings.Join(users, "\n")+"\n"), 0o600); err != nil {
			return "", "", err
		}
	}
	if len(passes) > 0 {
		passesPath = filepath.Join(dir, "pwneye-passes-"+sanitize(host)+".txt")
		if err := os.WriteFile(passesPath, []byte(strings.Join(passes, "\n")+"\n"), 0o600); err != nil {
			return "", "", err
		}
	}
	return usersPath, passesPath, nil
}

// unseen returns the entries of pool not already marked in seen.
func unseen(pool []string, seen map[string]bool) []string {
	var out []string
	for _, v := range pool {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// readPoolLines reads a pwneye pool file (one entry per line); an empty path
// or a missing file yields no entries.
func readPoolLines(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, nil
}

// PoolFromWordlist extracts unique usernames and passwords from "user:pass"
// lines, preserving first-appearance order and honouring the caps (0 = no cap).
func PoolFromWordlist(raw string, maxUsers, maxPasses int) (users, passes []string) {
	seenU, seenP := map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, pass, ok := splitCred(line)
		if !ok {
			continue
		}
		if !seenU[user] && (maxUsers <= 0 || len(users) < maxUsers) {
			seenU[user] = true
			users = append(users, user)
		}
		if !seenP[pass] && (maxPasses <= 0 || len(passes) < maxPasses) {
			seenP[pass] = true
			passes = append(passes, pass)
		}
		if (maxUsers > 0 && len(users) >= maxUsers) && (maxPasses > 0 && len(passes) >= maxPasses) {
			break
		}
	}
	return users, passes
}

// splitCred splits "user:pass" into its halves (the password may contain ':').
func splitCred(cred string) (string, string, bool) {
	parts := strings.SplitN(cred, ":", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// drivePrompts copies pwneye's output to the log while answering the prompts
// it blocks on. Answers are only sent for patterns the rule table recognises,
// so an unexpected prompt stalls the run instead of getting a blind "yes".
func drivePrompts(in io.WriteCloser, out io.Reader, logw io.Writer) {
	defer in.Close()
	buf := make([]byte, 2048)
	pending := ""
	for {
		n, err := out.Read(buf)
		if n > 0 {
			if logw != nil {
				logw.Write(buf[:n]) //nolint:errcheck
			}
			pending += string(buf[:n])
			if len(pending) > promptWindow {
				pending = pending[len(pending)-promptWindow:]
			}
			if answer, ok := answerFor(pending); ok {
				io.WriteString(in, answer+"\n") //nolint:errcheck
				pending = ""
			}
		}
		if err != nil {
			return
		}
	}
}

// answerFor inspects recent output and answers the prompt pwneye is waiting
// on. Destructive actions are always refused even though camrecon never asks
// for them — belt and braces.
func answerFor(raw string) (string, bool) {
	text := normalizePrompt(raw)
	switch {
	case containsAny(text,
		"factory-reset", "factory reset", "deface", "undeface", "reboot",
		"really want to", "proceed with the", "onvif shell"):
		return "n", true
	case strings.Contains(text, "exhaustive rtsp path scan"):
		return "n", true
	case strings.Contains(text, "select channel") || strings.Contains(text, "choice"):
		return "1", true
	case strings.Contains(text, "(y)es/(n)o") || strings.Contains(text, "do you want to"):
		return "y", true
	}
	return "", false
}

// normalizePrompt strips ANSI colouring and collapses whitespace so prompts
// that Rich wrapped over several lines still match.
func normalizePrompt(raw string) string {
	s := ansiRe.ReplaceAllString(raw, "")
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

func containsAny(text string, subs ...string) bool {
	for _, s := range subs {
		if strings.Contains(text, s) {
			return true
		}
	}
	return false
}

// PwneyeCachePath returns the per-host cache file pwneye writes (~/.pwneye).
func PwneyeCachePath(host string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".pwneye", "cache", sanitize(host)+".yaml")
	}
	return filepath.Join(home, ".pwneye", "cache", sanitize(host)+".yaml")
}

// sanitize mirrors pwneye's own cache filename rule (anything outside
// [A-Za-z0-9._-] becomes "_").
func sanitize(host string) string {
	return unsafeRe.ReplaceAllString(host, "_")
}

// LoadPwneyeResult reads pwneye's cache entry for a host.
func LoadPwneyeResult(host string) (PwneyeResult, error) {
	return parsePwneyeCache(PwneyeCachePath(host))
}

// flexString accepts any YAML scalar (pwneye dumps numeric passwords as
// integers) and keeps its textual form.
type flexString string

func (f *flexString) UnmarshalYAML(node *yaml.Node) error {
	*f = flexString(node.Value)
	return nil
}

func (f flexString) int() int {
	n, err := strconv.Atoi(strings.TrimSpace(string(f)))
	if err != nil {
		return 0
	}
	return n
}

func (f flexString) str() string {
	return strings.TrimSpace(string(f))
}

// cacheDoc mirrors ~/.pwneye/cache/<host>.yaml (see pwneye/core/storage/cache.py).
type cacheDoc struct {
	ONVIF struct {
		Supported    bool         `yaml:"supported"`
		Port         flexString   `yaml:"port"`
		Auth         cacheAuth    `yaml:"auth"`
		Manufacturer flexString   `yaml:"manufacturer"`
		Streams      []flexString `yaml:"streams"`
	} `yaml:"onvif"`
	RTSP struct {
		Supported bool       `yaml:"supported"`
		Port      flexString `yaml:"port"`
		Auth      cacheAuth  `yaml:"auth"`
		Path      flexString `yaml:"path"`
		Protocol  flexString `yaml:"protocol"`
		URL       flexString `yaml:"url"`
		Banner    struct {
			Port  flexString `yaml:"port"`
			Value flexString `yaml:"value"`
		} `yaml:"banner"`
		Channels []struct {
			Channel  flexString `yaml:"channel"`
			Port     flexString `yaml:"port"`
			Path     flexString `yaml:"path"`
			Protocol flexString `yaml:"protocol"`
			URL      flexString `yaml:"url"`
		} `yaml:"channels"`
	} `yaml:"rtsp"`
}

type cacheAuth struct {
	Username flexString `yaml:"username"`
	Password flexString `yaml:"password"`
}

func parsePwneyeCache(path string) (PwneyeResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return PwneyeResult{}, err
	}
	var doc cacheDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return PwneyeResult{}, fmt.Errorf("parse %s: %w", path, err)
	}

	var res PwneyeResult
	if doc.ONVIF.Supported || doc.ONVIF.Auth.Username.str() != "" {
		o := &PwneyeONVIF{
			Supported:    doc.ONVIF.Supported,
			Port:         doc.ONVIF.Port.int(),
			Username:     doc.ONVIF.Auth.Username.str(),
			Password:     doc.ONVIF.Auth.Password.str(),
			Manufacturer: doc.ONVIF.Manufacturer.str(),
		}
		for _, s := range doc.ONVIF.Streams {
			if v := s.str(); v != "" {
				o.Streams = append(o.Streams, v)
			}
		}
		res.ONVIF = o
	}
	if doc.RTSP.Supported || doc.RTSP.Auth.Username.str() != "" || doc.RTSP.URL.str() != "" {
		r := &PwneyeRTSP{
			Supported: doc.RTSP.Supported,
			Port:      doc.RTSP.Port.int(),
			Username:  doc.RTSP.Auth.Username.str(),
			Password:  doc.RTSP.Auth.Password.str(),
			Path:      doc.RTSP.Path.str(),
			Protocol:  doc.RTSP.Protocol.str(),
			URL:       doc.RTSP.URL.str(),
			Banner:    doc.RTSP.Banner.Value.str(),
		}
		for _, ch := range doc.RTSP.Channels {
			r.Channels = append(r.Channels, PwneyeChannel{
				Channel:  ch.Channel.int(),
				Port:     ch.Port.int(),
				Path:     ch.Path.str(),
				Protocol: ch.Protocol.str(),
				URL:      ch.URL.str(),
			})
		}
		res.RTSP = r
	}
	return res, nil
}
