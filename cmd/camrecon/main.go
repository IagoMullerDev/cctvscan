// Command camrecon runs the full IP camera assessment pipeline over an
// authorized target database (txt or csv): network discovery and
// fingerprinting (cctvscan/eyehack engine), CVE mapping, HTTP credential
// testing, RTSP credential testing (rtspbrute engine) and ONVIF/RTSP probing
// with pwneye — then writes a consolidated report of every camera it managed
// to get into.
//
// Usage:
//
//	camrecon ips.txt                 # full pipeline
//	camrecon db.csv -out rel         # custom report directory
//	camrecon ips.txt -reuse          # reuse <db>.results.json, only re-test access
//
// Everything it does is read-only against the target: pwneye is driven without
// any of its reboot/reset/deface/move actions, and no stream is recorded.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/postfix/cctvscan/internal/camrecon"
	"github.com/postfix/cctvscan/internal/credbrute"
	"github.com/postfix/cctvscan/internal/eyehack"
)

var (
	credsFlag        = flag.String("creds", "", "wordlist usuario:senha (padrão: mycreds.txt ao lado do banco)")
	outFlag          = flag.String("out", "acessos", "diretório dos relatórios")
	reuseFlag        = flag.Bool("reuse", false, "reaproveitar <db>.results.json existente em vez de escanear")
	skipRTSPFlag     = flag.Bool("skip-rtsp", false, "não testar credenciais RTSP")
	skipPwneyeFlag   = flag.Bool("skip-pwneye", false, "não rodar o pwneye")
	pwneyeBinFlag    = flag.String("pwneye", "pwneye", "binário do pwneye")
	pwneyeTOFlag     = flag.Duration("pwneye-timeout", 5*time.Minute, "prazo por host no pwneye")
	pwneyeWorkFlag   = flag.Int("pwneye-workers", 4, "hosts processados em paralelo pelo pwneye")
	pwneyeUsersFlag  = flag.String("pwneye-users", "", "lista de usuários para o pwneye (padrão: derivada da wordlist)")
	pwneyePassFlag   = flag.String("pwneye-passes", "", "lista de senhas para o pwneye (padrão: derivada da wordlist)")
	pwneyeKBFlag     = flag.Bool("pwneye-kb", false, "usar só a base interna de credenciais do pwneye")
	rtspWorkFlag     = flag.Int("rtsp-workers", 32, "endpoints RTSP testados em paralelo")
	rtspTOFlag       = flag.Duration("rtsp-timeout", 5*time.Second, "timeout de uma requisição RTSP")
	rtspOverallFlag  = flag.Duration("rtsp-overall", 30*time.Minute, "prazo total do teste RTSP (0 desativa)")
	portsFlag        = flag.String("ports", "", "faixa de portas (padrão: portas de câmera + servidores)")
	comprehensiveFlg = flag.Bool("comprehensive", false, "scan completo de 1000+ portas de câmera")
	rateFlag         = flag.Int("rate", 1000, "pacotes por segundo no masscan")
	scanTOFlag       = flag.Duration("scan-timeout", 30*time.Minute, "prazo total do scan de portas")
	debugFlag        = flag.Bool("debug", false, "saída detalhada")
	helpFlag         = flag.Bool("help", false, "mostrar ajuda")
)

func main() {
	flag.CommandLine.Parse(reorderArgs(os.Args[1:]))
	if *helpFlag || flag.NArg() == 0 {
		printHelp()
		os.Exit(0)
	}

	dbPath := flag.Arg(0)
	if _, err := os.Stat(dbPath); err != nil {
		log.Fatalf("banco de alvos não encontrado: %s", dbPath)
	}
	credsFile := resolveCredsFile(*credsFlag, dbPath)
	if _, err := os.Stat(credsFile); err != nil {
		fmt.Printf("aviso: wordlist %q não encontrada — testes HTTP/RTSP pulados (use -creds arquivo)\n", credsFile)
		credsFile = ""
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ---------- 1. discovery: port scan, fingerprint, CVEs, HTTP creds ----------
	res := mustLoadOrScan(ctx, dbPath, credsFile)
	cameras := make([]camrecon.Camera, 0, len(res.Hosts))
	for _, rec := range res.Hosts {
		cameras = append(cameras, camrecon.CameraFromRecord(rec))
	}
	fmt.Printf("\n%d host(s) carregados (%s)\n\n", len(cameras), eyehack.ResultsPath(dbPath))

	// ---------- 2. RTSP credential testing ----------
	curated := map[string][]int{}
	known := map[string][]string{}
	if reqs, err := eyehack.LoadHostRequests(dbPath); err == nil {
		for _, r := range reqs {
			if len(r.Ports) > 0 {
				curated[r.Host] = append(curated[r.Host], r.Ports...)
			}
		}
		known = eyehack.CredsByHost(reqs)
		if hosts, cands := len(known), countCreds(known); cands > 0 {
			fmt.Printf("credenciais do banco: %d candidato(s) em %d host(s) (inclui usuário/senha em branco) — testados antes da wordlist\n",
				cands, hosts)
		}
	}
	if !*skipRTSPFlag {
		runRTSP(ctx, cameras, credsFile, curated, known)
	}

	// ---------- 3. pwneye: ONVIF + vendor-aware RTSP ----------
	if !*skipPwneyeFlag {
		runPwneye(ctx, cameras, credsFile, known)
	}

	// ---------- 4. consolidated report ----------
	rep := camrecon.BuildReport(dbPath, credsFile, cameras)
	if err := os.MkdirAll(*outFlag, 0o755); err != nil {
		log.Fatalf("criar %s: %v", *outFlag, err)
	}
	jsonPath := filepath.Join(*outFlag, "acessos.json")
	mdPath := filepath.Join(*outFlag, "acessos.md")
	if err := camrecon.WriteJSON(jsonPath, rep); err != nil {
		log.Fatalf("gravar %s: %v", jsonPath, err)
	}
	if err := camrecon.WriteMarkdown(mdPath, rep); err != nil {
		log.Fatalf("gravar %s: %v", mdPath, err)
	}

	fmt.Println("\n=== resumo ===")
	camrecon.RenderSummary(os.Stdout, rep)
	fmt.Println("\n=== câmeras com acesso confirmado ===")
	if len(rep.Access) == 0 {
		fmt.Println("(nenhum acesso comprovado nesta execução)")
	} else {
		camrecon.RenderAccessTable(os.Stdout, rep)
	}
	fmt.Printf("\nrelatórios: %s · %s\n", jsonPath, mdPath)
	if *skipPwneyeFlag {
		fmt.Println("(pwneye desativado — apenas cctvscan/rtspbrute foram usados)")
	}
}

// mustLoadOrScan reuses saved results with -reuse, otherwise runs the
// cctvscan/eyehack discovery pipeline and saves them for later runs.
func mustLoadOrScan(ctx context.Context, dbPath, credsFile string) *eyehack.Results {
	resultsPath := eyehack.ResultsPath(dbPath)
	if *reuseFlag {
		res, err := eyehack.LoadResults(resultsPath)
		if err != nil {
			log.Fatalf("carregar resultados: %v", err)
		}
		if res != nil {
			fmt.Printf("Reaproveitando %d host(s) de %s\n", res.HostCount, resultsPath)
			return res
		}
		fmt.Println("Nenhum resultado salvo; escaneando...")
	}

	scanCtx, cancel := context.WithTimeout(ctx, positive(*scanTOFlag))
	defer cancel()
	res, err := eyehack.RunScan(scanCtx, dbPath, eyehack.ScanConfig{
		Ports:         *portsFlag,
		Comprehensive: *comprehensiveFlg,
		Rate:          *rateFlag,
		CredsFile:     credsFile,
		OutputDir:     *outFlag,
		Debug:         *debugFlag,
	})
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	if err := eyehack.SaveResults(resultsPath, res); err != nil {
		log.Fatalf("salvar resultados: %v", err)
	}
	fmt.Printf("Salvos %d host(s) em %s\n", res.HostCount, resultsPath)
	return res
}

// runRTSP tests RTSP credentials on every discovered RTSP endpoint.
func runRTSP(ctx context.Context, cameras []camrecon.Camera, credsFile string, curated map[string][]int, known map[string][]string) {
	var urls []string
	for _, c := range cameras {
		urls = append(urls, camrecon.RTSPURLs(c, curated[c.Host]...)...)
	}
	if len(urls) == 0 {
		fmt.Println("RTSP: nenhum endpoint descoberto; pulando")
		return
	}
	groups := credbrute.GroupRTSPURLs(urls)
	knownByKey := credsForGroups(groups, known)
	if credsFile == "" && len(knownByKey) == 0 {
		fmt.Println("RTSP: sem wordlist; pulando")
		return
	}
	fmt.Printf("RTSP: %d endpoint(s) (%d URL(s)) com %s\n", len(groups), len(urls), credsFile)
	if len(knownByKey) > 0 {
		fmt.Printf("RTSP: %d endpoint(s) com credencial(ais) declarada(s) no banco\n", len(knownByKey))
	}

	rtspCtx := ctx
	var cancel context.CancelFunc
	if *rtspOverallFlag > 0 {
		rtspCtx, cancel = context.WithTimeout(ctx, *rtspOverallFlag)
		defer cancel()
	}

	done := 0
	total := len(groups)
	results := credbrute.BruteRTSPBatchKnown(rtspCtx, groups, credsFile, knownByKey, *rtspTOFlag, *rtspWorkFlag,
		func(r credbrute.RTSPResult) {
			done++
			switch r.Outcome {
			case credbrute.RTSPCreds:
				fmt.Printf("[%3d/%d] CRED   %-42s %s\n", done, total, r.URL, r.Credential)
			case credbrute.RTSPPublic:
				fmt.Printf("[%3d/%d] OPEN   %-42s stream aberto\n", done, total, r.URL)
			case credbrute.RTSPAnyPassword:
				fmt.Printf("[%3d/%d] OPEN*  %-42s %s\n", done, total, r.URL, r.Note)
			}
		})
	camrecon.AttachRTSPResults(cameras, results)
}

// countCreds totals the credential candidates held for every host.
func countCreds(known map[string][]string) int {
	n := 0
	for _, cs := range known {
		n += len(cs)
	}
	return n
}

// credsForGroups indexes the credentials declared in the database by the
// "host:port" key the RTSP batch groups URLs with.
func credsForGroups(groups map[string][]string, byHost map[string][]string) map[string][]string {
	if len(byHost) == 0 {
		return nil
	}
	out := make(map[string][]string, len(groups))
	for key := range groups {
		host := key
		if h, _, err := net.SplitHostPort(key); err == nil {
			host = h
		}
		if c := byHost[host]; len(c) > 0 {
			out[key] = c
		}
	}
	return out
}

// runPwneye probes each camera-ish host with pwneye (ONVIF + RTSP).
func runPwneye(ctx context.Context, cameras []camrecon.Camera, credsFile string, known map[string][]string) {
	var pending []int
	for i, c := range cameras {
		if camrecon.IsPwneyeCandidate(c) {
			pending = append(pending, i)
		}
	}
	if len(pending) == 0 {
		fmt.Println("pwneye: nenhuma câmera candidata; pulando")
		return
	}

	logDir := filepath.Join(*outFlag, "logs")
	fmt.Printf("pwneye: %d host(s) candidato(s), %d em paralelo\n", len(pending), *pwneyeWorkFlag)

	usersFile, passesFile := *pwneyeUsersFlag, *pwneyePassFlag
	if usersFile == "" && passesFile == "" && !*pwneyeKBFlag && credsFile != "" {
		u, p, err := camrecon.DeriveUserPassFiles(credsFile, *outFlag,
			camrecon.MaxPwneyeUsers, camrecon.MaxPwneyePasses)
		if err != nil {
			fmt.Printf("pwneye: wordlist não derivada (%v) — usando a base interna do pwneye\n", err)
		} else {
			usersFile, passesFile = u, p
			fmt.Printf("pwneye: pools derivados da wordlist (%s × %s)\n",
				filepath.Base(u), filepath.Base(p))
		}
	}

	cfg := camrecon.PwneyeConfig{
		Bin:       *pwneyeBinFlag,
		Timeout:   *pwneyeTOFlag,
		UsersFile: usersFile,
		PassFile:  passesFile,
		LogDir:    logDir,
		Fresh:     !*reuseFlag,
	}

	// Credenciais declaradas no banco entram na frente dos pools deste host.
	// Em -pwneye-kb a base interna é preservada — essas credenciais já são
	// testadas nas etapas HTTP e RTSP.
	pools := map[string][2]string{}
	if !*pwneyeKBFlag {
		for _, idx := range pending {
			host := cameras[idx].Host
			if len(known[host]) == 0 {
				continue
			}
			u, p, err := camrecon.MergePwneyePools(host, known[host], usersFile, passesFile, logDir)
			if err != nil {
				fmt.Printf("pwneye: pools de %s não gerados: %v\n", host, err)
				continue
			}
			pools[host] = [2]string{u, p}
		}
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		sem  = make(chan struct{}, max(1, *pwneyeWorkFlag))
		done int
	)
	for _, idx := range pending {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			host := cameras[i].Host
			hostCfg := cfg
			if p, ok := pools[host]; ok {
				hostCfg.UsersFile, hostCfg.PassFile = p[0], p[1]
			}
			res, err := camrecon.RunPwneye(ctx, host, hostCfg)

			mu.Lock()
			defer mu.Unlock()
			done++
			if err != nil {
				fmt.Printf("[%3d/%d] %-42s %v\n", done, len(pending), host, err)
				return
			}
			camrecon.AttachPwneye(&cameras[i], res)
			switch {
			case res.ONVIF != nil && res.ONVIF.Username != "":
				fmt.Printf("[%3d/%d] ONVIF  %-42s %s:%s\n", done, len(pending), host,
					res.ONVIF.Username, res.ONVIF.Password)
			case res.RTSP != nil && res.RTSP.Username != "":
				fmt.Printf("[%3d/%d] RTSP   %-42s %s:%s\n", done, len(pending), host,
					res.RTSP.Username, res.RTSP.Password)
			case res.RTSP != nil && res.RTSP.URL != "":
				fmt.Printf("[%3d/%d] OPEN   %-42s %s\n", done, len(pending), host, res.RTSP.URL)
			default:
				fmt.Printf("[%3d/%d] %-46s sem acesso\n", done, len(pending), host)
			}
		}(idx)
	}
	wg.Wait()
}

// resolveCredsFile picks a wordlist: the explicit flag wins, otherwise the
// first existing candidate near the database file or the current directory.
func resolveCredsFile(explicit, dbPath string) string {
	if explicit != "" {
		return explicit
	}
	dir := filepath.Dir(dbPath)
	for _, cand := range []string{
		filepath.Join(dir, "mycreds.txt"),
		filepath.Join(dir, "cctvscan", "mycreds.txt"),
		filepath.Join(dir, "..", "mycreds.txt"),
		"mycreds.txt",
		"cctvscan/mycreds.txt",
		filepath.Join("..", "mycreds.txt"),
		"/etc/cctvscan/credentials.txt",
	} {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return "/etc/cctvscan/credentials.txt"
}

// positive guards a duration flag against zero/negative values.
func positive(d time.Duration) time.Duration {
	if d <= 0 {
		return 24 * time.Hour
	}
	return d
}

// reorderArgs moves flags ahead of positional arguments. Go's flag package
// stops at the first non-flag token, so `camrecon db.txt -reuse` would
// otherwise ignore every flag.
func reorderArgs(args []string) []string {
	var flags, positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if strings.Contains(name, "=") {
				continue
			}
			if f := flag.Lookup(name); f != nil {
				if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
					continue
				}
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

func printHelp() {
	fmt.Printf("Usage: %s [OPTIONS] <db-file>\n", os.Args[0])
	fmt.Println("\nRoda o pipeline completo de avaliação de câmeras IP sobre um banco de")
	fmt.Println("alvos autorizado (.txt ou .csv) e gera o relatório das câmeras em que")
	fmt.Println("o acesso foi comprovado:")
	fmt.Println("\n  1. cctvscan/eyehack  — scan de portas, fingerprint, CVEs, HTTP creds")
	fmt.Println("  2. rtspbrute         — credenciais RTSP (digest) por host:porta")
	fmt.Println("  3. pwneye            — ONVIF + RTSP com paths por fabricante")
	fmt.Println("\nSaídas em -out: acessos.json, acessos.md e logs/pwneye-<host>.log")
	fmt.Println("\nOptions:")
	flag.VisitAll(func(f *flag.Flag) {
		fmt.Printf("  -%-17s %s (default: %v)\n", f.Name, f.Usage, f.DefValue)
	})
	fmt.Println("\nExamples:")
	fmt.Printf("  %s ips.txt                        # pipeline completo\n", os.Args[0])
	fmt.Printf("  %s db.csv -out relatorios         # banco CSV, saída em relatorios/\n", os.Args[0])
	fmt.Printf("  %s ips.txt -reuse                 # só refaz os testes de acesso\n", os.Args[0])
	fmt.Printf("  %s ips.txt -skip-pwneye           # apenas cctvscan + rtspbrute\n", os.Args[0])
	fmt.Println("\nFormatos do banco:")
	fmt.Println("  txt: um IP ou CIDR por linha (# comentários); \"ip:porta\" testa só aquela porta")
	fmt.Println("       \"ip:porta,user,pass\" testa essa credencial antes da wordlist; campos vazios também")
	fmt.Println("       são testados (\",,\" = usuário e senha em branco, \",,senha\" = usuário em branco)")
	fmt.Println("  csv: coluna de IP detectada pelo cabeçalho (ip/host/address) ou pelo conteúdo")
	fmt.Println("\nWordlist (user:pass por linha, # comentários):")
	fmt.Println("  admin:admin")
	fmt.Println("  admin:12345")
	fmt.Println("\nUse somente em ativos com autorização explícita.")
}
