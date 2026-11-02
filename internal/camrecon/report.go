package camrecon

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

// WriteJSON writes the machine-readable report.
func WriteJSON(path string, rep Report) error {
	blob, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, blob, 0o600)
}

// RenderAccessTable prints the "access confirmed" list the operator asked for:
// one line per camera that the pipeline managed to get into.
func RenderAccessTable(w io.Writer, rep Report) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tDISPOSITIVO\tACESSO\tCREDENCIAL\tCVEs")
	fmt.Fprintln(tw, "----\t-----------\t------\t-----------\t----")
	for _, c := range rep.Access {
		creds := strings.Join(c.Credentials(), ", ")
		if creds == "" {
			creds = "(stream aberto)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			c.Host, c.Description(), strings.Join(c.Vectors(), "+"), creds, cveLabel(c.CVEs))
	}
	tw.Flush()
}

// RenderSummary prints the run counters.
func RenderSummary(w io.Writer, rep Report) {
	s := rep.Summary
	fmt.Fprintf(w, "alvos: %d | vivos: %d | câmeras: %d | CVEs mapeadas: %d\n",
		s.Targets, s.Live, s.Cameras, s.CVEs)
	fmt.Fprintf(w, "ACESSO CONFIRMADO: %d  (http %d | rtsp %d | onvif %d | streams abertos %d)\n",
		s.Access, s.HTTP, s.RTSP, s.ONVIF, s.OpenStreams)
}

// WriteMarkdown writes the human-readable report in plain language: a short
// front section anyone can follow, technical detail parked in the appendices.
func WriteMarkdown(path string, rep Report) error {
	var b strings.Builder
	renderMarkdown(&b, rep)
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func renderMarkdown(w io.Writer, rep Report) {
	s := rep.Summary

	// ---------------------------------------------------------------- topo
	fmt.Fprintln(w, "# 📹 Câmeras IP — o que encontramos (versão simples)")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Gerado em** %s · **comando** `camrecon %s` · **%d alvos testados**\n\n",
		rep.GeneratedAt, rep.Source, s.Targets)
	fmt.Fprintln(w, "> 🔒 **Este arquivo tem senhas em texto claro.** Não compartilhe, não mande por")
	fmt.Fprintln(w, "> mensagem e não suba para a nuvem. Trate como uma senha de cofre.")
	fmt.Fprintln(w, ">")
	fmt.Fprintln(w, "> ⚠️ **Arquivo automático:** o `camrecon` o reescreve a cada execução.")
	fmt.Fprintln(w, "> Não escreva anotações aqui — elas desaparecem no próximo scan.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "---")
	fmt.Fprintln(w)

	// --------------------------------------------------------- em uma frase
	var frase strings.Builder
	fmt.Fprintf(&frase, "Testamos %d endereços de câmeras: **%d estavam ligadas** e **%d aceitaram a senha**",
		s.Targets, s.Live, s.Access)
	if s.OpenStreams > 0 {
		fmt.Fprintf(&frase, " — e %d delas nem pedem senha para mostrar o vídeo", s.OpenStreams)
	}
	frase.WriteString(".")
	fmt.Fprintf(w, "## Em uma frase\n\n%s\n\n", frase.String())
	if left := s.Live - s.Access; left > 0 {
		fmt.Fprintf(w, "**As outras %d não deram acesso** — isso é bom: significa senha forte, porta "+
			"fechada ou que o endereço nem era câmera de verdade.\n\n", left)
	}

	// ------------------------------------------------------------ os números
	fmt.Fprintln(w, "## Os números")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Pergunta | Resposta |")
	fmt.Fprintln(w, "|---|---|")
	fmt.Fprintf(w, "| Endereços testados | %d |\n", s.Targets)
	fmt.Fprintf(w, "| Câmeras ligadas (respondendo) | %d |\n", s.Live)
	fmt.Fprintf(w, "| Câmeras / gravadores identificados | %d |\n", s.Cameras)
	fmt.Fprintf(w, "| **Câmeras com acesso confirmado** | **%d** |\n", s.Access)
	fmt.Fprintf(w, "| Vídeos abertos **sem** senha | %d |\n", s.OpenStreams)
	fmt.Fprintf(w, "| Falhas de segurança conhecidas (CVEs) | %d |\n", s.CVEs)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "---")
	fmt.Fprintln(w)

	// ------------------------------------------------- câmeras que abriram
	fmt.Fprintf(w, "## ⭐ As %d câmeras que abriram\n\n", len(rep.Access))
	if len(rep.Access) == 0 {
		fmt.Fprintln(w, "Nenhum acesso foi comprovado nesta execução.")
		fmt.Fprintln(w)
	} else {
		fmt.Fprintln(w, "O usuário e a senha já vêm **dentro do endereço**. É copiar, colar no VLC e")
		fmt.Fprintln(w, "pronto (veja o passo a passo logo abaixo).")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Nº | IP | Marca | Senha | Endereço do vídeo (copie e cole) |")
		fmt.Fprintln(w, "|---|---|---|---|---|")
		for i, c := range rep.Access {
			cred := "**nenhuma** (vídeo aberto)"
			if creds := c.Credentials(); len(creds) > 0 {
				cred = "`" + strings.Join(creds, "` `") + "`"
			}
			video := "—"
			if u := primaryRTSPURL(c); u != "" {
				video = "`" + mdEscape(u) + "`"
			}
			fmt.Fprintf(w, "| %d | `%s` | %s | %s | %s |\n",
				i+1, c.Host, mdEscape(c.Description()), cred, video)
		}
		fmt.Fprintln(w)

		if temPainel(rep.Access) {
			fmt.Fprintln(w, "**Painel web** (a tela de login no navegador) — quando existe:")
			fmt.Fprintln(w)
			fmt.Fprintln(w, "| Nº | Abrir no navegador |")
			fmt.Fprintln(w, "|---|---|")
			for i, c := range rep.Access {
				if u := webPanelURL(c); u != "" {
					fmt.Fprintf(w, "| %d | `%s` |\n", i+1, u)
				}
			}
			fmt.Fprintln(w)
			fmt.Fprintln(w, "> As câmeras que não aparecem na tabela acima não têm tela de login: só a")
			fmt.Fprintln(w, "> porta de vídeo (554) está aberta.")
			fmt.Fprintln(w, ">")
			fmt.Fprintln(w, "> **A senha do painel web pode ser diferente da senha do vídeo.** Em vários")
			fmt.Fprintln(w, "> modelos são cadastros separados — se uma funcionar e a outra não, é normal.")
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, "---")
		fmt.Fprintln(w)
	}

	// ------------------------------------------------- como abrir o vídeo
	fmt.Fprintln(w, "## ▶️ Como abrir o vídeo (30 segundos)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "1. Abra o **VLC** (baixe em <https://www.videolan.org>).")
	fmt.Fprintln(w, "2. Clique em **Mídia → Abrir stream de rede** (atalho `Ctrl+N`).")
	fmt.Fprintln(w, "3. Cole o endereço **RTSP** da tabela acima.")
	fmt.Fprintln(w, "4. Clique em **Play**. 🎬")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "No celular: **VLC para Android/iOS → Migalhas → Stream de rede**.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Por linha de comando (Linux/Mac), com aspas:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "```bash")
	exemplo := "rtsp://USUARIO:SENHA@HOST:554/caminho"
	if len(rep.Access) > 0 {
		if u := primaryRTSPURL(rep.Access[0]); u != "" {
			exemplo = u
		}
	}
	fmt.Fprintf(w, "ffplay '%s'\n", exemplo)
	fmt.Fprintln(w, "```")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "---")
	fmt.Fprintln(w)

	// --------------------------------------------------- remediação/checklist
	abertos := hostsComStreamAberto(rep.Access)
	var itens [][2]string
	itens = append(itens, [2]string{
		"Troque todas as senhas padrão",
		"as senhas da tabela acima são de fábrica e estão entre as mais conhecidas do " +
			"mundo; enquanto estiverem assim, qualquer pessoa com internet entra."})
	itens = append(itens, [2]string{
		"Troque a senha do painel web E a do vídeo",
		"são cadastros separados em vários modelos — trocar um não troca o outro."})
	itens = append(itens, [2]string{
		"Pare de expor a câmera na internet",
		"o ideal é deixá-la numa rede interna (VLAN) e acessar por VPN. Quem está na " +
			"internet enxerga a câmera — inclusive quem não deveria."})
	if len(abertos) > 0 {
		itens = append(itens, [2]string{
			fmt.Sprintf("Feche os %d vídeos abertos sem senha", len(abertos)),
			fmt.Sprintf("hoje qualquer um com o endereço vê o vídeo: %s.", strings.Join(abertos, ", "))})
	}
	if s.CVEs > 0 {
		itens = append(itens, [2]string{
			"Atualize o firmware",
			fmt.Sprintf("esta varredura apontou %d falhas de segurança conhecidas; procure a "+
				"versão nova no site do fabricante.", s.CVEs)})
	}
	itens = append(itens, [2]string{
		"Desative o que não usa",
		"ONVIF, Telnet e UPnP."})
	itens = append(itens, [2]string{
		"Fique de olho nos logs",
		"tentativa de login de IP desconhecido = alguém está batendo na porta."})

	fmt.Fprintln(w, "## 🔧 Remediação recomendada (o que fazer agora)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Faça nesta ordem — é o que resolve de verdade:")
	fmt.Fprintln(w)
	for i, it := range itens {
		fmt.Fprintf(w, "- [ ] **%d. %s** — %s\n", i+1, it[0], it[1])
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "---")
	fmt.Fprintln(w)

	// ------------------------------------------------------------ erros comuns
	fmt.Fprintln(w, "## ❓ Erros comuns e o que eles significam")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Você vê | O que é | O que fazer |")
	fmt.Fprintln(w, "|---|---|---|")
	fmt.Fprintln(w, "| Não conecta / `Connection refused` | A câmera desligou, mudou de IP ou a porta fechou | Confirme se o endereço ainda é o dela |")
	fmt.Fprintln(w, "| Pediu usuário e senha / `401 Unauthorized` | Senha errada ou digitada separada do endereço | Use o endereço da tabela, que já traz a senha embutida |")
	fmt.Fprintln(w, "| **`Invalid path`** (nos logs) | Aquele **endereço de vídeo** não existe naquele modelo — não é erro de senha | Use o RTSP correto; `/Streaming/Channels/101` é de Hikvision, por exemplo |")
	fmt.Fprintln(w, "| `Auth failed` (nos logs) | Usuário ou senha errados | Teste outra combinação |")
	fmt.Fprintln(w, "| `Errors` (nos logs) | Falha de rede / tempo esgotado | A câmera pode estar instável; espere e tente de novo |")
	fmt.Fprintln(w, "| Vídeo fica preto uns segundos | A câmera \"se cansou\" depois de muitas tentativas | Espere ~30 s e abra de novo |")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "> **Sobre o `Invalid path`:** ele é só um **contador** de tentativas que caíram")
	fmt.Fprintln(w, "> num endereço inexistente — **não** quer dizer que o IP está errado. O que")
	fmt.Fprintln(w, "> importa é o resultado final: se o resumo terminou com")
	fmt.Fprintln(w, "> `Working RTSP stream discovered`, o acesso foi comprovado.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "---")
	fmt.Fprintln(w)

	// --------------------------------------------------------------- glossário
	fmt.Fprintln(w, "## 📖 Palavras difíceis (glossário)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Palavra | Significado simples |")
	fmt.Fprintln(w, "|---|---|")
	fmt.Fprintln(w, "| **RTSP** | O \"cano\" por onde o vídeo corre. É o endereço que você cola no VLC. Costuma usar a porta **554**. |")
	fmt.Fprintln(w, "| **Porta** | Um número que diz qual serviço responde naquele endereço. 80 = site, 443 = site seguro, 554 = vídeo. |")
	fmt.Fprintln(w, "| **Painel web** | A tela de login da câmera no navegador. |")
	fmt.Fprintln(w, "| **Stream aberto** | Vídeo que aparece **sem senha**. Qualquer um com o endereço vê. |")
	fmt.Fprintln(w, "| **ONVIF** | Um \"idioma comum\" que quase toda câmera moderna fala para se apresentar e aceitar senha. |")
	fmt.Fprintln(w, "| **NVR / DVR** | O gravador que guarda o vídeo de várias câmeras ao mesmo tempo. |")
	fmt.Fprintln(w, "| **CVE** | Um código para uma falha já conhecida e corrigida pelo fabricante. \"CVE-2021-36260\" = falha de 2021. |")
	fmt.Fprintln(w, "| **Firmware** | O \"sistema operacional\" embutido dentro da câmera. |")
	fmt.Fprintln(w, "| **ip:porta,user,pass** | Formato da lista de alvos. O `,,` significa \"usuário e senha vazios\". |")
	fmt.Fprintln(w, "| **Hikvision / Intelbras** | Marcas de câmera. Hikvision = chinesa; Intelbras = brasileira. |")
	fmt.Fprintln(w)

	// -------------------------------------------------- apêndice A: técnico
	if len(rep.Access) > 0 {
		fmt.Fprintln(w, "---")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "## Apêndice A — detalhe técnico das câmeras")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Para quem precisa de portas, CVEs e endereços exatos de cada teste.")
		fmt.Fprintln(w)
		for i, c := range rep.Access {
			fmt.Fprintf(w, "### A%d. `%s` — %s\n\n", i+1, c.Host, mdEscape(c.Description()))
			if len(c.Ports) > 0 {
				fmt.Fprintf(w, "- Portas abertas: %s\n", joinInts(c.Ports))
			}
			if c.Server != "" {
				fmt.Fprintf(w, "- Banner HTTP: `%s`\n", mdEscape(c.Server))
			}
			if len(c.CVEs) > 0 {
				fmt.Fprintf(w, "- CVEs do firmware/linha: %s\n", strings.Join(c.CVEs, ", "))
			}
			for _, f := range c.Findings {
				switch f.Vector {
				case VectorHTTP:
					fmt.Fprintf(w, "- **HTTP** (`%s`): credencial `%s`", f.Source, f.Credential)
				case VectorRTSP:
					fmt.Fprintf(w, "- **RTSP** (`%s`): credencial `%s`", f.Source, f.Credential)
				case VectorONVIF:
					fmt.Fprintf(w, "- **ONVIF** (`%s`): credencial `%s`", f.Source, f.Credential)
				case VectorRTSPOpen:
					fmt.Fprintf(w, "- **Stream aberto** (`%s`): sem autenticação", f.Source)
				}
				if f.URL != "" {
					fmt.Fprintf(w, " — `%s`", mdEscape(f.URL))
				}
				if f.Note != "" {
					fmt.Fprintf(w, " (%s)", mdEscape(f.Note))
				}
				fmt.Fprintln(w)
			}
			if len(c.Streams) > 0 {
				fmt.Fprintf(w, "- Streams detectados: %s\n", "`"+strings.Join(c.Streams, "`, `")+"`")
			}
			fmt.Fprintln(w)
		}
	}

	// ------------------------------------------------ apêndice B: todos alvos
	if len(rep.Hosts) > 0 {
		fmt.Fprintln(w, "---")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "## Apêndice B — todos os alvos testados")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Lista técnica. Se você só queria o resultado, pule esta parte. Na coluna")
		fmt.Fprintln(w, "**ACESSO**, `sim` significa que a câmera é uma das listadas acima.")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| HOST | STATUS | TIPO | MARCA | PORTAS | ACESSO |")
		fmt.Fprintln(w, "|---|---|---|---|---|---|")
		for _, c := range rep.Hosts {
			access := "não"
			if c.Access {
				access = "**sim**"
			}
			fmt.Fprintf(w, "| `%s` | %s | %s | %s | %s | %s |\n",
				c.Host, c.Status, c.DeviceType, mdEscape(c.Description()),
				joinInts(c.Ports), access)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "---\n\nGerado por `camrecon` em %s.\n", time.Now().UTC().Format(time.RFC3339))
}

// primaryRTSPURL picks the one address worth copy-pasting: a URL that already
// carries the proven credential, falling back to a stream that needs none.
func primaryRTSPURL(c Camera) string {
	for _, f := range c.Findings {
		if f.Vector == VectorRTSP && f.URL != "" {
			return f.URL
		}
	}
	for _, f := range c.Findings {
		if f.Vector == VectorRTSPOpen && f.URL != "" {
			return f.URL
		}
	}
	return ""
}

// webPanelURL builds the browser link for a camera: the plain HTTP port when
// one is open, otherwise the lowest port that is not an RTSP port.
func webPanelURL(c Camera) string {
	if len(c.Ports) == 0 {
		return ""
	}
	for _, p := range c.Ports {
		if p == 80 {
			return "http://" + c.Host + "/"
		}
	}
	for _, p := range c.Ports {
		if p == 443 {
			return "https://" + c.Host + "/"
		}
	}
	best := 0
	for _, p := range c.Ports {
		if isRTSPPort(p) {
			continue
		}
		if best == 0 || p < best {
			best = p
		}
	}
	if best == 0 {
		return ""
	}
	return fmt.Sprintf("http://%s:%d/", c.Host, best)
}

func isRTSPPort(p int) bool {
	switch p {
	case 554, 555, 8554, 10554:
		return true
	}
	return false
}

func temPainel(cams []Camera) bool {
	for _, c := range cams {
		if webPanelURL(c) != "" {
			return true
		}
	}
	return false
}

// hostsComStreamAberto lists the cameras whose video answers with no password,
// each one backticked so it can be dropped straight into the checklist.
func hostsComStreamAberto(cams []Camera) []string {
	var out []string
	for _, c := range cams {
		for _, f := range c.Findings {
			if f.Vector == VectorRTSPOpen {
				out = append(out, "`"+c.Host+"`")
				break
			}
		}
	}
	return out
}

func cveLabel(cves []string) string {
	if len(cves) == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", len(cves))
}

func joinInts(in []int) string {
	if len(in) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(in))
	for _, n := range in {
		parts = append(parts, fmt.Sprintf("%d", n))
	}
	return strings.Join(parts, ",")
}

// mdEscape keeps user-controlled strings from breaking table rendering.
func mdEscape(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ").Replace(s)
}
