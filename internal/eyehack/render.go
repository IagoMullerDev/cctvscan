package eyehack

import (
	"fmt"
	"io"
	"strings"
)

// RenderTable writes an aligned table of the given hosts to w.
func RenderTable(w io.Writer, hosts []HostRecord) {
	if len(hosts) == 0 {
		fmt.Fprintln(w, "No hosts matched.")
		return
	}

	headers := []string{"HOST", "STATUS", "TYPE", "PORTS", "VIDEO", "BRAND", "CREDS", "CVEs"}
	rows := make([][]string, 0, len(hosts))
	for _, h := range hosts {
		creds := h.Credentials
		if creds == "" {
			creds = "-"
		}
		video := "-"
		if h.Video {
			video = "yes"
		}
		brand := h.Brand
		if brand == "" {
			brand = "-"
		}
		rows = append(rows, []string{
			h.Host,
			h.Status,
			h.DeviceType,
			portsStr(h.Ports),
			video,
			brand,
			creds,
			cveStr(h.CVEs),
		})
	}

	// Column widths.
	widths := make([]int, len(headers))
	for i, hd := range headers {
		widths[i] = len(hd)
	}
	for _, r := range rows {
		for i, c := range r {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}

	writeRow(w, headers, widths)
	sep := make([]string, len(headers))
	for i, wd := range widths {
		sep[i] = strings.Repeat("-", wd)
	}
	writeRow(w, sep, widths)
	for _, r := range rows {
		writeRow(w, r, widths)
	}

	// Summary.
	c := CountByType(hosts)
	fmt.Fprintf(w, "\n%d host(s): %d live, %d down · camera=%d nvr=%d dvr=%d server=%d · video=%d creds=%d cve=%d\n",
		len(hosts), c[StatusLive], c[StatusDown],
		c[TypeCamera], c[TypeNVR], c[TypeDVR], c[TypeServer],
		c["video"], c["creds"], c["cve"])
}

func writeRow(w io.Writer, cells []string, widths []int) {
	var b strings.Builder
	for i, c := range cells {
		b.WriteString(c)
		if i < len(widths)-1 {
			b.WriteString(strings.Repeat(" ", widths[i]-len(c)+2))
		}
	}
	b.WriteByte('\n')
	io.WriteString(w, b.String())
}

func portsStr(ports []int) string {
	if len(ports) == 0 {
		return "-"
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	s := strings.Join(parts, ",")
	const max = 28
	if len(s) > max {
		return s[:max-1] + "…"
	}
	return s
}

func cveStr(cves []string) string {
	if len(cves) == 0 {
		return "-"
	}
	if len(cves) == 1 {
		return cves[0]
	}
	return fmt.Sprintf("%d CVEs", len(cves))
}
