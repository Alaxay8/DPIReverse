package cmd

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Alaxay8/dpireverse/internal/audit"
	"github.com/Alaxay8/dpireverse/internal/proxy"
)

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
	ansiBold   = "\033[1m"
)

func runScanProxy(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("scan proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		timeout durationFlag
		format  string
	)

	fs.Var(&timeout, "timeout", "Auditing timeout (e.g. 5s)")
	fs.StringVar(&format, "format", "text", "Output format (text or json)")

	if err := fs.Parse(args); err != nil {
		return wrapCommandError(err, "parse flags")
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		return fmt.Errorf("missing proxy link. Usage: dpi scan proxy <vless://...|trojan://...|ss://...>")
	}

	proxyLink := remaining[0]

	// Parse proxy link
	cfg, err := proxy.ParseURI(proxyLink)
	if err != nil {
		return fmt.Errorf("failed to parse proxy link: %w", err)
	}

	// Adjust timeout
	timeoutVal := timeout.Duration
	if timeoutVal <= 0 {
		timeoutVal = 6 * time.Second
	}

	// Perform audit
	fmt.Fprintf(stderr, "%s🔍 Auditing proxy server...%s\n", ansiCyan, ansiReset)
	engine := audit.NewEngine(timeoutVal)
	report, err := engine.Audit(ctx, cfg)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	// Render report
	if format == "json" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("serialize report to json: %w", err)
		}
		_, err = stdout.Write(data)
		return err
	}

	renderTextReport(stdout, report)
	return nil
}

func renderTextReport(w io.Writer, r *audit.Report) {
	fmt.Fprintf(w, "\n%s🚀 DPIReverse — Proxy Security & DPI Resistance Audit%s\n", ansiBold, ansiReset)
	fmt.Fprintf(w, "--------------------------------------------------------\n")
	fmt.Fprintf(w, "%sProtocol:%s %s\n", ansiBold, ansiReset, strings.ToUpper(string(r.Config.Protocol)))
	fmt.Fprintf(w, "%sHost:%s     %s:%d\n", ansiBold, ansiReset, r.Config.Host, r.Config.Port)
	if r.Config.Security != "" {
		fmt.Fprintf(w, "%sSecurity:%s %s\n", ansiBold, ansiReset, strings.ToUpper(r.Config.Security))
	}
	if r.Config.SNI != "" {
		fmt.Fprintf(w, "%sDecoy SNI:%s %s\n", ansiBold, ansiReset, r.Config.SNI)
	}
	if r.Config.Alias != "" {
		fmt.Fprintf(w, "%sAlias:%s    %s\n", ansiBold, ansiReset, r.Config.Alias)
	}
	fmt.Fprintf(w, "--------------------------------------------------------\n\n")

	for i, check := range r.Checks {
		statusStr := ""
		switch check.Status {
		case audit.StatusSuccess:
			statusStr = fmt.Sprintf("%s✅ SUCCESS%s", ansiGreen, ansiReset)
		case audit.StatusWarning:
			statusStr = fmt.Sprintf("%s⚠️  WARNING%s", ansiYellow, ansiReset)
		case audit.StatusDanger:
			statusStr = fmt.Sprintf("%s❌ DANGER %s", ansiRed, ansiReset)
		default:
			statusStr = fmt.Sprintf("%sℹ️  INFO  %s", ansiBlue, ansiReset)
		}

		fmt.Fprintf(w, "[%d/%d] %-12s | %s\n", i+1, len(r.Checks), statusStr, check.Summary)
		if check.Details != "" {
			lines := strings.Split(check.Details, "\n")
			for _, line := range lines {
				fmt.Fprintf(w, "      │ %s\n", line)
			}
		}
		fmt.Fprintln(w)
	}

	scoreColor := ansiGreen
	if r.Score < 50 {
		scoreColor = ansiRed
	} else if r.Score < 80 {
		scoreColor = ansiYellow
	}

	fmt.Fprintf(w, "========================================================\n")
	fmt.Fprintf(w, "🛡️  DPI Resistance Score: %s%d/100%s\n", scoreColor, r.Score, ansiReset)
	fmt.Fprintf(w, "========================================================\n")

	// Recommendations
	hasWarnings := false
	for _, check := range r.Checks {
		if check.Status == audit.StatusWarning || check.Status == audit.StatusDanger {
			hasWarnings = true
			break
		}
	}

	if hasWarnings {
		fmt.Fprintf(w, "\n%s💡 Recommended Mitigations:%s\n", ansiBold, ansiReset)
		for _, check := range r.Checks {
			if strings.Contains(check.Name, "Timing Side-channel") && (check.Status == audit.StatusWarning || check.Status == audit.StatusDanger) {
				fmt.Fprintf(w, "  • %sTiming Side-Channel Delay:%s Locate a REALITY decoy server that is geographically closer to your proxy server to reduce differential handshake latency side-channels.\n", ansiYellow, ansiReset)
			}
			if strings.Contains(check.Name, "Standard Go TLS") && (check.Status == audit.StatusWarning || check.Status == audit.StatusDanger) {
				fmt.Fprintf(w, "  • %sStandard TLS Fingerprints:%s Configure server-side rules to strictly reject non-browser/standard library fingerprints. Enforce uTLS clients matching Chrome/Firefox ClientHellos.\n", ansiYellow, ansiReset)
			}
			if strings.Contains(check.Name, "Active Probing") && (check.Status == audit.StatusWarning || check.Status == audit.StatusDanger) {
				fmt.Fprintf(w, "  • %sActive Probing Fallback:%s Ensure your proxy server acts like a real web server (e.g., returns Nginx 400 Bad Request or mirrors a website) when probed with arbitrary data. Do not allow connection resets (TCP RST).\n", ansiYellow, ansiReset)
			}
		}
		fmt.Fprintln(w)
	}
}

// durationFlag parses standard duration notation
type durationFlag struct {
	time.Duration
}

func (d *durationFlag) String() string {
	return d.Duration.String()
}

func (d *durationFlag) Set(value string) error {
	dur, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}
