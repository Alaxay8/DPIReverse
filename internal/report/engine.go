package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Alaxay8/dpireverse/pkg/model"
)

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Build(req model.ScanRequest, results []model.TestResult, analysis model.AnalysisResult, startedAt, completedAt time.Time) model.ScanReport {
	measurements := make([]model.Measurement, 0)
	for _, result := range results {
		measurements = append(measurements, result.Measurements...)
	}

	return model.ScanReport{
		Target:       req.Target.Address(),
		Profile:      req.Profile,
		StartedAt:    startedAt,
		CompletedAt:  completedAt,
		Results:      results,
		Measurements: measurements,
		Analysis:     analysis,
	}
}

func (e *Engine) RenderJSON(report model.ScanReport) ([]byte, error) {
	payload, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}

	return append(payload, '\n'), nil
}

func (e *Engine) RenderText(report model.ScanReport) string {
	var buffer bytes.Buffer
	buffer.WriteString("DPI Analysis Report\n")
	buffer.WriteString(fmt.Sprintf("Resource: %s\n", report.Target))
	buffer.WriteString(fmt.Sprintf("Profile: %s\n", report.Profile))
	buffer.WriteString(fmt.Sprintf("Window: %s -> %s\n", report.StartedAt.Format(time.RFC3339), report.CompletedAt.Format(time.RFC3339)))
	buffer.WriteString(fmt.Sprintf("Overall confidence: %.2f\n\n", report.Analysis.Confidence))

	buffer.WriteString("DPI Signals:\n")
	for _, finding := range report.Analysis.Findings {
		status := "not detected"
		if finding.Detected {
			status = "detected"
		}
		buffer.WriteString(fmt.Sprintf("- %s: %s (confidence %.2f)\n", finding.Key, status, finding.Confidence))
		buffer.WriteString(fmt.Sprintf("  assessment: %s\n", finding.Summary))
		for _, evidence := range finding.Evidence {
			buffer.WriteString(fmt.Sprintf("  evidence: %s\n", evidence))
		}
	}

	buffer.WriteString("\nExperiment Matrix:\n")
	for _, result := range report.Results {
		buffer.WriteString(fmt.Sprintf("- %s\n", describeResult(result)))
		buffer.WriteString(fmt.Sprintf("  success rate: %.2f, avg latency: %.1f ms, dominant error: %s\n", result.SuccessRate, result.MeanLatencyMS, dominantError(result)))
		if note := resultNote(result); note != "" {
			buffer.WriteString(fmt.Sprintf("  note: %s\n", note))
		}
		if len(result.ErrorBreakdown) > 0 {
			parts := make([]string, 0, len(result.ErrorBreakdown))
			for _, key := range model.OrderedErrorKeys(result.ErrorBreakdown) {
				parts = append(parts, fmt.Sprintf("%s=%d", key, result.ErrorBreakdown[key]))
			}
			buffer.WriteString(fmt.Sprintf("  errors: %s\n", strings.Join(parts, ", ")))
		}
	}

	buffer.WriteString(e.renderSummaryTable(report))

	return buffer.String()
}

func (e *Engine) renderSummaryTable(report model.ScanReport) string {
	var (
		l3l4Status = "OK"
		l7Status   = "OK"
		verdict    = "No blocking detected"
	)

	hasBypassSuccess := false
	hasBaselineSuccess := false

	for _, res := range report.Results {
		isBypass := res.Tags["sni_mode"] == "empty" || res.Tags["sni_mode"] == "randomized"
		isBaseline := res.Tags["variant"] == "baseline" || res.Tags["variant"] == "tls12_baseline"

		if isBypass && res.SuccessRate > 0.1 {
			hasBypassSuccess = true
		}
		if isBaseline && res.SuccessRate > 0.1 {
			hasBaselineSuccess = true
		}
	}

	if !hasBypassSuccess && !hasBaselineSuccess {
		l3l4Status = "BLOCKED"
		l7Status   = "UNKNOWN"
		verdict    = "IP address or Port is unreachable (L3/L4 Block)"
	} else if hasBypassSuccess && !hasBaselineSuccess {
		l3l4Status = "OK"
		l7Status   = "FILTERED"
		verdict    = "Domain/SNI is filtered by DPI (L7 Block)"
	} else if !hasBypassSuccess && hasBaselineSuccess {
		l3l4Status = "OK"
		l7Status   = "OK*"
		verdict    = "Baseline works, but SNI variations fail (unusual behavior)"
	}

	return fmt.Sprintf(
		"\nConclusion Table:\n"+
			"+-----------------+-----------+--------------------------------+\n"+
			"| Layer           | Status    | Logic                          |\n"+
			"+-----------------+-----------+--------------------------------+\n"+
			"| L3/L4 (IP/Port) | %-9s | Connection establishment        |\n"+
			"| L7 (Domain/SNI) | %-9s | Deep Packet Inspection          |\n"+
			"+-----------------+-----------+--------------------------------+\n"+
			"Final Verdict: %s\n",
		l3l4Status, l7Status, verdict,
	)
}

func describeResult(result model.TestResult) string {
	if len(result.Tags) == 0 {
		return fmt.Sprintf("%s (%s)", result.Name, result.TestID)
	}

	scenario := result.Tags["scenario"]
	variant := result.Tags["variant"]
	clientHello := fallback(result.Tags["client_hello"], "default")
	tlsVersion := fallback(result.Tags["tls_version"], "default")
	sniMode := fallback(result.Tags["sni_mode"], "default")
	fragmented := result.Tags["fragmented"] == "true"
	role := roleForVariant(result)

	if scenario == "http2" {
		return fmt.Sprintf("%s: standard HTTP/2 request", role)
	}
	if scenario == "http3" {
		return fmt.Sprintf("%s: standard HTTP/3 (QUIC) request", role)
	}

	if fragmented {
		return fmt.Sprintf("%s: fragmented TLS handshake, client hello %s, TLS %s, SNI %s", role, clientHello, tlsVersion, sniMode)
	}

	handshakeKind := "TLS handshake"
	if variant == "baseline" || variant == "tls12_baseline" {
		handshakeKind = "baseline TLS handshake"
	}

	return fmt.Sprintf("%s: %s, client hello %s, TLS %s, SNI %s", role, handshakeKind, clientHello, tlsVersion, sniMode)
}

func roleForVariant(result model.TestResult) string {
	scenario := result.Tags["scenario"]
	variant := result.Tags["variant"]

	if scenario == "http2" {
		return "HTTP/2 baseline"
	}
	if scenario == "http3" {
		return "HTTP/3 baseline"
	}

	switch variant {
	case "baseline":
		return "baseline"
	case "fragmented":
		return "fragmented"
	case "fragmented_burst":
		return "fragmented burst"
	case "ja3_randomized":
		return "randomized fingerprint"
	case "ja3_golang":
		return "golang fingerprint"
	case "sni_empty":
		return "empty SNI"
	case "sni_randomized":
		return "randomized SNI"
	case "tls12_baseline":
		return "TLS 1.2 baseline"
	default:
		if variant == "" {
			return "experiment"
		}
		return variant
	}
}

func dominantError(result model.TestResult) model.ErrorType {
	if len(result.ErrorBreakdown) == 0 {
		return model.ErrorTypeUnknown
	}

	var (
		selected model.ErrorType
		count    int
	)
	for _, key := range model.OrderedErrorKeys(result.ErrorBreakdown) {
		if result.ErrorBreakdown[key] > count {
			selected = key
			count = result.ErrorBreakdown[key]
		}
	}

	return selected
}

func resultNote(result model.TestResult) string {
	switch result.Tags["variant"] {
	case "sni_empty":
		return "Empty SNI often fails on normal origin infrastructure. Treat it as supporting evidence only when compared against baseline and alternate SNI outcomes."
	case "fragmented", "fragmented_burst":
		return "If this variant succeeds while the baseline fails, the path likely does not fully reassemble the handshake before inspection."
	case "ja3_randomized", "ja3_golang":
		return "Use this variant to compare fingerprint sensitivity. A large delta against the baseline suggests TLS fingerprint-based blocking."
	default:
		scenario := result.Tags["scenario"]
		if scenario == "http3" {
			return "Tests if UDP-based QUIC traffic is allowed. Success here bypasses many TCP-based DPI inspection rules."
		}
		if scenario == "http2" {
			return "Standard application layer check over TCP/TLS."
		}

		if result.Tags["sni_mode"] == "target" {
			return "This is the control path for the requested resource."
		}
		return ""
	}
}

func fallback(value, alternative string) string {
	if value == "" {
		return alternative
	}

	return value
}
