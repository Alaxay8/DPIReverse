package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Alaxay8/dpireverse/pkg/model"
)

func TestRenderTextIncludesDetailedSections(t *testing.T) {
	engine := NewEngine()
	report := model.ScanReport{
		Target:      "youtube.com:443",
		Profile:     model.ProfileQuick,
		StartedAt:   time.Unix(0, 0).UTC(),
		CompletedAt: time.Unix(10, 0).UTC(),
		Results: []model.TestResult{
			{
				TestID:        "tls-baseline-chrome13",
				Name:          "TLS baseline Chrome-like",
				Attempts:      2,
				SuccessRate:   0,
				MeanLatencyMS: 150,
				Tags: map[string]string{
					"client_hello": "chrome",
					"tls_version":  "1.3",
					"sni_mode":     "target",
					"fragmented":   "false",
					"variant":      "baseline",
				},
				ErrorBreakdown: map[model.ErrorType]int{
					model.ErrorTypeTimeout: 2,
				},
			},
		},
		Analysis: model.AnalysisResult{
			Confidence: 0.8,
			Findings: []model.AnalysisFinding{
				{
					Key:        "fragmentation_bypass",
					Detected:   true,
					Confidence: 0.8,
					Summary:    "Fragmented TLS handshakes succeeded where the baseline handshake failed.",
					Evidence:   []string{"baseline success rate: 0.00"},
				},
			},
		},
	}

	rendered := engine.RenderText(report)
	for _, needle := range []string{
		"Resource:",
		"DPI Signals:",
		"Experiment Matrix:",
		"baseline TLS handshake",
	} {
		if !strings.Contains(rendered, needle) {
			t.Fatalf("RenderText() missing %q\n%s", needle, rendered)
		}
	}
}
