package analyzer

import (
	"log/slog"
	"testing"

	"github.com/Alaxay8/dpireverse/pkg/model"
)

func TestAnalyzeDetectsFragmentationBypass(t *testing.T) {
	engine := NewEngine(slog.Default())
	results := []model.TestResult{
		testResult("baseline", 0.0, 3, map[string]string{
			"scenario":     "tls",
			"variant":      "baseline",
			"client_hello": "chrome",
			"tls_version":  "1.3",
			"sni_mode":     "target",
			"fragmented":   "false",
		}),
		testResult("fragmented", 1.0, 3, map[string]string{
			"scenario":     "tls",
			"variant":      "fragmented",
			"client_hello": "chrome",
			"tls_version":  "1.3",
			"sni_mode":     "target",
			"fragmented":   "true",
		}),
		testResult("sni-empty", 0.0, 3, map[string]string{
			"scenario":     "tls",
			"variant":      "sni_empty",
			"client_hello": "chrome",
			"tls_version":  "1.3",
			"sni_mode":     "empty",
			"fragmented":   "false",
		}),
		testResult("ja3-randomized", 0.0, 3, map[string]string{
			"scenario":     "tls",
			"variant":      "ja3_randomized",
			"client_hello": "randomized",
			"tls_version":  "1.3",
			"sni_mode":     "target",
			"fragmented":   "false",
		}),
	}

	analysis, err := engine.Analyze(results)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if !analysis.DPIProfile.FragmentationBypass {
		t.Fatalf("expected fragmentation bypass detection")
	}
}

func TestAnalyzeDetectsSNIFiltering(t *testing.T) {
	engine := NewEngine(slog.Default())
	results := []model.TestResult{
		testResult("baseline", 0.0, 3, map[string]string{
			"scenario":     "tls",
			"variant":      "baseline",
			"client_hello": "chrome",
			"tls_version":  "1.3",
			"sni_mode":     "target",
			"fragmented":   "false",
		}),
		testResult("empty", 1.0, 3, map[string]string{
			"scenario":     "tls",
			"variant":      "sni_empty",
			"client_hello": "chrome",
			"tls_version":  "1.3",
			"sni_mode":     "empty",
			"fragmented":   "false",
		}),
		testResult("randomized", 0.5, 3, map[string]string{
			"scenario":     "tls",
			"variant":      "sni_randomized",
			"client_hello": "chrome",
			"tls_version":  "1.3",
			"sni_mode":     "randomized",
			"fragmented":   "false",
		}),
	}

	analysis, err := engine.Analyze(results)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if !analysis.DPIProfile.SNIFiltering {
		t.Fatalf("expected SNI filtering detection")
	}
}

func TestAnalyzeDetectsJA3Blocking(t *testing.T) {
	engine := NewEngine(slog.Default())
	results := []model.TestResult{
		testResult("chrome", 1.0, 3, map[string]string{
			"scenario":     "tls",
			"variant":      "baseline",
			"client_hello": "chrome",
			"tls_version":  "1.3",
			"sni_mode":     "target",
			"fragmented":   "false",
		}),
		testResult("randomized", 0.0, 3, map[string]string{
			"scenario":     "tls",
			"variant":      "ja3_randomized",
			"client_hello": "randomized",
			"tls_version":  "1.3",
			"sni_mode":     "target",
			"fragmented":   "false",
		}),
	}

	analysis, err := engine.Analyze(results)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if !analysis.DPIProfile.JA3Blocking {
		t.Fatalf("expected JA3 blocking detection")
	}
}

func TestAnalyzeReturnsNoSignalsWhenBaselineSucceeds(t *testing.T) {
	engine := NewEngine(slog.Default())
	results := []model.TestResult{
		testResult("baseline", 1.0, 3, map[string]string{
			"scenario":     "tls",
			"variant":      "baseline",
			"client_hello": "chrome",
			"tls_version":  "1.3",
			"sni_mode":     "target",
			"fragmented":   "false",
		}),
		testResult("fragmented", 1.0, 3, map[string]string{
			"scenario":     "tls",
			"variant":      "fragmented",
			"client_hello": "chrome",
			"tls_version":  "1.3",
			"sni_mode":     "target",
			"fragmented":   "true",
		}),
		testResult("randomized", 1.0, 3, map[string]string{
			"scenario":     "tls",
			"variant":      "ja3_randomized",
			"client_hello": "randomized",
			"tls_version":  "1.3",
			"sni_mode":     "target",
			"fragmented":   "false",
		}),
	}

	analysis, err := engine.Analyze(results)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if analysis.DPIProfile.FragmentationBypass || analysis.DPIProfile.SNIFiltering || analysis.DPIProfile.JA3Blocking {
		t.Fatalf("expected no detections, got %+v", analysis.DPIProfile)
	}
}

func testResult(id string, successRate float64, attempts int, tags map[string]string) model.TestResult {
	return model.TestResult{
		TestID:      id,
		Attempts:    attempts,
		SuccessRate: successRate,
		Tags:        tags,
	}
}
