package analyzer

import (
	"fmt"
	"math"

	"github.com/Alaxay8/dpireverse/pkg/model"
)

type FragmentationBypassRule struct{}

func (FragmentationBypassRule) Evaluate(results []model.TestResult) model.AnalysisFinding {
	baseline := findResult(results, map[string]string{
		"scenario":     "tls",
		"variant":      "baseline",
		"client_hello": "chrome",
		"tls_version":  "1.3",
		"sni_mode":     "target",
		"fragmented":   "false",
	})
	fragmented := findResult(results, map[string]string{
		"scenario":     "tls",
		"client_hello": "chrome",
		"tls_version":  "1.3",
		"sni_mode":     "target",
		"fragmented":   "true",
	})

	if baseline == nil || fragmented == nil {
		return unavailableFinding("fragmentation_bypass", "Not enough fragmented TLS data to evaluate bypass behavior.")
	}

	diff := fragmented.SuccessRate - baseline.SuccessRate
	confidence := diffConfidence(diff, minAttempts(*baseline, *fragmented))
	detected := baseline.SuccessRate <= 0.34 && fragmented.SuccessRate >= 0.67 && diff >= 0.4

	summary := "No fragmentation bypass evidence observed."
	if detected {
		summary = "Fragmented TLS handshakes succeeded where the baseline handshake failed."
	}

	return model.AnalysisFinding{
		Key:        "fragmentation_bypass",
		Detected:   detected,
		Confidence: confidence,
		Summary:    summary,
		Evidence: []string{
			fmt.Sprintf("baseline success rate: %.2f", baseline.SuccessRate),
			fmt.Sprintf("fragmented success rate: %.2f", fragmented.SuccessRate),
		},
	}
}

type SNIFilteringRule struct{}

func (SNIFilteringRule) Evaluate(results []model.TestResult) model.AnalysisFinding {
	baseline := findResult(results, map[string]string{
		"scenario":     "tls",
		"variant":      "baseline",
		"client_hello": "chrome",
		"tls_version":  "1.3",
		"sni_mode":     "target",
		"fragmented":   "false",
	})
	empty := findResult(results, map[string]string{
		"scenario":     "tls",
		"client_hello": "chrome",
		"tls_version":  "1.3",
		"sni_mode":     "empty",
		"fragmented":   "false",
	})
	randomized := findResult(results, map[string]string{
		"scenario":     "tls",
		"client_hello": "chrome",
		"tls_version":  "1.3",
		"sni_mode":     "randomized",
		"fragmented":   "false",
	})

	if baseline == nil || (empty == nil && randomized == nil) {
		return unavailableFinding("sni_filtering", "Not enough SNI variation data to evaluate filtering.")
	}

	bestBypass := maxSuccessResult(empty, randomized)
	diff := bestBypass.SuccessRate - baseline.SuccessRate
	confidence := diffConfidence(diff, minAttempts(*baseline, *bestBypass))
	detected := baseline.SuccessRate <= 0.34 && bestBypass.SuccessRate >= 0.67 && diff >= 0.4

	summary := "No SNI filtering evidence observed."
	if detected {
		summary = "Baseline SNI failed while alternate SNI variants succeeded on the same endpoint."
	}

	evidence := []string{
		fmt.Sprintf("baseline SNI success rate: %.2f", baseline.SuccessRate),
	}
	if empty != nil {
		evidence = append(evidence, fmt.Sprintf("empty SNI success rate: %.2f", empty.SuccessRate))
	}
	if randomized != nil {
		evidence = append(evidence, fmt.Sprintf("randomized SNI success rate: %.2f", randomized.SuccessRate))
	}

	return model.AnalysisFinding{
		Key:        "sni_filtering",
		Detected:   detected,
		Confidence: confidence,
		Summary:    summary,
		Evidence:   evidence,
	}
}

type JA3BlockingRule struct{}

func (JA3BlockingRule) Evaluate(results []model.TestResult) model.AnalysisFinding {
	chrome := findResult(results, map[string]string{
		"scenario":     "tls",
		"client_hello": "chrome",
		"tls_version":  "1.3",
		"sni_mode":     "target",
		"fragmented":   "false",
	})
	randomized := findResult(results, map[string]string{
		"scenario":     "tls",
		"client_hello": "randomized",
		"tls_version":  "1.3",
		"sni_mode":     "target",
		"fragmented":   "false",
	})
	golang := findResult(results, map[string]string{
		"scenario":     "tls",
		"client_hello": "golang",
		"tls_version":  "1.3",
		"sni_mode":     "target",
		"fragmented":   "false",
	})

	bestSupported, leastSupported, ok := distinctSuccessExtrema(chrome, randomized, golang)
	if !ok {
		return unavailableFinding("ja3_blocking", "Not enough fingerprint variation data to evaluate JA3 blocking.")
	}

	diff := bestSupported.SuccessRate - leastSupported.SuccessRate
	confidence := diffConfidence(diff, minAttempts(*bestSupported, *leastSupported))
	detected := bestSupported.SuccessRate >= 0.67 && leastSupported.SuccessRate <= 0.34 && diff >= 0.4

	summary := "No JA3-based blocking evidence observed."
	if detected {
		summary = fmt.Sprintf(
			"TLS fingerprints showed materially different outcomes: %s outperformed %s.",
			bestSupported.Tags["client_hello"],
			leastSupported.Tags["client_hello"],
		)
	}

	evidence := []string{
		fmt.Sprintf("%s success rate: %.2f", bestSupported.Tags["client_hello"], bestSupported.SuccessRate),
		fmt.Sprintf("%s success rate: %.2f", leastSupported.Tags["client_hello"], leastSupported.SuccessRate),
	}

	return model.AnalysisFinding{
		Key:        "ja3_blocking",
		Detected:   detected,
		Confidence: confidence,
		Summary:    summary,
		Evidence:   evidence,
	}
}

func unavailableFinding(key, summary string) model.AnalysisFinding {
	return model.AnalysisFinding{
		Key:        key,
		Detected:   false,
		Confidence: 0.2,
		Summary:    summary,
	}
}

func findResult(results []model.TestResult, tags map[string]string) *model.TestResult {
	for i := range results {
		match := true
		for key, value := range tags {
			if results[i].Tags[key] != value {
				match = false
				break
			}
		}
		if match {
			return &results[i]
		}
	}

	return nil
}

func maxSuccessResult(candidates ...*model.TestResult) *model.TestResult {
	var best *model.TestResult
	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		if best == nil || candidate.SuccessRate > best.SuccessRate {
			best = candidate
		}
	}

	return best
}

func minSuccessResult(candidates ...*model.TestResult) *model.TestResult {
	var worst *model.TestResult
	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		if worst == nil || candidate.SuccessRate < worst.SuccessRate {
			worst = candidate
		}
	}

	return worst
}

func distinctSuccessExtrema(candidates ...*model.TestResult) (*model.TestResult, *model.TestResult, bool) {
	best := maxSuccessResult(candidates...)
	worst := minSuccessResult(candidates...)
	if best == nil || worst == nil {
		return nil, nil, false
	}

	if best != worst {
		return best, worst, true
	}

	for _, candidate := range candidates {
		if candidate != nil && candidate != best {
			return best, candidate, true
		}
	}

	return nil, nil, false
}

func minAttempts(left, right model.TestResult) int {
	if left.Attempts < right.Attempts {
		return left.Attempts
	}

	return right.Attempts
}

func diffConfidence(diff float64, attempts int) float64 {
	weight := math.Min(float64(attempts)/3.0, 1.0)
	return model.NormalizeConfidence(math.Abs(diff) * weight)
}
