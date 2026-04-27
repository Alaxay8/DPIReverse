package analyzer

import (
	"fmt"
	"log/slog"

	"github.com/Alaxay8/dpireverse/pkg/model"
)

type Rule interface {
	Evaluate([]model.TestResult) model.AnalysisFinding
}

type Engine struct {
	rules  []Rule
	logger *slog.Logger
}

func NewEngine(logger *slog.Logger) *Engine {
	return &Engine{
		logger: logger,
		rules: []Rule{
			FragmentationBypassRule{},
			SNIFilteringRule{},
			JA3BlockingRule{},
		},
	}
}

func (e *Engine) Analyze(results []model.TestResult) (model.AnalysisResult, error) {
	if len(results) == 0 {
		return model.AnalysisResult{}, fmt.Errorf("no measurements available for analysis")
	}

	analysis := model.AnalysisResult{
		Findings: make([]model.AnalysisFinding, 0, len(e.rules)),
	}

	var confidenceSum float64
	for _, rule := range e.rules {
		finding := rule.Evaluate(results)
		analysis.Findings = append(analysis.Findings, finding)
		confidenceSum += finding.Confidence

		switch finding.Key {
		case "fragmentation_bypass":
			analysis.DPIProfile.FragmentationBypass = finding.Detected
		case "sni_filtering":
			analysis.DPIProfile.SNIFiltering = finding.Detected
		case "ja3_blocking":
			analysis.DPIProfile.JA3Blocking = finding.Detected
		}

		if e.logger != nil {
			e.logger.Debug("rule evaluated",
				"rule", finding.Key,
				"detected", finding.Detected,
				"confidence", finding.Confidence,
			)
		}
	}

	analysis.Confidence = model.NormalizeConfidence(confidenceSum / float64(len(e.rules)))
	return analysis, nil
}
