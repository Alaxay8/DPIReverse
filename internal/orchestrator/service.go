package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Alaxay8/dpireverse/internal/analyzer"
	"github.com/Alaxay8/dpireverse/internal/generator"
	"github.com/Alaxay8/dpireverse/internal/measurement"
	"github.com/Alaxay8/dpireverse/internal/report"
	"github.com/Alaxay8/dpireverse/pkg/model"
)

type Service struct {
	generator   generator.Generator
	measurement *measurement.Engine
	analyzer    *analyzer.Engine
	reporter    *report.Engine
	logger      *slog.Logger
}

func NewService(
	gen generator.Generator,
	measurementEngine *measurement.Engine,
	analyzerEngine *analyzer.Engine,
	reporter *report.Engine,
	logger *slog.Logger,
) *Service {
	return &Service{
		generator:   gen,
		measurement: measurementEngine,
		analyzer:    analyzerEngine,
		reporter:    reporter,
		logger:      logger,
	}
}

func (s *Service) Run(ctx context.Context, req model.ScanRequest) (model.ScanReport, error) {
	startedAt := time.Now().UTC()
	if s.logger != nil {
		s.logger.Info("scan started",
			"target", req.Target.Address(),
			"profile", req.Profile,
			"concurrency", req.Concurrency,
		)
	}

	tests, err := s.generator.Generate(req)
	if err != nil {
		return model.ScanReport{}, fmt.Errorf("generate tests: %w", err)
	}

	if len(tests) == 0 {
		return model.ScanReport{}, fmt.Errorf("generator returned no tests")
	}

	results, err := s.runMeasurements(ctx, tests, req.Concurrency)
	if err != nil {
		return model.ScanReport{}, err
	}

	analysis, err := s.analyzer.Analyze(results)
	if err != nil {
		return model.ScanReport{}, fmt.Errorf("analyze results: %w", err)
	}

	completedAt := time.Now().UTC()
	if s.logger != nil {
		s.logger.Info("scan completed",
			"target", req.Target.Address(),
			"profile", req.Profile,
			"tests", len(tests),
			"confidence", analysis.Confidence,
			"duration_ms", completedAt.Sub(startedAt).Milliseconds(),
		)
	}

	return s.reporter.Build(req, results, analysis, startedAt, completedAt), nil
}

func (s *Service) runMeasurements(ctx context.Context, tests []model.TestCase, concurrency int) ([]model.TestResult, error) {
	if concurrency <= 0 {
		concurrency = 1
	}

	type job struct {
		index int
		test  model.TestCase
	}
	type outcome struct {
		index  int
		result model.TestResult
		err    error
	}

	jobs := make(chan job)
	outcomes := make(chan outcome, len(tests))

	var wg sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				result, err := s.measurement.Measure(ctx, item.test)
				outcomes <- outcome{
					index:  item.index,
					result: result,
					err:    err,
				}
			}
		}()
	}

	go func() {
		for idx, test := range tests {
			jobs <- job{index: idx, test: test}
		}
		close(jobs)
		wg.Wait()
		close(outcomes)
	}()

	results := make([]model.TestResult, len(tests))
	for outcome := range outcomes {
		if outcome.err != nil {
			return nil, fmt.Errorf("measure %s: %w", tests[outcome.index].ID, outcome.err)
		}
		results[outcome.index] = outcome.result
	}

	return results, nil
}
