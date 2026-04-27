package measurement

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/Alaxay8/dpireverse/internal/transport"
	"github.com/Alaxay8/dpireverse/pkg/model"
)

type Engine struct {
	registry *transport.Registry
	logger   *slog.Logger
}

func NewEngine(registry *transport.Registry, logger *slog.Logger) *Engine {
	return &Engine{
		registry: registry,
		logger:   logger,
	}
}

func (e *Engine) Measure(ctx context.Context, test model.TestCase) (model.TestResult, error) {
	runner, err := e.registry.RunnerFor(test.Protocol)
	if err != nil {
		return model.TestResult{}, err
	}

	attempts := test.Repeats
	if attempts <= 0 {
		attempts = 1
	}

	timeout := test.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	result := model.TestResult{
		TestID:         test.ID,
		Name:           test.Name,
		Group:          test.Group,
		Protocol:       test.Protocol,
		Tags:           test.Tags,
		Attempts:       attempts,
		ErrorBreakdown: make(map[model.ErrorType]int),
		Measurements:   make([]model.Measurement, 0, attempts),
	}

	var totalLatency int64
	for attempt := 1; attempt <= attempts; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		metadata, runErr := runner.Run(attemptCtx, test)
		latency := time.Since(start)
		cancel()

		errType := classifyError(runErr)
		measurement := model.Measurement{
			TestID:    test.ID,
			Attempt:   attempt,
			Protocol:  test.Protocol,
			Success:   runErr == nil,
			LatencyMS: latency.Milliseconds(),
			ErrorType: errType,
			Timestamp: time.Now().UTC(),
			Metadata:  metadata,
		}
		if runErr != nil {
			measurement.ErrorMessage = runErr.Error()
			e.logger.Warn("measurement failed",
				"test_id", test.ID,
				"attempt", attempt,
				"error_type", errType,
				"error", runErr,
			)
		} else {
			e.logger.Info("measurement succeeded",
				"test_id", test.ID,
				"attempt", attempt,
				"latency_ms", measurement.LatencyMS,
			)
		}

		totalLatency += measurement.LatencyMS
		if measurement.Success {
			result.SuccessRate += 1
		}
		result.ErrorBreakdown[measurement.ErrorType]++
		result.Measurements = append(result.Measurements, measurement)

		if attempt < attempts {
			jitter := time.Duration(100+rand.Intn(400)) * time.Millisecond
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			case <-time.After(jitter):
			}
		}
	}

	result.SuccessRate = model.NormalizeConfidence(result.SuccessRate / float64(attempts))
	result.MeanLatencyMS = float64(totalLatency) / float64(attempts)
	return result, nil
}

func classifyError(err error) model.ErrorType {
	if err == nil {
		return model.ErrorTypeNone
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return model.ErrorTypeTimeout
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return model.ErrorTypeTimeout
	}

	if errors.Is(err, syscall.ECONNRESET) {
		return model.ErrorTypeRST
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return model.ErrorTypeRefused
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return model.ErrorTypeFIN
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.ECONNRESET) {
			return model.ErrorTypeRST
		}
		if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			return model.ErrorTypeRefused
		}
		if opErr.Timeout() {
			return model.ErrorTypeTimeout
		}
	}

	message := err.Error()
	switch {
	case containsAny(message, "tls", "handshake"):
		return model.ErrorTypeTLS
	case containsAny(message, "websocket", "http/1.1 101"):
		return model.ErrorTypeProtocol
	default:
		return model.ErrorTypeUnknown
	}
}

func containsAny(value string, needles ...string) bool {
	lowerValue := strings.ToLower(value)
	for _, needle := range needles {
		if needle != "" && strings.Contains(lowerValue, strings.ToLower(needle)) {
			return true
		}
	}

	return false
}
