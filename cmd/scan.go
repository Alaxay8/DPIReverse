package cmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/Alaxay8/dpireverse/internal/analyzer"
	"github.com/Alaxay8/dpireverse/internal/generator"
	"github.com/Alaxay8/dpireverse/internal/measurement"
	"github.com/Alaxay8/dpireverse/internal/orchestrator"
	"github.com/Alaxay8/dpireverse/internal/report"
	"github.com/Alaxay8/dpireverse/internal/transport"
	"github.com/Alaxay8/dpireverse/pkg/model"
)

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	args = normalizeScanArgs(args)

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		target      string
		resource    string
		port        int
		profile     string
		output      string
		repeats     int
		timeout     time.Duration
		concurrency int
		logLevel    string
		proxy       string
	)

	fs.StringVar(&target, "target", "", "Target host to scan")
	fs.StringVar(&resource, "resource", "", "Resource host to scan")
	fs.IntVar(&port, "port", 443, "Target port")
	fs.StringVar(&profile, "profile", string(model.ProfileQuick), "Scan profile: quick or full")
	fs.StringVar(&output, "format", string(model.OutputText), "Output format: text or json")
	fs.IntVar(&repeats, "repeats", 2, "Number of attempts per test case")
	fs.DurationVar(&timeout, "timeout", 5*time.Second, "Per-attempt timeout")
	fs.IntVar(&concurrency, "concurrency", 4, "Concurrent test workers")
	fs.StringVar(&logLevel, "log-level", "info", "Log level: debug, info, warn")
	fs.StringVar(&proxy, "proxy", "", "Proxy URL (socks5:// or http://)")

	if err := fs.Parse(args); err != nil {
		return wrapCommandError(err, "parse flags")
	}

	resolvedTarget, err := resolveResource(target, resource, fs.Args())
	if err != nil {
		return err
	}

	if err := validateRequired(resolvedTarget, "resource"); err != nil {
		return err
	}

	level := new(slog.LevelVar)
	switch strings.ToLower(logLevel) {
	case "debug":
		level.Set(slog.LevelDebug)
	case "warn":
		level.Set(slog.LevelWarn)
	default:
		level.Set(slog.LevelInfo)
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	reporter := report.NewEngine()
	request := model.ScanRequest{
		Target: model.Target{
			Host: resolvedTarget,
			Port: port,
		},
		Profile:      model.Profile(profile),
		OutputFormat: model.OutputFormat(output),
		Repeats:      repeats,
		Timeout:      timeout,
		Concurrency:  concurrency,
		ProxyURL:     proxy,
	}

	registry := transport.NewRegistry(logger, proxy)
	service := orchestrator.NewService(
		generator.NewDefaultGenerator(),
		measurement.NewEngine(registry, logger),
		analyzer.NewEngine(logger),
		reporter,
		logger,
	)

	result, err := service.Run(ctx, request)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	switch request.OutputFormat {
	case model.OutputJSON:
		payload, err := reporter.RenderJSON(result)
		if err != nil {
			return fmt.Errorf("render json: %w", err)
		}
		_, err = stdout.Write(payload)
		return err
	case model.OutputText:
		_, err := io.WriteString(stdout, reporter.RenderText(result))
		return err
	default:
		return fmt.Errorf("unsupported output format %q", request.OutputFormat)
	}
}

func resolveResource(targetFlag, resourceFlag string, positionals []string) (string, error) {
	resolved := targetFlag
	if resourceFlag != "" {
		if resolved != "" && resolved != resourceFlag {
			return "", fmt.Errorf("target and resource must match when both are set")
		}
		resolved = resourceFlag
	}

	switch len(positionals) {
	case 0:
	case 1:
		if resolved != "" && resolved != positionals[0] {
			return "", fmt.Errorf("resource flag and positional resource must match when both are set")
		}
		resolved = positionals[0]
	default:
		return "", fmt.Errorf("expected at most one positional resource, got %d", len(positionals))
	}

	return resolved, nil
}

func normalizeScanArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}

	if strings.HasPrefix(args[0], "-") {
		return args
	}

	normalized := make([]string, 0, len(args)+2)
	normalized = append(normalized, "--resource", args[0])
	normalized = append(normalized, args[1:]...)
	return normalized
}
