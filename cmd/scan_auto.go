package cmd

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"bufio"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Alaxay8/dpireverse/internal/analyzer"
	"github.com/Alaxay8/dpireverse/internal/generator"
	"github.com/Alaxay8/dpireverse/internal/measurement"
	"github.com/Alaxay8/dpireverse/internal/orchestrator"
	"github.com/Alaxay8/dpireverse/internal/report"
	"github.com/Alaxay8/dpireverse/internal/transport"
	"github.com/Alaxay8/dpireverse/pkg/model"
	"github.com/jedib0t/go-pretty/v6/table"
	"gopkg.in/yaml.v3"
)

//go:embed resources.yaml
var resourcesYAML []byte

type ResourcesConfig struct {
	Categories []ResourceCategory `yaml:"categories"`
}

type ResourceCategory struct {
	Name      string     `yaml:"name"`
	Resources []Resource `yaml:"resources"`
}

type Resource struct {
	Domain string `yaml:"domain"`
	Name   string `yaml:"name"`
}

type scanAutoResult struct {
	Resource Resource
	Category string
	Success  bool
	Strategy string
	Err      error
}

func runScanAuto(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("scan auto", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		port        int
		concurrency int
		proxy       string
		inputFile   string
	)

	fs.IntVar(&port, "port", 443, "Target port")
	fs.IntVar(&concurrency, "concurrency", 4, "Concurrent worker count")
	fs.StringVar(&proxy, "proxy", "", "Proxy URL (socks5:// or http://)")
	fs.StringVar(&inputFile, "file", "", "Path to custom resources file (YAML or TXT)")
	fs.StringVar(&inputFile, "f", "", "Path to custom resources file (shorthand)")

	if err := fs.Parse(args); err != nil {
		return wrapCommandError(err, "parse flags")
	}

	var config ResourcesConfig
	if inputFile != "" {
		cfg, err := loadResourcesFromFile(inputFile)
		if err != nil {
			return fmt.Errorf("failed to load resources from %s: %w", inputFile, err)
		}
		config = cfg
	} else {
		if err := yaml.Unmarshal(resourcesYAML, &config); err != nil {
			return fmt.Errorf("failed to parse built-in resources list: %w", err)
		}
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil)) // Disable logs for auto scan to keep console clean
	reporter := report.NewEngine()
	registry := transport.NewRegistry(logger, proxy)
	service := orchestrator.NewService(
		generator.NewDefaultGenerator(),
		measurement.NewEngine(registry, logger),
		analyzer.NewEngine(logger),
		reporter,
		logger,
	)

	var allTasks []func()
	resultChan := make(chan scanAutoResult, 100)
	var wg sync.WaitGroup

	for _, category := range config.Categories {
		for _, resource := range category.Resources {
			res := resource
			catName := category.Name
			task := func() {
				defer wg.Done()
				request := model.ScanRequest{
					Target: model.Target{
						Host: res.Domain,
						Port: port,
					},
					Profile:      model.ProfileQuick,
					OutputFormat: model.OutputText,
					Repeats:      1,
					Timeout:      3 * time.Second, // Shorter timeout for auto scan
					Concurrency:  2,
					ProxyURL:     proxy,
				}

				reportResult, err := service.Run(ctx, request)
				if err != nil {
					resultChan <- scanAutoResult{Resource: res, Category: catName, Success: false, Err: err}
					return
				}

				// Check report to see if anything worked
				success := false
				strategy := "BLOCKED"
				var successfulStrategies []string

				// Looking for successful tests
				for _, res := range reportResult.Results {
					if res.SuccessRate > 0 {
						success = true
						if res.Name == "TLS Baseline" {
							successfulStrategies = append(successfulStrategies, "Direct Access")
						} else {
							successfulStrategies = append(successfulStrategies, res.Name)
						}
					}
				}

				if success {
					if len(successfulStrategies) > 0 {
                        // If "Direct Access" is present, it's not blocked
                        directIndex := -1
                        for i, s := range successfulStrategies {
                            if s == "Direct Access" {
                                directIndex = i
                                break
                            }
                        }
                        if directIndex != -1 {
                            strategy = "Direct Access"
                        } else {
                            strategy = successfulStrategies[0] // pick the first successful bypass
                        }
					} else {
                        strategy = "SUCCESS"
                    }
				}

				resultChan <- scanAutoResult{
					Resource: res,
					Category: catName,
					Success:  success,
					Strategy: strategy,
				}
			}
			allTasks = append(allTasks, task)
		}
	}

	fmt.Fprintf(stdout, "Starting automatic scan of %d resources...\n", len(allTasks))
	startTime := time.Now()

	// Worker pool
	sem := make(chan struct{}, concurrency)
	go func() {
		for _, task := range allTasks {
			wg.Add(1)
			sem <- struct{}{}
			go func(t func()) {
				defer func() { <-sem }()
				t()
			}(task)
		}
		wg.Wait()
		close(resultChan)
	}()

	var results []scanAutoResult
	successCount := 0
	for res := range resultChan {
		results = append(results, res)
		if res.Success {
			successCount++
		}
	}

	duration := time.Since(startTime)

	// Draw table
	t := table.NewWriter()
	t.SetOutputMirror(stdout)
	t.AppendHeader(table.Row{"Category", "Resource Name", "Domain", "Status", "Strategy / Error"})

	for _, res := range results {
		status := "❌ BLOCKED"
		if res.Success {
			status = "✅ ACCESSIBLE"
		}
		
		info := res.Strategy
		if res.Err != nil {
			info = res.Err.Error()
            // Truncate long errors
            if len(info) > 40 {
                info = info[:37] + "..."
            }
		}

		t.AppendRow([]interface{}{
			res.Category,
			res.Resource.Name,
			res.Resource.Domain,
			status,
			info,
		})
	}

	t.AppendSeparator()
	t.SetStyle(table.StyleLight)
	t.Render()

	fmt.Fprintf(stdout, "\nScan completed in %v. Accessible: %d/%d\n", 
		duration.Round(10*time.Millisecond), successCount, len(allTasks))

	return nil
}

func loadResourcesFromFile(path string) (ResourcesConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ResourcesConfig{}, err
	}

	// Try YAML first
	var config ResourcesConfig
	if err := yaml.Unmarshal(data, &config); err == nil && len(config.Categories) > 0 {
		return config, nil
	}

	// Fallback to plain text (one domain per line)
	var resources []Resource
	scanner := bufio.NewScanner(os.NewFile(0, "stdin")) // Placeholder, using data below
	_ = scanner
	
	lines := bufio.NewScanner(strings.NewReader(string(data)))
	for lines.Scan() {
		domain := strings.TrimSpace(lines.Text())
		if domain == "" || strings.HasPrefix(domain, "#") {
			continue
		}
		resources = append(resources, Resource{
			Domain: domain,
			Name:   domain,
		})
	}

	if len(resources) == 0 {
		return ResourcesConfig{}, fmt.Errorf("no valid domains found in file")
	}

	return ResourcesConfig{
		Categories: []ResourceCategory{
			{
				Name:      "User List",
				Resources: resources,
			},
		},
	}, nil
}
