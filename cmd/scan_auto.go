package cmd

import (
	"context"
	_ "embed"
	"flag"
	"crypto/tls"
	"fmt"
	"io"
	"bufio"
	"log/slog"
	"net"
	"net/http"
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
	"github.com/schollz/progressbar/v3"
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
	Resource  Resource
	Category  string
	Success   bool
	Strategy  string
	SpeedKbps float64
	Err       error
}

func runScanAuto(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("scan auto", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		port        int
		concurrency int
		proxy       string
		inputFile   string
		showSpeed   bool
	)

	fs.IntVar(&port, "port", 443, "Target port")
	fs.IntVar(&concurrency, "concurrency", 4, "Concurrent worker count")
	fs.StringVar(&proxy, "proxy", "", "Proxy URL (socks5:// or http://)")
	fs.StringVar(&inputFile, "file", "", "Path to custom resources file (YAML or TXT)")
	fs.StringVar(&inputFile, "f", "", "Path to custom resources file (shorthand)")
	fs.BoolVar(&showSpeed, "speed", false, "Measure download speed for accessible resources")
	fs.BoolVar(&showSpeed, "s", false, "Measure download speed (shorthand)")

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
						// Normalize "Direct Access" or baseline names (both 1.3 and 1.2)
						directFound := false
						for _, s := range successfulStrategies {
							if s == "Direct Access" || s == "TLS baseline Chrome-like" || s == "TLS 1.2 baseline Chrome-like" {
								directFound = true
								break
							}
						}
						if directFound {
							strategy = "Direct Access"
						} else {
							strategy = successfulStrategies[0] // pick the first successful bypass
						}
					} else {
						strategy = "SUCCESS"
					}

					// Measure speed if requested
					if showSpeed {
						speed, _ := measureThroughput(ctx, res.Domain, port, proxy)
						resultChan <- scanAutoResult{
							Resource:  res,
							Category:  catName,
							Success:   true,
							Strategy:  strategy,
							SpeedKbps: speed,
						}
						return
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
	bar := progressbar.Default(int64(len(allTasks)))
	startTime := time.Now()

	// Worker pool
	sem := make(chan struct{}, concurrency)
	go func() {
		for _, task := range allTasks {
			wg.Add(1)
			sem <- struct{}{}
			go func(t func()) {
				defer func() {
					<-sem
					_ = bar.Add(1)
				}()
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
	header := table.Row{"Category", "Resource Name", "Domain", "Status", "Strategy / Error"}
	if showSpeed {
		header = append(header, "Speed")
	}
	t.AppendHeader(header)

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

		row := table.Row{
			res.Category,
			res.Resource.Name,
			res.Resource.Domain,
			status,
			info,
		}
		if showSpeed {
			speedStr := "-"
			if res.Success {
				if res.SpeedKbps > 1024 {
					speedStr = fmt.Sprintf("%.2f Mbps", res.SpeedKbps/1024)
				} else {
					speedStr = fmt.Sprintf("%.1f Kbps", res.SpeedKbps)
				}
			}
			row = append(row, speedStr)
		}
		t.AppendRow(row)
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

func measureThroughput(ctx context.Context, domain string, port int, proxy string) (float64, error) {
	// Create a custom transport that uses our ProxyDialer
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return transport.ProxyDialer(ctx, network, addr, proxy)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
		},
	}
	
	client := &http.Client{
		Transport: tr,
		Timeout:   7 * time.Second,
	}

	url := fmt.Sprintf("https://%s:%d/", domain, port)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}
	// Use a common user agent to avoid being blocked by WAF/Bot protection
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// Read body for up to 3 seconds
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var totalBytes int64
	buf := make([]byte, 32*1024)
	
	downloadStart := time.Now()
	for {
		select {
		case <-timeoutCtx.Done():
			goto done
		default:
			n, err := resp.Body.Read(buf)
			totalBytes += int64(n)
			if err != nil {
				goto done
			}
		}
	}

done:
	elapsed := time.Since(downloadStart).Seconds()
	if elapsed <= 0 {
		// If we finished instantly (small page), use time from request start to get some data
		elapsed = time.Since(start).Seconds()
	}

	if elapsed <= 0 {
		return 0, nil
	}

	kbps := (float64(totalBytes) * 8) / (elapsed * 1024)
	return kbps, nil
}
