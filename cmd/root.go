package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
)

func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if err := run(ctx, args, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	return 0
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}

	switch args[0] {
	case "scan":
		if len(args) > 1 && args[1] == "auto" {
			return runScanAuto(ctx, args[2:], stdout, stderr)
		}
		return runScan(ctx, args[1:], stdout, stderr)
	case "help":
		printDetailedHelp(stdout)
		return nil
	case "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "DPIReverse — Black-box network analysis tool for DPI behavior inference.")
	fmt.Fprintln(w, "\nUsage:")
	fmt.Fprintln(w, "  dpi scan <resource> [--profile quick|full] [--format text|json] [--repeats N] [--proxy URL]")
	fmt.Fprintln(w, "  dpi scan auto       # Auto-scan built-in popular resources")
	fmt.Fprintln(w, "\nExamples:")
	fmt.Fprintln(w, "  dpi scan auto")
	fmt.Fprintln(w, "  dpi scan youtube.com")
	fmt.Fprintln(w, "  dpi scan youtube.com --profile full --repeats 3 --format json")
	fmt.Fprintln(w, "\nTry 'dpi help' for detailed information or 'dpi scan --help' for all flags.")
}

func printDetailedHelp(w io.Writer) {
	fmt.Fprintln(w, "DPIReverse: Detailed Help")
	fmt.Fprintln(w, "=========================")
	fmt.Fprintln(w, "\nDPIReverse performs differential analysis by varying TLS and Transport parameters")
	fmt.Fprintln(w, "to detect filtering at different layers (L3/L4/L7).")

	fmt.Fprintln(w, "\nUsage Examples:")
	fmt.Fprintln(w, "  dpi scan auto                                    # Scan built-in popular domains")
	fmt.Fprintln(w, "  dpi scan youtube.com                             # Quick report")
	fmt.Fprintln(w, "  dpi scan youtube.com --format json > report.json # Export to JSON")
	fmt.Fprintln(w, "  dpi scan instagram.com --profile full            # Deep analysis")
	fmt.Fprintln(w, "  dpi scan twitter.com --proxy socks5://localhost  # Scan via proxy")

	fmt.Fprintln(w, "\nScan Profiles (--profile):")
	fmt.Fprintln(w, "  quick (default):")
	fmt.Fprintln(w, "    - Baseline TLS 1.3 & 1.2 (Chrome-like)")
	fmt.Fprintln(w, "    - Randomized JA3 fingerprint")
	fmt.Fprintln(w, "    - Fragmented ClientHello (32-byte chunks)")
	fmt.Fprintln(w, "    - Empty SNI check")

	fmt.Fprintln(w, "  full:")
	fmt.Fprintln(w, "    - All 'quick' experiments")
	fmt.Fprintln(w, "    - Randomized SNI (spoofing)")
	fmt.Fprintln(w, "    - Go standard library fingerprint")
	fmt.Fprintln(w, "    - Burst fragmentation (16-byte chunks)")
	fmt.Fprintln(w, "    - HTTP/2 baseline request")

	fmt.Fprintln(w, "\nCommon Flags:")
	fmt.Fprintln(w, "  --repeats      Number of attempts per test case (default 2)")
	fmt.Fprintln(w, "  --proxy        SOCKS5 proxy URL (e.g., socks5://127.0.0.1:9050)")
	fmt.Fprintln(w, "  --concurrency  Concurrent worker count (default 4)")
	fmt.Fprintln(w, "  --format       Output format: text (human) or json (machine)")
}

func validateRequired(value, name string) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}

	return nil
}

func wrapCommandError(err error, command string) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, io.EOF) {
		return fmt.Errorf("%s failed: unexpected EOF", command)
	}

	return fmt.Errorf("%s failed: %w", command, err)
}
