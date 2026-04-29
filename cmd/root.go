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
	fmt.Fprintln(w, "🚀 DPIReverse — Advanced Black-box Network Analysis Tool")
	fmt.Fprintln(w, "Inference and bypass of DPI (Deep Packet Inspection) filtering strategies.")
	fmt.Fprintln(w, "\nUsage:")
	fmt.Fprintln(w, "  dpi scan <domain> [flags]    Perform analysis on a specific target")
	fmt.Fprintln(w, "  dpi scan auto [flags]      Automated scan of pre-defined popular resources")
	fmt.Fprintln(w, "  dpi help                   Show detailed explanation of capabilities")
	fmt.Fprintln(w, "\nCore Capabilities:")
	fmt.Fprintln(w, "  • Fingerprint Spoofing (JA3, uTLS)")
	fmt.Fprintln(w, "  • Multi-layer Analysis (TCP, TLS, HTTP/2, HTTP/3)")
	fmt.Fprintln(w, "  • Packet Fragmentation (bypass testing)")
	fmt.Fprintln(w, "  • SOCKS5/HTTP Proxy Support")
	fmt.Fprintln(w, "\nQuick Start:")
	fmt.Fprintln(w, "  dpi scan google.com")
	fmt.Fprintln(w, "  dpi scan auto --speed")
}

func printDetailedHelp(w io.Writer) {
	fmt.Fprintln(w, "DPIReverse: Capability Overview")
	fmt.Fprintln(w, "==============================")
	fmt.Fprintln(w, "\nDPIReverse performs differential analysis by varying protocol parameters")
	fmt.Fprintln(w, "to detect filtering and identify potential bypass strategies.")

	fmt.Fprintln(w, "\nSupported Protocols & Layers:")
	fmt.Fprintln(w, "  L4: TCP, UDP (Raw connectivity checks)")
	fmt.Fprintln(w, "  L7: TLS (1.2, 1.3), HTTP/2, HTTP/3 (QUIC), WebSocket")

	fmt.Fprintln(w, "\nScan Profiles (--profile):")
	fmt.Fprintln(w, "  quick (default):")
	fmt.Fprintln(w, "    - Baseline TLS 1.3 & 1.2 (Chrome-like)")
	fmt.Fprintln(w, "    - Randomized JA3 fingerprints")
	fmt.Fprintln(w, "    - Basic TLS Fragmentation (32-byte chunks)")
	fmt.Fprintln(w, "    - Empty SNI verification")

	fmt.Fprintln(w, "  full:")
	fmt.Fprintln(w, "    - Everything in 'quick'")
	fmt.Fprintln(w, "    - Randomized SNI (Domain spoofing)")
	fmt.Fprintln(w, "    - Go standard library fingerprints")
	fmt.Fprintln(w, "    - Aggressive Fragmentation (16-byte chunks)")
	fmt.Fprintln(w, "    - HTTP/2 & HTTP/3 (QUIC) baseline validation")

	fmt.Fprintln(w, "\nAdvanced Features:")
	fmt.Fprintln(w, "  --speed        Measure download throughput for successful bypasses")
	fmt.Fprintln(w, "  --proxy        Route traffic through SOCKS5/HTTP proxy")
	fmt.Fprintln(w, "  --concurrency  Adjust worker pool size for faster bulk scanning")

	fmt.Fprintln(w, "\nExample Usage:")
	fmt.Fprintln(w, "  dpi scan auto --concurrency 8 --speed")
	fmt.Fprintln(w, "  dpi scan youtube.com --profile full --format json")
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
