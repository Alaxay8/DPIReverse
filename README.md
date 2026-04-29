# DPIReverse

[English](README.md) | [Русский](README.ru.md)

---

## Who is this for?

1. **Network Engineers & Researchers:** To analyze and understand censorship mechanisms and DPI behavior.
2. **Digital Rights Advocates & Activists:** To gather technical evidence of internet censorship and network interference.
3. **Developers of Circumvention Tools:** To gather data on how network traffic is blocked, helping to design better evasion strategies.

## Overview

DPIReverse is a black-box network analysis tool for inferring Deep Packet Inspection behavior from externally observable network effects.

The scanner generates controlled transport and TLS variations, measures how the path responds, and applies rule-based differential analysis to estimate likely filtering behavior.

Use DPIReverse only on networks and services you are authorized to test.

## Features

- Modular clean architecture with generator, transport, measurement, analyzer, orchestrator, and report layers.
- TLS-focused MVP with Chrome-like and randomized ClientHello profiles, TLS 1.2 and 1.3 coverage, SNI variations, and fragmented handshakes.
- Structured measurement output with latency, success state, and error classification.
- Pluggable rule engine for DPI behavior inference.
- Intelligent OSI-layered summary table (L3/L4/L7).
- SOCKS5 proxy support for anonymous scanning and research.
- Measurement Jitter to prevent rate-limiting and pattern detection.
- Human-readable CLI reports and machine-readable JSON output.
- **Auto-scan mode** with a built-in list of popular restricted resources.
- **HTTP/3 (QUIC) Support**: Specialized runner for UDP-based bypass analysis.
- **Throughput Measurement**: Integrated speed test for successful bypass strategies.

## Scanning Strategies

DPIReverse uses various techniques to identify filtering patterns:

- **TLS baseline Chrome-like**: A standard TLS 1.3 handshake mimicking a modern Chrome browser with a valid SNI (Server Name Indication). Used as a control test to see if the resource is blocked by default.
- **TLS empty SNI variant**: Sends a handshake without any SNI extension. Many DPI systems fail to identify the target domain when the SNI is missing.
- **TLS fragmented ClientHello**: Splits the initial handshake packet into small chunks (e.g., 32 bytes) with a slight delay. This often confuses DPI state machines.
- **TLS randomized fingerprint**: Uses a randomized JA3 signature to check if the filter blocks based on specific browser fingerprints.
- **TLS randomized SNI**: (Full profile) Sends a fake/random domain in the SNI field to check if the block is IP-based or purely SNI-based.
- **HTTP/3 (QUIC) Baseline**: (Full profile) Performs a native QUIC handshake. Success here often indicates that the network path allows UDP traffic that bypasses standard TCP-based DPI rules.

## Custom Resource Lists

You can provide your own list of domains for mass scanning using the `--file` flag. Two formats are supported:

### 1. Plain Text (.txt)
A simple list of domains, one per line. Lines starting with `#` are treated as comments.

```text
# My custom list
google.com
twitter.com
example.org
```

### 2. YAML (.yaml)
A structured format that allows grouping resources into categories and providing human-readable names.

```yaml
categories:
  - name: "Social Media"
    resources:
      - domain: "twitter.com"
        name: "X (Twitter)"
      - domain: "instagram.com"
        name: "Instagram"
  - name: "My Servers"
    resources:
      - domain: "vpn.example.com"
        name: "Home VPN"
```

```bash
go mod tidy
go run . scan youtube.com
```

### One-liner Installation (Linux & macOS)

```bash
wget -qO- https://raw.githubusercontent.com/Alaxay8/DPIReverse/v1.0.0/scripts/install.sh | bash
```

### One-liner Uninstallation

```bash
wget -qO- https://raw.githubusercontent.com/Alaxay8/DPIReverse/v1.0.0/scripts/uninstall.sh | bash
```

### Manual Installation

```bash
git clone https://github.com/Alaxay8/DPIReverse.git
cd DPIReverse
go build -o dpi .
```

## Usage

Run a quick text report:

```bash
dpi scan youtube.com --profile quick --format text
```

Run an automatic scan of built-in resources:

```bash
dpi scan auto
```

Run an automatic scan from a custom file (TXT or YAML):

```bash
dpi scan auto --file my_domains.txt
```

Common flags:

- `--target`: host name to scan.
- `--port`: destination port. Defaults to `443`.
- `--profile`: `quick` or `full`.
- `--proxy`: SOCKS5 proxy URL (e.g., `socks5://127.0.0.1:9050`).
- `--format`: `text` or `json`.
- `--repeats`: attempts per test case.
- `--file`, `-f`: path to a custom resources file (TXT or YAML).
- `--timeout`: per-attempt timeout such as `5s`.
- `--concurrency`: number of worker goroutines.
- `--log-level`: `debug`, `info`, or `warn`.
- `--speed`, `-s`: measure download speed for successful bypasses.

## Examples

Example text output:

```text
DPI Analysis Report
Target: example.com:443
Profile: quick
Window: 2026-04-12T10:00:00Z -> 2026-04-12T10:00:06Z
Overall confidence: 0.72

Findings:
- Baseline SNI failed while alternate SNI variants succeeded on the same endpoint. (Yes, confidence 0.84)
- Fragmented TLS handshakes succeeded where the baseline handshake failed. (Yes, confidence 0.76)
- No JA3-based blocking evidence observed. (No, confidence 0.28)
```

Example JSON snippet:

```json
{
  "analysis": {
    "dpi_profile": {
      "sni_filtering": true,
      "ja3_blocking": false,
      "fragmentation_bypass": true
    },
    "confidence": 0.72
  }
}
```

## Configuration

The current MVP ships with built-in `quick` and `full` TLS experiment profiles.

Each generated test case carries structured tags such as `client_hello`, `tls_version`, `sni_mode`, and `fragmented`. These tags are the contract used by the analyzer, which makes new transport experiments and new rules easy to add.

## Development

Run formatting and tests:

```bash
gofmt -w $(find . -name '*.go' -print)
go test ./...
```

Project layout:

```text
DPIReverse/
├── cmd/
├── configs/
├── internal/
│   ├── analyzer/
│   ├── generator/
│   ├── measurement/
│   ├── orchestrator/
│   ├── report/
│   └── transport/
├── pkg/
└── main.go
```

## License

MIT

