package generator

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/Alaxay8/dpireverse/pkg/model"
)

type Generator interface {
	Generate(model.ScanRequest) ([]model.TestCase, error)
}

type DefaultGenerator struct{}

func NewDefaultGenerator() *DefaultGenerator {
	return &DefaultGenerator{}
}

func (g *DefaultGenerator) Generate(req model.ScanRequest) ([]model.TestCase, error) {
	repeats := req.Repeats
	if repeats <= 0 {
		repeats = 2
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	switch req.Profile {
	case "", model.ProfileQuick:
		return quickTLSProfile(req.Target, repeats, timeout), nil
	case model.ProfileFull:
		return fullTLSProfile(req.Target, repeats, timeout), nil
	default:
		return nil, fmt.Errorf("unsupported scan profile %q", req.Profile)
	}
}

func quickTLSProfile(target model.Target, repeats int, timeout time.Duration) []model.TestCase {
	return []model.TestCase{
		newTLSCase(target, "tls-baseline-chrome13", "TLS baseline Chrome-like", repeats, timeout, "tls-primary", map[string]string{
			"scenario":     "tls",
			"variant":      "baseline",
			"client_hello": "chrome",
			"tls_version":  "1.3",
			"sni_mode":     "target",
			"fragmented":   "false",
		}, model.TLSOptions{
			ServerName:         target.Host,
			ClientHelloProfile: "chrome",
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		}),
		newTLSCase(target, "tls-ja3-randomized13", "TLS randomized fingerprint", repeats, timeout, "tls-primary", map[string]string{
			"scenario":     "tls",
			"variant":      "ja3_randomized",
			"client_hello": "randomized",
			"tls_version":  "1.3",
			"sni_mode":     "target",
			"fragmented":   "false",
		}, model.TLSOptions{
			ServerName:         target.Host,
			ClientHelloProfile: "randomized",
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		}),
		newTLSCase(target, "tls-baseline-chrome12", "TLS 1.2 baseline Chrome-like", repeats, timeout, "tls-primary", map[string]string{
			"scenario":     "tls",
			"variant":      "tls12_baseline",
			"client_hello": "chrome",
			"tls_version":  "1.2",
			"sni_mode":     "target",
			"fragmented":   "false",
		}, model.TLSOptions{
			ServerName:         target.Host,
			ClientHelloProfile: "chrome",
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
		}),
		newTLSCase(target, "tls-fragmented-chrome13", "TLS fragmented ClientHello", repeats, timeout, "tls-primary", map[string]string{
			"scenario":     "tls",
			"variant":      "fragmented",
			"client_hello": "chrome",
			"tls_version":  "1.3",
			"sni_mode":     "target",
			"fragmented":   "true",
		}, model.TLSOptions{
			ServerName:         target.Host,
			ClientHelloProfile: "chrome",
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			Fragmentation: &model.FragmentationOptions{
				ChunkSize: 32,
				Delay:     20 * time.Millisecond,
			},
		}),
		newTLSCase(target, "tls-empty-sni-chrome13", "TLS empty SNI variant", repeats, timeout, "tls-primary", map[string]string{
			"scenario":     "tls",
			"variant":      "sni_empty",
			"client_hello": "chrome",
			"tls_version":  "1.3",
			"sni_mode":     "empty",
			"fragmented":   "false",
		}, model.TLSOptions{
			ServerName:         "",
			ClientHelloProfile: "chrome",
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		}),
	}
}

func fullTLSProfile(target model.Target, repeats int, timeout time.Duration) []model.TestCase {
	cases := quickTLSProfile(target, repeats, timeout)
	randomSNI := fmt.Sprintf("bypass-%s.invalid", target.Host)
	cases = append(cases,
		newTLSCase(target, "tls-random-sni-chrome13", "TLS randomized SNI variant", repeats, timeout, "tls-primary", map[string]string{
			"scenario":     "tls",
			"variant":      "sni_randomized",
			"client_hello": "chrome",
			"tls_version":  "1.3",
			"sni_mode":     "randomized",
			"fragmented":   "false",
		}, model.TLSOptions{
			ServerName:         randomSNI,
			ClientHelloProfile: "chrome",
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		}),
		newTLSCase(target, "tls-golang13", "TLS Go stdlib fingerprint", repeats, timeout, "tls-primary", map[string]string{
			"scenario":     "tls",
			"variant":      "ja3_golang",
			"client_hello": "golang",
			"tls_version":  "1.3",
			"sni_mode":     "target",
			"fragmented":   "false",
		}, model.TLSOptions{
			ServerName:         target.Host,
			ClientHelloProfile: "golang",
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		}),
		newTLSCase(target, "tls-fragmented-burst13", "TLS burst fragmentation", repeats, timeout, "tls-primary", map[string]string{
			"scenario":     "tls",
			"variant":      "fragmented_burst",
			"client_hello": "chrome",
			"tls_version":  "1.3",
			"sni_mode":     "target",
			"fragmented":   "true",
		}, model.TLSOptions{
			ServerName:         target.Host,
			ClientHelloProfile: "chrome",
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			Fragmentation: &model.FragmentationOptions{
				ChunkSize: 16,
				Delay:     5 * time.Millisecond,
			},
		}),
		model.TestCase{
			ID:       "http2-baseline",
			Name:     "HTTP/2 baseline request",
			Group:    "http-primary",
			Protocol: model.ProtocolHTTP2,
			Target:   target,
			Repeats:  repeats,
			Timeout:  timeout,
			Tags: map[string]string{
				"scenario": "http2",
				"variant":  "baseline",
			},
			HTTP: &model.HTTPOptions{
				Method: "GET",
				Path:   "/",
			},
		},
	)

	return cases
}

func newTLSCase(target model.Target, id, name string, repeats int, timeout time.Duration, group string, tags map[string]string, tlsOptions model.TLSOptions) model.TestCase {
	return model.TestCase{
		ID:       id,
		Name:     name,
		Group:    group,
		Protocol: model.ProtocolTLS,
		Target:   target,
		Repeats:  repeats,
		Timeout:  timeout,
		Tags:     tags,
		TLS:      &tlsOptions,
	}
}
