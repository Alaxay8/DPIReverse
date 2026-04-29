package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/Alaxay8/dpireverse/pkg/model"
)

type HTTP3Runner struct {
	logger   *slog.Logger
	proxyURL string
}

func (r *HTTP3Runner) Run(ctx context.Context, test model.TestCase) (map[string]string, error) {
	if test.HTTP3 == nil {
		test.HTTP3 = &model.HTTP3Options{
			Method: "GET",
			Path:   "/",
		}
	}

	// Note: Proxying UDP/QUIC is more complex than TCP. 
	// For now, we'll implement direct HTTP/3 check.
	// Future: Implement UDP over SOCKS5 if needed.

	tlsConfig := &tls.Config{
		ServerName:         test.Target.Host,
		InsecureSkipVerify: true,
	}

	if test.TLS != nil {
		if test.TLS.ServerName != "" {
			tlsConfig.ServerName = test.TLS.ServerName
		}
	}

	transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			MaxIdleTimeout: 10 * time.Second,
		},
	}
	defer transport.Close()

	client := &http.Client{
		Transport: transport,
	}

	method := test.HTTP3.Method
	if method == "" {
		method = "GET"
	}
	path := test.HTTP3.Path
	if path == "" {
		path = "/"
	}

	url := fmt.Sprintf("https://%s%s", test.Target.Address(), path)
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http3 request failed: %w", err)
	}
	defer resp.Body.Close()

	metadata := map[string]string{
		"proto":             resp.Proto,
		"status":            resp.Status,
		"negotiated_server": tlsConfig.ServerName,
	}

	return metadata, nil
}
