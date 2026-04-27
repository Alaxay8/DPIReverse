package transport

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"golang.org/x/net/http2"
	utls "github.com/refraction-networking/utls"

	"github.com/Alaxay8/dpireverse/pkg/model"
)

type HTTP2Runner struct {
	logger   *slog.Logger
	proxyURL string
}

func (r *HTTP2Runner) Run(ctx context.Context, test model.TestCase) (map[string]string, error) {
	if test.HTTP == nil {
		test.HTTP = &model.HTTPOptions{
			Method: "GET",
			Path:   "/",
		}
	}

	rawConn, err := ProxyDialer(ctx, "tcp", test.Target.Address(), r.proxyURL)
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	uTlsConfig := &utls.Config{
		ServerName:         test.Target.Host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	if test.TLS != nil {
		if test.TLS.ServerName != "" {
			uTlsConfig.ServerName = test.TLS.ServerName
		}
		uTlsConfig.MinVersion = test.TLS.MinVersion
		uTlsConfig.MaxVersion = test.TLS.MaxVersion
	}

	clientHelloID := utls.HelloChrome_Auto
	if test.TLS != nil {
		clientHelloID = GetClientHelloID(test.TLS.ClientHelloProfile)
	}

	uConn := utls.UClient(rawConn, uTlsConfig, clientHelloID)
	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}
	defer uConn.Close()

	state := uConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		return nil, fmt.Errorf("http/2 not negotiated: %s", state.NegotiatedProtocol)
	}

	tr := &http2.Transport{
		AllowHTTP: true,
	}

	cc, err := tr.NewClientConn(uConn)
	if err != nil {
		return nil, fmt.Errorf("failed to create http2 client conn: %w", err)
	}

	method := test.HTTP.Method
	if method == "" {
		method = "GET"
	}
	path := test.HTTP.Path
	if path == "" {
		path = "/"
	}

	authority := test.Target.Host
	if uTlsConfig.ServerName != "" {
		authority = uTlsConfig.ServerName
	}

	req, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("https://%s%s", authority, path), nil)
	if err != nil {
		return nil, err
	}

	for k, v := range test.HTTP.Headers {
		req.Header.Set(k, v)
	}

	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("http2 roundtrip failed: %w", err)
	}
	defer resp.Body.Close()

	metadata := map[string]string{
		"proto":             resp.Proto,
		"status":            resp.Status,
		"negotiated_proto":  state.NegotiatedProtocol,
		"tls_version":       tlsVersionString(state.Version),
		"cipher_suite":      utls.CipherSuiteName(state.CipherSuite),
		"negotiated_server": uTlsConfig.ServerName,
	}

	return metadata, nil
}
