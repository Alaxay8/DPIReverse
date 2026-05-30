package audit

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Alaxay8/dpireverse/internal/proxy"
)

func TestAuditEngineConnectivity(t *testing.T) {
	// Start a local TCP listener to mock the proxy server
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	// Parse host and port
	host, portStr, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("failed to split host port: %v", err)
	}
	port := 8388
	if p, err := net.LookupPort("tcp", portStr); err == nil {
		port = p
	}

	// Channel to signal acceptance
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Just read and discard, or respond if malformed request
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err == nil && n > 0 {
					// If it looks like HTTP malformed, respond with 400
					if string(buf[:3]) == "GET" {
						c.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
					}
				}
			}(conn)
		}
	}()

	engine := NewEngine(1 * time.Second)
	cfg := &proxy.Config{
		Protocol: proxy.ProtocolShadowsocks,
		Host:     host,
		Port:     port,
		Security: "", // No security to run basic connectivity check only
	}

	report, err := engine.Audit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected audit error: %v", err)
	}

	if !report.TCPConnected {
		t.Errorf("expected TCPConnected to be true")
	}

	if len(report.Checks) == 0 {
		t.Errorf("expected report checks to be populated")
	}

	// Verify connectivity check name
	foundConnCheck := false
	for _, check := range report.Checks {
		if check.Name == "Connectivity" && check.Status == StatusSuccess {
			foundConnCheck = true
			break
		}
	}
	if !foundConnCheck {
		t.Errorf("expected successful Connectivity check in report")
	}
}

func TestAuditEngineActiveProbing(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	host, portStr, _ := net.SplitHostPort(l.Addr().String())
	var port int
	if p, err := net.LookupPort("tcp", portStr); err == nil {
		port = p
	}

	// Goroutine that accepts and responds to simulated active probe
	go func() {
		conn, err := l.Accept()
		if err == nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			if n > 0 {
				conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			}
		}
	}()

	engine := NewEngine(500 * time.Millisecond)
	cfg := &proxy.Config{
		Protocol:    proxy.ProtocolVLESS,
		Host:        host,
		Port:        port,
		Security:    "tls",
		SNI:         "decoy.com",
		Fingerprint: "chrome",
	}

	report := &Report{
		Config: cfg,
	}

	// Test the auditActiveProbing method directly
	engine.auditActiveProbing(context.Background(), cfg, report)

	if !report.ActiveProbed {
		t.Errorf("expected ActiveProbed to be true after mock HTTP 400 response")
	}

	foundActiveProbeCheck := false
	for _, check := range report.Checks {
		if check.Name == "Active Probing Fallback" && check.Status == StatusSuccess {
			foundActiveProbeCheck = true
			break
		}
	}
	if !foundActiveProbeCheck {
		t.Errorf("expected successful Active Probing Fallback check in report")
	}
}
