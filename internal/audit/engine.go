package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Alaxay8/dpireverse/internal/proxy"
	utls "github.com/refraction-networking/utls"
)

type CheckStatus string

const (
	StatusSuccess CheckStatus = "SUCCESS"
	StatusWarning CheckStatus = "WARNING"
	StatusDanger  CheckStatus = "DANGER"
	StatusInfo    CheckStatus = "INFO"
)

type AuditCheck struct {
	Name    string      `json:"name"`
	Status  CheckStatus `json:"status"`
	Summary string      `json:"summary"`
	Details string      `json:"details,omitempty"`
}

type Report struct {
	Config        *proxy.Config `json:"config"`
	TCPConnected  bool          `json:"tcp_connected"`
	ProxyRTT      time.Duration `json:"proxy_rtt"`
	DecoyMatch    bool          `json:"decoy_match"`
	TimingDiff    time.Duration `json:"timing_diff"`
	GoTLSRejected bool          `json:"go_tls_rejected"`
	uTLSSucceeded bool          `json:"utls_succeeded"`
	ActiveProbed  bool          `json:"active_probed"`
	GoTLSAligned  bool          `json:"go_tls_aligned"`
	ActiveAligned bool          `json:"active_aligned"`
	Score         int           `json:"score"`
	Checks        []AuditCheck  `json:"checks"`
}

type Engine struct {
	timeout time.Duration
}

func NewEngine(timeout time.Duration) *Engine {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Engine{timeout: timeout}
}

func (e *Engine) Audit(ctx context.Context, cfg *proxy.Config) (*Report, error) {
	report := &Report{
		Config: cfg,
		Score:  100,
	}

	targetAddr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))

	// 1. TCP Connection Check
	start := time.Now()
	dialer := net.Dialer{Timeout: e.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		report.TCPConnected = false
		report.Score = 0
		report.Checks = append(report.Checks, AuditCheck{
			Name:    "Connectivity",
			Status:  StatusDanger,
			Summary: "TCP connection failed",
			Details: err.Error(),
		})
		return report, nil
	}
	report.TCPConnected = true
	report.ProxyRTT = time.Since(start)
	conn.Close()

	report.Checks = append(report.Checks, AuditCheck{
		Name:    "Connectivity",
		Status:  StatusSuccess,
		Summary: fmt.Sprintf("TCP connected (RTT: %v)", report.ProxyRTT.Round(100*time.Microsecond)),
	})

	// If it is SOCKS, we run SOCKS audit and return
	if cfg.Protocol == proxy.ProtocolSOCKS {
		e.auditSOCKS5(ctx, cfg, report)
		report.Score = 25 // SOCKS5 is plaintext, low DPI resistance score
		return report, nil
	}

	// If no SNI or security, we only do TCP
	if cfg.Security == "" || cfg.Security == "none" {
		report.Checks = append(report.Checks, AuditCheck{
			Name:    "DPI Security Profile",
			Status:  StatusWarning,
			Summary: "Unencrypted proxy or no security configuration",
			Details: "Traffic is fully transparent and vulnerable to easy DPI signature detection.",
		})
		report.Score = 20
		return report, nil
	}

	// 2. Reality Decoy Handshake Verification
	if cfg.Security == "reality" && cfg.SNI != "" {
		e.auditRealityDecoy(ctx, cfg, report)
	}

	// 3. TLS Fingerprint Alignment
	e.auditTLSFingerprint(ctx, cfg, report)

	// 4. Active Probing & Fallback
	e.auditActiveProbing(ctx, cfg, report)

	// Calculate overall score reductions
	if cfg.Security == "reality" {
		if !report.DecoyMatch {
			report.Score -= 40
		}
		if !report.GoTLSAligned {
			report.Score -= 15
		}
		if report.TimingDiff > 50*time.Millisecond {
			// High timing discrepancy in REALITY
			report.Score -= 15
		}
		if !report.ActiveAligned {
			report.Score -= 30
		}
	} else {
		// Standard TLS (Non-Reality)
		if !report.GoTLSRejected {
			// Proxy accepts Go TLS (fingerprint exposure risk)
			report.Score -= 20
		}
		if !report.ActiveProbed {
			// Proxy drops connection abruptly without fallback
			report.Score -= 30
		}
	}

	if report.Score < 0 {
		report.Score = 0
	}

	return report, nil
}

func (e *Engine) auditRealityDecoy(ctx context.Context, cfg *proxy.Config, report *Report) {
	// Measure direct decoy connection
	directStart := time.Now()
	directDialer := net.Dialer{Timeout: e.timeout}
	directConn, err := directDialer.DialContext(ctx, "tcp", net.JoinHostPort(cfg.SNI, "443"))
	var directCert *x509.Certificate
	if err == nil {
		tlsDirectConn := tls.Client(directConn, &tls.Config{
			ServerName:         cfg.SNI,
			InsecureSkipVerify: true,
		})
		directHandshakeStart := time.Now()
		err = tlsDirectConn.HandshakeContext(ctx)
		if err == nil {
			state := tlsDirectConn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				directCert = state.PeerCertificates[0]
			}
		}
		tlsDirectConn.Close()
		directConn.Close()
		_ = directHandshakeStart
	}

	// Measure decoy handshake through proxy IP
	proxyDecoyStart := time.Now()
	proxyAddr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	proxyConn, err := directDialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		report.Checks = append(report.Checks, AuditCheck{
			Name:    "REALITY Decoy",
			Status:  StatusDanger,
			Summary: "Failed to connect to proxy decoy port",
			Details: err.Error(),
		})
		return
	}
	defer proxyConn.Close()

	tlsProxyConn := tls.Client(proxyConn, &tls.Config{
		ServerName:         cfg.SNI,
		InsecureSkipVerify: true,
	})
	proxyHandshakeStart := time.Now()
	err = tlsProxyConn.HandshakeContext(ctx)
	proxyHandshakeDuration := time.Since(proxyHandshakeStart)
	
	if err != nil {
		report.Checks = append(report.Checks, AuditCheck{
			Name:    "REALITY Decoy",
			Status:  StatusDanger,
			Summary: "Decoy handshake failed through proxy server",
			Details: err.Error(),
		})
		return
	}
	defer tlsProxyConn.Close()

	proxyState := tlsProxyConn.ConnectionState()
	var proxyCert *x509.Certificate
	if len(proxyState.PeerCertificates) > 0 {
		proxyCert = proxyState.PeerCertificates[0]
	}

	// Compare certs
	if directCert != nil && proxyCert != nil {
		if directCert.Subject.String() == proxyCert.Subject.String() &&
			directCert.Issuer.String() == proxyCert.Issuer.String() {
			report.DecoyMatch = true
			report.Checks = append(report.Checks, AuditCheck{
				Name:    "REALITY Decoy Certificate",
				Status:  StatusSuccess,
				Summary: fmt.Sprintf("Certificate match SUCCESS (decoy: %s)", cfg.SNI),
				Details: fmt.Sprintf("Subject: %s\nIssuer: %s", proxyCert.Subject, proxyCert.Issuer),
			})
		} else {
			report.DecoyMatch = false
			report.Checks = append(report.Checks, AuditCheck{
				Name:    "REALITY Decoy Certificate",
				Status:  StatusDanger,
				Summary: "Decoy certificate mismatch!",
				Details: fmt.Sprintf("Proxy returned cert for %q, but direct DNS returned %q. Proxy server might be misconfigured.",
					proxyCert.Subject.CommonName, directCert.Subject.CommonName),
			})
		}
	} else if proxyCert != nil {
		// We couldn't compare directly, but got a cert
		report.DecoyMatch = true
		report.Checks = append(report.Checks, AuditCheck{
			Name:    "REALITY Decoy Certificate",
			Status:  StatusWarning,
			Summary: fmt.Sprintf("Proxy decoy connection succeeded, but direct comparison failed"),
			Details: fmt.Sprintf("Returned Subject: %s", proxyCert.Subject),
		})
	}

	// Measure timing discrepancy
	if err == nil && directCert != nil {
		directDuration := time.Since(directStart)
		proxyDuration := time.Since(proxyDecoyStart)
		report.TimingDiff = proxyDuration - directDuration
		if report.TimingDiff < 0 {
			report.TimingDiff = 0
		}
		
		status := StatusSuccess
		summary := fmt.Sprintf("Decoy timing check (Latency diff: %v)", report.TimingDiff.Round(100*time.Microsecond))
		if report.TimingDiff > 80*time.Millisecond {
			status = StatusDanger
			summary += " — CRITICAL DELAY"
		} else if report.TimingDiff > 40*time.Millisecond {
			status = StatusWarning
			summary += " — SLIGHT DELAY"
		}

		report.Checks = append(report.Checks, AuditCheck{
			Name:    "Timing Side-channel",
			Status:  status,
			Summary: summary,
			Details: fmt.Sprintf("Proxy Decoy Handshake: %v\nDirect Decoy Handshake: %v\nTiming difference: %v",
				proxyHandshakeDuration.Round(100*time.Microsecond), directDuration.Round(100*time.Microsecond), report.TimingDiff.Round(100*time.Microsecond)),
		})
	}
}

type probeHTTPResult struct {
	Class   string // "CLOSED", "TIMEOUT", "HTTP_200", "HTTP_400", "HTTP_3XX", "ERROR"
	Details string
}

func probeMalformedHTTP(ctx context.Context, addr string, sni string, timeout time.Duration) probeHTTPResult {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return probeHTTPResult{Class: "ERROR", Details: err.Error()}
	}
	defer conn.Close()

	malformedReq := []byte("GET /index.html HTTP/1.1\r\nHost: " + sni + "\r\n\r\n")
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write(malformedReq)
	if err != nil {
		return probeHTTPResult{Class: "ERROR", Details: err.Error()}
	}

	buf := make([]byte, 1024)
	n, readErr := conn.Read(buf)
	if readErr != nil {
		if readErr == io.EOF {
			return probeHTTPResult{Class: "CLOSED", Details: "Connection closed abruptly (TCP FIN/RST)"}
		}
		if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
			return probeHTTPResult{Class: "TIMEOUT", Details: "Connection timed out"}
		}
		return probeHTTPResult{Class: "ERROR", Details: readErr.Error()}
	}

	resStr := string(buf[:n])
	firstLine := resStr
	if idx := strings.IndexByte(resStr, '\n'); idx != -1 {
		firstLine = resStr[:idx]
	}
	firstLine = strings.TrimSpace(firstLine)

	class := "UNKNOWN_HTTP"
	if bytes.Contains(buf[:n], []byte("400 Bad Request")) {
		class = "HTTP_400"
	} else if bytes.Contains(buf[:n], []byte("301 Moved")) || bytes.Contains(buf[:n], []byte("302 Found")) {
		class = "HTTP_3XX"
	} else if bytes.Contains(buf[:n], []byte("200 OK")) {
		class = "HTTP_200"
	}

	return probeHTTPResult{
		Class:   class,
		Details: firstLine,
	}
}

func (e *Engine) auditTLSFingerprint(ctx context.Context, cfg *proxy.Config, report *Report) {
	proxyAddr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	dialer := net.Dialer{Timeout: e.timeout}

	// Test 1: Standard Go TLS ClientHello on proxy
	proxyAccepted := false
	var proxyHandshakeErr error
	goConn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err == nil {
		tlsGoConn := tls.Client(goConn, &tls.Config{
			ServerName:         cfg.SNI,
			InsecureSkipVerify: true,
		})
		proxyHandshakeErr = tlsGoConn.HandshakeContext(ctx)
		tlsGoConn.Close()
		goConn.Close()
		if proxyHandshakeErr == nil {
			proxyAccepted = true
		}
	}

	// Test decoy directly if Reality
	decoyAccepted := false
	decoyChecked := false
	if cfg.Security == "reality" && cfg.SNI != "" {
		decoyConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(cfg.SNI, "443"))
		if err == nil {
			tlsDecoyConn := tls.Client(decoyConn, &tls.Config{
				ServerName:         cfg.SNI,
				InsecureSkipVerify: true,
			})
			decoyHandshakeErr := tlsDecoyConn.HandshakeContext(ctx)
			tlsDecoyConn.Close()
			decoyConn.Close()
			if decoyHandshakeErr == nil {
				decoyAccepted = true
			}
			decoyChecked = true
		}
	}

	report.GoTLSRejected = !proxyAccepted

	if cfg.Security == "reality" && decoyChecked {
		report.GoTLSAligned = (proxyAccepted == decoyAccepted)
		status := StatusSuccess
		summary := "Standard Go TLS alignment SUCCESS"
		details := ""
		if report.GoTLSAligned {
			if proxyAccepted {
				details = fmt.Sprintf("Both proxy and decoy (%s) ACCEPTED standard Go TLS fingerprint. Masquerading is successful.", cfg.SNI)
			} else {
				details = fmt.Sprintf("Both proxy and decoy (%s) REJECTED standard Go TLS fingerprint. Masquerading is successful.", cfg.SNI)
			}
		} else {
			status = StatusWarning
			summary = "Standard Go TLS alignment MISMATCH"
			if proxyAccepted && !decoyAccepted {
				details = fmt.Sprintf("Behavioral mismatch! Proxy accepted standard Go TLS, but decoy (%s) rejected it.", cfg.SNI)
			} else {
				details = fmt.Sprintf("Behavioral mismatch! Proxy rejected standard Go TLS (err: %v), but decoy (%s) accepted it. Censors can identify the proxy by this mismatch.", proxyHandshakeErr, cfg.SNI)
			}
		}
		report.Checks = append(report.Checks, AuditCheck{
			Name:    "Standard Go TLS Alignment",
			Status:  status,
			Summary: summary,
			Details: details,
		})
	} else {
		// Absolute check for standard TLS/Trojan proxy
		if !proxyAccepted {
			report.Checks = append(report.Checks, AuditCheck{
				Name:    "Standard Go TLS Rejection",
				Status:  StatusSuccess,
				Summary: "Server rejected standard Go TLS fingerprint",
				Details: fmt.Sprintf("Handshake error: %v (This is secure: prevents active probing via standard Go tools)", proxyHandshakeErr),
			})
		} else {
			report.Checks = append(report.Checks, AuditCheck{
				Name:    "Standard Go TLS Rejection",
				Status:  StatusWarning,
				Summary: "Server ACCEPTED standard Go TLS fingerprint",
				Details: "Risk: Censors can probe your server using default Go tools. Ensure your client hello profiles are locked.",
			})
		}
	}

	// Test 2: uTLS Chrome ClientHello
	uConn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err == nil {
		utlsConn := utls.UClient(uConn, &utls.Config{
			ServerName:         cfg.SNI,
			InsecureSkipVerify: true,
		}, utls.HelloChrome_Auto)
		
		utlsHandshakeErr := utlsConn.HandshakeContext(ctx)
		utlsConn.Close()
		uConn.Close()

		if utlsHandshakeErr == nil {
			report.uTLSSucceeded = true
			report.Checks = append(report.Checks, AuditCheck{
				Name:    "uTLS Chrome Mimicry",
				Status:  StatusSuccess,
				Summary: "Server successfully established TLS connection with uTLS Chrome fingerprint",
			})
		} else {
			report.uTLSSucceeded = false
			report.Checks = append(report.Checks, AuditCheck{
				Name:    "uTLS Chrome Mimicry",
				Status:  StatusDanger,
				Summary: "uTLS Chrome handshake failed!",
				Details: utlsHandshakeErr.Error(),
			})
		}
	}
}

func (e *Engine) auditActiveProbing(ctx context.Context, cfg *proxy.Config, report *Report) {
	proxyAddr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	proxyRes := probeMalformedHTTP(ctx, proxyAddr, cfg.SNI, e.timeout)

	report.ActiveProbed = (proxyRes.Class == "HTTP_400" || proxyRes.Class == "HTTP_200" || proxyRes.Class == "HTTP_3XX" || proxyRes.Class == "UNKNOWN_HTTP")

	decoyChecked := false
	var decoyRes probeHTTPResult
	if cfg.Security == "reality" && cfg.SNI != "" {
		decoyRes = probeMalformedHTTP(ctx, net.JoinHostPort(cfg.SNI, "443"), cfg.SNI, e.timeout)
		if decoyRes.Class != "ERROR" {
			decoyChecked = true
		}
	}

	if cfg.Security == "reality" && decoyChecked {
		report.ActiveAligned = (proxyRes.Class == decoyRes.Class)
		status := StatusSuccess
		summary := "Active Probing Fallback Alignment SUCCESS"
		details := ""
		if report.ActiveAligned {
			details = fmt.Sprintf("Both proxy and decoy (%s) returned same response class (%s) on non-TLS request. Masquerading is successful.\nProxy details: %s\nDecoy details: %s",
				cfg.SNI, proxyRes.Class, proxyRes.Details, decoyRes.Details)
		} else {
			status = StatusDanger
			summary = "Active Probing Fallback Alignment MISMATCH"
			details = fmt.Sprintf("Behavioral mismatch! Proxy returned %s (%s), but decoy (%s) returned %s (%s). Censors can identify the proxy by this mismatch.",
				proxyRes.Class, proxyRes.Details, cfg.SNI, decoyRes.Class, decoyRes.Details)
		}
		report.Checks = append(report.Checks, AuditCheck{
			Name:    "Active Probing Fallback Alignment",
			Status:  status,
			Summary: summary,
			Details: details,
		})
	} else {
		// Absolute check for standard TLS/Trojan
		if report.ActiveProbed {
			report.Checks = append(report.Checks, AuditCheck{
				Name:    "Active Probing Fallback",
				Status:  StatusSuccess,
				Summary: fmt.Sprintf("Server returned %s", proxyRes.Class),
				Details: fmt.Sprintf("Response snippet:\n%s", proxyRes.Details),
			})
		} else {
			report.Checks = append(report.Checks, AuditCheck{
				Name:    "Active Probing Fallback",
				Status:  StatusDanger,
				Summary: "Connection closed abruptly (TCP FIN/RST) during malformed request",
				Details: fmt.Sprintf("Details: %s\nProxy has no HTTP fallback active. This is a known fingerprinting vector for standard TLS proxies.", proxyRes.Details),
			})
		}
	}
}

func (e *Engine) auditSOCKS5(ctx context.Context, cfg *proxy.Config, report *Report) {
	report.Checks = append(report.Checks, AuditCheck{
		Name:    "SOCKS5 Encryption",
		Status:  StatusDanger,
		Summary: "Plaintext transport detected (No encryption)",
		Details: "SOCKS5 has no built-in transport layer encryption. All proxied data (domains, paths, payload) is sent in cleartext, making it trivial for DPI/ISPs to analyze and block. Recommended: use Shadowsocks, VLESS, or Trojan.",
	})

	proxyAddr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	dialer := net.Dialer{Timeout: e.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		report.Checks = append(report.Checks, AuditCheck{
			Name:    "SOCKS5 Handshake",
			Status:  StatusDanger,
			Summary: "Failed to connect for SOCKS5 handshake",
			Details: err.Error(),
		})
		return
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(e.timeout))

	// Send SOCKS5 Greeting
	// 0x05 (version 5), 0x02 (2 methods), 0x00 (no auth), 0x02 (user/pass)
	_, err = conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
	if err != nil {
		report.Checks = append(report.Checks, AuditCheck{
			Name:    "SOCKS5 Handshake",
			Status:  StatusDanger,
			Summary: "Failed to write SOCKS5 greeting",
			Details: err.Error(),
		})
		return
	}

	resp := make([]byte, 2)
	_, err = io.ReadFull(conn, resp)
	if err != nil {
		report.Checks = append(report.Checks, AuditCheck{
			Name:    "SOCKS5 Handshake",
			Status:  StatusDanger,
			Summary: "Failed to read SOCKS5 greeting response",
			Details: err.Error(),
		})
		return
	}

	if resp[0] != 0x05 {
		report.Checks = append(report.Checks, AuditCheck{
			Name:    "SOCKS5 Handshake",
			Status:  StatusDanger,
			Summary: "Invalid SOCKS version in server response",
			Details: fmt.Sprintf("Expected 0x05, got 0x%02x", resp[0]),
		})
		return
	}

	method := resp[1]
	if method == 0xff {
		report.Checks = append(report.Checks, AuditCheck{
			Name:    "SOCKS5 Handshake",
			Status:  StatusDanger,
			Summary: "No acceptable authentication methods",
			Details: "Server rejected both 'No Auth' and 'User/Password' methods",
		})
		return
	}

	if method == 0x00 {
		report.Checks = append(report.Checks, AuditCheck{
			Name:    "SOCKS5 Handshake",
			Status:  StatusWarning,
			Summary: "SOCKS5 connected successfully WITHOUT authentication",
			Details: "DANGER: The SOCKS5 proxy accepts anonymous connections. Anyone can use your proxy.",
		})
		return
	}

	if method == 0x02 {
		// User/Pass Auth
		parts := strings.SplitN(cfg.Password, ":", 2)
		user := parts[0]
		pass := ""
		if len(parts) > 1 {
			pass = parts[1]
		}

		if user == "" {
			report.Checks = append(report.Checks, AuditCheck{
				Name:    "SOCKS5 Handshake",
				Status:  StatusDanger,
				Summary: "Server requires authentication, but credentials are missing",
				Details: "Please provide credentials in the URL, e.g. socks://user:pass@host:port",
			})
			return
		}

		// Send subnegotiation
		buf := make([]byte, 0, 3+len(user)+len(pass))
		buf = append(buf, 0x01) // version
		buf = append(buf, byte(len(user)))
		buf = append(buf, []byte(user)...)
		buf = append(buf, byte(len(pass)))
		buf = append(buf, []byte(pass)...)

		_, err = conn.Write(buf)
		if err != nil {
			report.Checks = append(report.Checks, AuditCheck{
				Name:    "SOCKS5 Authentication",
				Status:  StatusDanger,
				Summary: "Failed to write auth credentials",
				Details: err.Error(),
			})
			return
		}

		authResp := make([]byte, 2)
		_, err = io.ReadFull(conn, authResp)
		if err != nil {
			report.Checks = append(report.Checks, AuditCheck{
				Name:    "SOCKS5 Authentication",
				Status:  StatusDanger,
				Summary: "Failed to read auth response",
				Details: err.Error(),
			})
			return
		}

		if authResp[0] != 0x01 {
			report.Checks = append(report.Checks, AuditCheck{
				Name:    "SOCKS5 Authentication",
				Status:  StatusDanger,
				Summary: "Invalid auth version response",
				Details: fmt.Sprintf("Expected 0x01, got 0x%02x", authResp[0]),
			})
			return
		}

		if authResp[1] != 0x00 {
			report.Checks = append(report.Checks, AuditCheck{
				Name:    "SOCKS5 Authentication",
				Status:  StatusDanger,
				Summary: "SOCKS5 authentication failed",
				Details: "Invalid username or password.",
			})
			return
		}

		report.Checks = append(report.Checks, AuditCheck{
			Name:    "SOCKS5 Authentication",
			Status:  StatusSuccess,
			Summary: "SOCKS5 connected successfully with user/password authentication",
		})
	}
}

