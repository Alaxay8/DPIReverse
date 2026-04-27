package transport

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/Alaxay8/dpireverse/pkg/model"
)

type TLSRunner struct {
	logger   *slog.Logger
	proxyURL string
}

func (r *TLSRunner) Run(ctx context.Context, test model.TestCase) (map[string]string, error) {
	if test.TLS == nil {
		return nil, fmt.Errorf("tls options are required for test %s", test.ID)
	}

	rawConn, err := ProxyDialer(ctx, "tcp", test.Target.Address(), r.proxyURL)
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		if err := tcpConn.SetNoDelay(true); err != nil && r.logger != nil {
			r.logger.Debug("set tcp no delay failed", "test_id", test.ID, "error", err)
		}
	}

	conn := rawConn
	if frag := test.TLS.Fragmentation; frag != nil && frag.ChunkSize > 0 {
		conn = &fragmentConn{
			Conn:      rawConn,
			chunkSize: frag.ChunkSize,
			delay:     frag.Delay,
		}
	}

	clientHelloID := GetClientHelloID(test.TLS.ClientHelloProfile)
	config := &utls.Config{
		ServerName:         test.TLS.ServerName,
		InsecureSkipVerify: true,
		MinVersion:         test.TLS.MinVersion,
		MaxVersion:         test.TLS.MaxVersion,
	}
	client := utls.UClient(conn, config, clientHelloID)

	if err := client.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	defer client.Close()

	state := client.ConnectionState()
	metadata := map[string]string{
		"version":           tlsVersionString(state.Version),
		"cipher_suite":      utls.CipherSuiteName(state.CipherSuite),
		"negotiated_server": test.TLS.ServerName,
		"client_hello":      test.TLS.ClientHelloProfile,
	}

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	if test.TLS.ClientHelloProfile == "randomized" {
		userAgent = "DPIReverse/1.0 (Research Scanner)"
	}

	triggerReq := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n", test.Target.Host, userAgent)
	if _, err := client.Write([]byte(triggerReq)); err != nil {
		return nil, fmt.Errorf("trigger write failed: %w", err)
	}

	return metadata, nil
}

func GetClientHelloID(name string) utls.ClientHelloID {
	switch name {
	case "chrome":
		return utls.HelloChrome_Auto
	case "randomized":
		return utls.HelloRandomizedALPN
	default:
		return utls.HelloGolang
	}
}

func tlsVersionString(version uint16) string {
	switch version {
	case utls.VersionTLS12:
		return "1.2"
	case utls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

type fragmentConn struct {
	net.Conn
	chunkSize int
	delay     time.Duration
}

func (c *fragmentConn) Write(p []byte) (int, error) {
	if c.chunkSize <= 0 || len(p) <= c.chunkSize {
		return c.Conn.Write(p)
	}

	total := 0
	for offset := 0; offset < len(p); offset += c.chunkSize {
		end := offset + c.chunkSize
		if end > len(p) {
			end = len(p)
		}

		n, err := c.Conn.Write(p[offset:end])
		total += n
		if err != nil {
			return total, err
		}

		if end < len(p) && c.delay > 0 {
			time.Sleep(c.delay)
		}
	}

	return total, nil
}
