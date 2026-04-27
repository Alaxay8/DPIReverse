package transport
 
import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
 
	utls "github.com/refraction-networking/utls"
 
	"github.com/Alaxay8/dpireverse/pkg/model"
)
 
type WebSocketRunner struct {
	proxyURL string
}
 
func (r *WebSocketRunner) Run(ctx context.Context, test model.TestCase) (map[string]string, error) {
	if test.WebSocket == nil {
		return nil, fmt.Errorf("websocket options are required for test %s", test.ID)
	}
 
	path := test.WebSocket.Path
	if path == "" {
		path = "/"
	}
 
	var (
		conn net.Conn
		err  error
	)
 
	if test.WebSocket.Secure {
		rawConn, err := ProxyDialer(ctx, "tcp", test.Target.Address(), r.proxyURL)
		if err != nil {
			return nil, err
		}
 
		clientHelloID := utls.HelloChrome_Auto
		if test.TLS != nil {
			clientHelloID = GetClientHelloID(test.TLS.ClientHelloProfile)
		}
 
		uConn := utls.UClient(rawConn, &utls.Config{
			ServerName:         test.Target.Host,
			InsecureSkipVerify: true,
		}, clientHelloID)
 
		if err := uConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("websocket tls handshake failed: %w", err)
		}
		conn = uConn
	} else {
		rawConn, err := ProxyDialer(ctx, "tcp", test.Target.Address(), r.proxyURL)
		if err != nil {
			return nil, err
		}
		conn = rawConn
	}
	defer conn.Close()
 
	key, err := websocketKey()
	if err != nil {
		return nil, err
	}
 
	headers := []string{
		fmt.Sprintf("GET %s HTTP/1.1", path),
		fmt.Sprintf("Host: %s", test.Target.Host),
		"Upgrade: websocket",
		"Connection: Upgrade",
		fmt.Sprintf("Sec-WebSocket-Key: %s", key),
		"Sec-WebSocket-Version: 13",
	}
	for key, value := range test.WebSocket.Headers {
		headers = append(headers, fmt.Sprintf("%s: %s", key, value))
	}
	headers = append(headers, "", "")
 
	if _, err := io.WriteString(conn, strings.Join(headers, "\r\n")); err != nil {
		return nil, fmt.Errorf("write websocket handshake: %w", err)
	}
 
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(line, "101") {
		return nil, fmt.Errorf("unexpected websocket response: %s", strings.TrimSpace(line))
	}
 
	return map[string]string{"status": strings.TrimSpace(line)}, nil
}
 
func websocketKey() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate websocket key: %w", err)
	}
 
	return base64.StdEncoding.EncodeToString(buf), nil
}
