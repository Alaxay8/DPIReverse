package transport

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"golang.org/x/net/proxy"
)

func ProxyDialer(ctx context.Context, network, addr, proxyURL string) (net.Conn, error) {
	if proxyURL == "" {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse proxy url: %w", err)
	}

	switch u.Scheme {
	case "socks5", "socks5h":
		dialer, err := proxy.FromURL(u, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("create socks5 dialer: %w", err)
		}
		
		contextDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return dialer.Dial(network, addr)
		}
		return contextDialer.DialContext(ctx, network, addr)
	case "http", "https":
		// HTTP proxy support usually requires a more complex handshake for CONNECT.
		// For simplicity in this tool, we'll focus on SOCKS5 first, but we can add HTTP CONNECT later if needed.
		return nil, fmt.Errorf("http proxy not implemented in this version")
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
}
