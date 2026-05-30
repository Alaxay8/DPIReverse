package proxy

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Protocol string

const (
	ProtocolVLESS       Protocol = "vless"
	ProtocolTrojan      Protocol = "trojan"
	ProtocolShadowsocks Protocol = "shadowsocks"
	ProtocolSOCKS       Protocol = "socks"
)

type Config struct {
	Protocol    Protocol `json:"protocol"`
	Password    string   `json:"password_or_uuid"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Security    string   `json:"security"`
	SNI         string   `json:"sni"`
	Fingerprint string   `json:"fingerprint"`
	PublicKey   string   `json:"public_key,omitempty"`
	ShortID     string   `json:"short_id,omitempty"`
	Path        string   `json:"path,omitempty"`
	Transport   string   `json:"transport"`
	Alias       string   `json:"alias,omitempty"`
}

func ParseURI(uri string) (*Config, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	cfg := &Config{
		Alias: u.Fragment,
	}

	switch u.Scheme {
	case "vless":
		cfg.Protocol = ProtocolVLESS
	case "trojan":
		cfg.Protocol = ProtocolTrojan
	case "ss":
		cfg.Protocol = ProtocolShadowsocks
	case "socks", "socks5", "socks5h":
		cfg.Protocol = ProtocolSOCKS
	default:
		return nil, fmt.Errorf("unsupported protocol scheme: %s", u.Scheme)
	}

	// Parse host & port
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		// Port might be omitted
		host = u.Host
		portStr = ""
	}
	cfg.Host = host
	if portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}
		cfg.Port = port
	} else {
		if cfg.Protocol == ProtocolShadowsocks {
			cfg.Port = 8388
		} else if cfg.Protocol == ProtocolSOCKS {
			cfg.Port = 1080
		} else {
			cfg.Port = 443
		}
	}

	// Extract credentials
	if u.User != nil {
		cfg.Password = u.User.Username()
		if pass, ok := u.User.Password(); ok {
			cfg.Password = cfg.Password + ":" + pass
		}
	}

	// Parse query parameters
	query := u.Query()
	cfg.Security = query.Get("security")
	cfg.SNI = query.Get("sni")
	cfg.Fingerprint = query.Get("fp")
	cfg.PublicKey = query.Get("pbk")
	cfg.ShortID = query.Get("sid")
	cfg.Path = query.Get("path")
	cfg.Transport = query.Get("type")
	if cfg.Transport == "" {
		cfg.Transport = "tcp"
	}

	// Decode password if base64 encoded (typical for SS/SOCKS URLs)
	if (cfg.Protocol == ProtocolShadowsocks || cfg.Protocol == ProtocolSOCKS) && cfg.Password != "" && !strings.Contains(cfg.Password, ":") {
		cfg.Password = decodeBase64(cfg.Password)
	}

	return cfg, nil
}

func decodeBase64(in string) string {
	in = strings.TrimSpace(in)
	
	// Helper to add padding if missing
	addPadding := func(str string) string {
		if l := len(str) % 4; l > 0 {
			str += strings.Repeat("=", 4-l)
		}
		return str
	}

	dec, err := base64.URLEncoding.DecodeString(addPadding(in))
	if err == nil {
		return string(dec)
	}
	dec, err = base64.StdEncoding.DecodeString(addPadding(in))
	if err == nil {
		return string(dec)
	}
	dec, err = base64.RawURLEncoding.DecodeString(in)
	if err == nil {
		return string(dec)
	}
	dec, err = base64.RawStdEncoding.DecodeString(in)
	if err == nil {
		return string(dec)
	}
	return in
}

