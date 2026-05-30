package proxy

import (
	"strings"
	"testing"
)

func TestParseURI(t *testing.T) {
	t.Run("VLESS Reality Link", func(t *testing.T) {
		link := "vless://07d978e1-62f3-4ffa-9e28-60ac51d1bbb8@3.72.7.78:443?flow=&type=xhttp&host=&path=/xhttp-path&mode=auto&security=reality&fp=chrome&sni=images.apple.com&pbk=gJHWg7lnRExvVzbvZhoAA38du07j99lrVnYncuMTLDk&sid=22f15c12267a9b1d#%F0%9F%87%A9%F0%9F%87%AA(AWS)%20Frankfurt,%20Germany"
		cfg, err := ParseURI(link)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.Protocol != ProtocolVLESS {
			t.Errorf("expected protocol vless, got %s", cfg.Protocol)
		}
		if cfg.Password != "07d978e1-62f3-4ffa-9e28-60ac51d1bbb8" {
			t.Errorf("expected user UUID, got %s", cfg.Password)
		}
		if cfg.Host != "3.72.7.78" {
			t.Errorf("expected host, got %s", cfg.Host)
		}
		if cfg.Port != 443 {
			t.Errorf("expected port 443, got %d", cfg.Port)
		}
		if cfg.Security != "reality" {
			t.Errorf("expected security reality, got %s", cfg.Security)
		}
		if cfg.SNI != "images.apple.com" {
			t.Errorf("expected sni images.apple.com, got %s", cfg.SNI)
		}
		if cfg.Fingerprint != "chrome" {
			t.Errorf("expected fp chrome, got %s", cfg.Fingerprint)
		}
		if cfg.PublicKey != "gJHWg7lnRExvVzbvZhoAA38du07j99lrVnYncuMTLDk" {
			t.Errorf("expected pbk, got %s", cfg.PublicKey)
		}
		if cfg.ShortID != "22f15c12267a9b1d" {
			t.Errorf("expected sid, got %s", cfg.ShortID)
		}
		if cfg.Path != "/xhttp-path" {
			t.Errorf("expected path, got %s", cfg.Path)
		}
		if cfg.Transport != "xhttp" {
			t.Errorf("expected transport xhttp, got %s", cfg.Transport)
		}
		// Expect decoded fragment: 🇩🇪(AWS) Frankfurt, Germany
		if !strings.Contains(cfg.Alias, "(AWS)") {
			t.Errorf("expected alias containing (AWS), got %s", cfg.Alias)
		}
	})

	t.Run("Trojan TLS Link", func(t *testing.T) {
		link := "trojan://mypassword@myproxy.com:443?security=tls&sni=mydecoy.com#Test"
		cfg, err := ParseURI(link)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.Protocol != ProtocolTrojan {
			t.Errorf("expected trojan, got %s", cfg.Protocol)
		}
		if cfg.Password != "mypassword" {
			t.Errorf("expected password, got %s", cfg.Password)
		}
		if cfg.Host != "myproxy.com" {
			t.Errorf("expected host, got %s", cfg.Host)
		}
		if cfg.Port != 443 {
			t.Errorf("expected port 443, got %d", cfg.Port)
		}
		if cfg.Security != "tls" {
			t.Errorf("expected security tls, got %s", cfg.Security)
		}
		if cfg.SNI != "mydecoy.com" {
			t.Errorf("expected sni mydecoy.com, got %s", cfg.SNI)
		}
		if cfg.Alias != "Test" {
			t.Errorf("expected alias Test, got %s", cfg.Alias)
		}
	})

	t.Run("SOCKS5 Base64 Link", func(t *testing.T) {
		link := "socks://VVgxQWRzTno6MWR3ZW5OYUo=@45.86.79.27:64901#🇨🇾Nicosia, Cyprus"
		cfg, err := ParseURI(link)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.Protocol != ProtocolSOCKS {
			t.Errorf("expected socks protocol, got %s", cfg.Protocol)
		}
		// Expect decoded base64: UX1AdsNz:1dwenNaJ
		if cfg.Password != "UX1AdsNz:1dwenNaJ" {
			t.Errorf("expected decoded user info, got %s", cfg.Password)
		}
		if cfg.Host != "45.86.79.27" {
			t.Errorf("expected host 45.86.79.27, got %s", cfg.Host)
		}
		if cfg.Port != 64901 {
			t.Errorf("expected port 64901, got %d", cfg.Port)
		}
		if !strings.Contains(cfg.Alias, "Nicosia") {
			t.Errorf("expected alias containing Nicosia, got %s", cfg.Alias)
		}
	})
}
