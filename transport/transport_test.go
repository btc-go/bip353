package transport_test

import (
	"testing"

	"github.com/btc-go/bip353/transport"
)

func TestDefaultNameservers(t *testing.T) {
	if len(transport.DefaultNameservers) == 0 {
		t.Fatal("DefaultNameservers must not be empty")
	}
	for _, s := range transport.DefaultNameservers {
		if len(s) < 3 || s[len(s)-3:] != ":53" {
			t.Errorf("nameserver %q must end in ':53'", s)
		}
	}
}

func TestFullValidationTransportDefaults(t *testing.T) {
	tr := transport.NewFullValidationTransport()
	if len(tr.Nameservers) == 0 {
		t.Error("nameservers must not be empty")
	}
	if tr.Timeout == 0 {
		t.Error("timeout must not be zero")
	}
}

func TestFullValidationTransportCustomNameservers(t *testing.T) {
	ns := []string{"192.0.2.1:53", "192.0.2.2:53"}
	tr := transport.NewFullValidationTransportWithNameservers(ns)
	if len(tr.Nameservers) != 2 {
		t.Errorf("expected 2 nameservers, got %d", len(tr.Nameservers))
	}
}

func TestDoHKnownProviders(t *testing.T) {
	for _, p := range []string{"cloudflare", "google", "quad9", "nextdns"} {
		t.Run(p, func(t *testing.T) {
			tr, err := transport.NewDoHTransport(p)
			if err != nil {
				t.Fatalf("NewDoHTransport(%q): %v", p, err)
			}
			if len(tr.Endpoints) == 0 {
				t.Error("endpoints must not be empty")
			}
		})
	}
}

func TestDoHUnknownProvider(t *testing.T) {
	if _, err := transport.NewDoHTransport("not-a-provider"); err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestDoHCustomURL(t *testing.T) {
	if _, err := transport.NewDoHTransportWithURL("https://example.com/dns-query"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDoHInvalidURL(t *testing.T) {
	if _, err := transport.NewDoHTransportWithURL("://not-a-url"); err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestWellKnownProviderURLs(t *testing.T) {
	for name, u := range transport.WellKnownDoHProviders {
		if u == "" {
			t.Errorf("provider %q has empty URL", name)
		}
		if len(u) < 8 || u[:8] != "https://" {
			t.Errorf("provider %q URL must start with https://", name)
		}
	}
}

func TestTorTransportInvalidProxy(t *testing.T) {
	if _, err := transport.NewTorTransport("not-a-host", "cloudflare"); err == nil {
		t.Error("expected error for invalid proxy address")
	}
}

func TestTorTransportInvalidProvider(t *testing.T) {
	if _, err := transport.NewTorTransport("127.0.0.1:9050", "nonexistent"); err == nil {
		t.Error("expected error for invalid DoH provider")
	}
}

func TestCheckTorProxyUnreachable(t *testing.T) {
	if err := transport.CheckTorProxy("127.0.0.1:19999"); err == nil {
		t.Log("port 19999 was open (unusual)")
	}
}
