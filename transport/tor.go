package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const (
	TorDaemonProxy  = "127.0.0.1:9050"
	TorBrowserProxy = "127.0.0.1:9150"
)

// TorTransport routes DoH queries through a Tor SOCKS5 proxy. The DoH server
// sees only the Tor exit node's IP. The DoH server is used only as a query
// relay — it is not trusted for DNSSEC validation. Chain validation always
// happens locally via dnssec-prover.
type TorTransport struct {
	ProxyAddr string
	doh       *DoHTransport
}

// NewTorTransport routes DoH queries through a Tor SOCKS5 proxy.
// proxyAddr defaults to TorDaemonProxy (127.0.0.1:9050) if empty.
// dohProvider is a named provider ("cloudflare", "google", "quad9", "nextdns")
// or a full https:// URL.
func NewTorTransport(proxyAddr, dohProvider string) (*TorTransport, error) {
	if proxyAddr == "" {
		proxyAddr = TorDaemonProxy
	}
	host, _, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("tor: invalid proxy address %q: %w", proxyAddr, err)
	}
	if !isLoopbackHost(host) && os.Getenv("BIP353_ALLOW_REMOTE_TOR_PROXY") != "1" {
		return nil, fmt.Errorf("tor: refusing non-loopback proxy %q (a remote SOCKS proxy is not Tor anonymity); set BIP353_ALLOW_REMOTE_TOR_PROXY=1 to override", proxyAddr)
	}

	var doh *DoHTransport
	if strings.HasPrefix(dohProvider, "https://") {
		doh, err = NewDoHTransportWithURL(dohProvider)
	} else {
		doh, err = NewDoHTransport(dohProvider)
	}
	if err != nil {
		return nil, fmt.Errorf("tor: %w", err)
	}

	torDialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("tor: SOCKS5 dialer for %s: %w", proxyAddr, err)
	}

	cd, ok := torDialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("tor: SOCKS5 dialer does not support contexts")
	}
	dialContext := cd.DialContext

	doh.Client = &http.Client{
		Timeout:       DefaultTimeout,
		CheckRedirect: noRedirect,
		Transport: &http.Transport{
			DialContext:           dialContext,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          10,
			IdleConnTimeout:       DefaultTimeout,
			TLSHandshakeTimeout:   DefaultTimeout,
			ExpectContinueTimeout: time.Second,
		},
	}

	return &TorTransport{ProxyAddr: proxyAddr, doh: doh}, nil
}

func (t *TorTransport) LookupTXT(ctx context.Context, name string) (*QueryResult, error) {
	result, err := resolveWithProver(ctx, name, "tor+doh", t.doh.sendQuery)
	if err != nil {
		return nil, fmt.Errorf("tor(%s): %w", t.ProxyAddr, err)
	}
	return result, nil
}

// CheckTorProxy checks whether something is listening at proxyAddr.
func CheckTorProxy(proxyAddr string) error {
	conn, err := net.DialTimeout("tcp", proxyAddr, DefaultTimeout)
	if err != nil {
		return fmt.Errorf("tor proxy at %s not reachable: %w", proxyAddr, err)
	}
	_ = conn.Close()
	return nil
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
