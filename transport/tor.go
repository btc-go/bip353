package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"golang.org/x/net/proxy"
)

const (
	TorDaemonProxy  = "127.0.0.1:9050"
	TorBrowserProxy = "127.0.0.1:9150"
)

type TorTransport struct {
	ProxyAddr string
	DoH       *DoHTransport
}

// NewTorTransport routes DoH queries through a Tor SOCKS5 proxy.
// proxyAddr defaults to TorDaemonProxy if empty.
// dohProvider is a provider name ("cloudflare", "google", "quad9") or a full https:// URL.
func NewTorTransport(proxyAddr, dohProvider string) (*TorTransport, error) {
	if proxyAddr == "" {
		proxyAddr = TorDaemonProxy
	}
	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		return nil, fmt.Errorf("tor: invalid proxy address %q: %w", proxyAddr, err)
	}
	var doh *DoHTransport
	var err error
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
	var dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	if cd, ok := torDialer.(proxy.ContextDialer); ok {
		dialContext = cd.DialContext
	} else {
		dialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
			return torDialer.Dial(network, addr)
		}
	}
	doh.Client = &http.Client{
		Timeout: DefaultTimeout,
		Transport: &http.Transport{
			DialContext:           dialContext,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          10,
			IdleConnTimeout:       DefaultTimeout,
			TLSHandshakeTimeout:   DefaultTimeout,
			ExpectContinueTimeout: 1e9,
		},
	}
	return &TorTransport{ProxyAddr: proxyAddr, DoH: doh}, nil
}

func (t *TorTransport) LookupTXT(ctx context.Context, name string) (*QueryResult, error) {
	result, err := t.DoH.LookupTXT(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("tor(%s): %w", t.ProxyAddr, err)
	}
	if result != nil {
		result.Transport = "tor+" + result.Transport
	}
	return result, nil
}

// CheckTorProxy checks whether something is listening at proxyAddr.
// It does not verify that Tor is running or that the circuit is live.
func CheckTorProxy(proxyAddr string) error {
	conn, err := net.DialTimeout("tcp", proxyAddr, DefaultTimeout)
	if err != nil {
		return fmt.Errorf("tor proxy at %s not reachable: %w", proxyAddr, err)
	}
	if err := conn.Close(); err != nil {
		_ = err 
	}
	return nil
}